package encrypt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

const (
	ContentVersionV3         = core.ContentVersionV3
	V3HeaderSize             = core.V3HeaderSize
	V3TrailerSize            = 16
	MaxMobileV3ChunkSize     = 32 * 1024 * 1024
	MaxMobileV3KDFIterations = 2_000_000
)

// ErrV3ResourceLimit is a local policy rejection, not a provider capability error.
var ErrV3ResourceLimit = errors.New("v3 metadata exceeds mobile resource limits")

func (m ContentMeta) IsV3() bool { return m.Version == ContentVersionV3 }

// Explicit mapping applies only to V3. Mobile V2 must keep its own AES magic
// parser: mobile aes-ctr and core aesctr are not interchangeable wire lookups.
func v3CoreEncType(encType EncryptionType) core.EncType {
	if normalizeContentEncType(encType) == EncTypeAESCTR {
		return core.EncType("aesctr")
	}
	return core.EncType(normalizeContentEncType(encType))
}

func ContentMetaFromV3Core(m core.ContentMeta, encType EncryptionType) ContentMeta {
	return ContentMeta{EncType: normalizeContentEncType(encType), Version: m.Version, HeaderLen: m.HeaderLen,
		PlainSize: m.PlainSize, CiphertextSize: m.CiphertextSize, NonceField: cloneNonceField(m.NonceField), ChunkSize: m.ChunkSize, KDFIterations: m.KDFIterations}
}

func (m ContentMeta) V3CoreMeta() core.ContentMeta {
	return core.ContentMeta{EncType: v3CoreEncType(m.EncType), Version: m.Version, HeaderLen: m.HeaderLen,
		PlainSize: m.PlainSize, CiphertextSize: m.CiphertextSize, NonceField: cloneNonceField(m.NonceField), ChunkSize: m.ChunkSize, KDFIterations: m.KDFIterations}
}

func validateV3Parameters(m ContentMeta) error {
	if !m.IsV3() || m.HeaderLen != V3HeaderSize || len(m.NonceField) != 16 || m.PlainSize < 0 {
		return fmt.Errorf("v3: invalid metadata header, nonce or plaintext size")
	}
	if m.ChunkSize == 0 || m.ChunkSize > 1<<30 {
		return fmt.Errorf("v3: invalid chunk size %d", m.ChunkSize)
	}
	if m.ChunkSize > MaxMobileV3ChunkSize || m.KDFIterations > MaxMobileV3KDFIterations {
		return fmt.Errorf("%w: chunk=%d kdf=%d", ErrV3ResourceLimit, m.ChunkSize, m.KDFIterations)
	}
	return nil
}

// ValidateV3ContentMeta validates fully resolved container geometry, not AEAD
// authentication. A matching header/trailer is still untrusted until records
// are authenticated by the shared chunk reader. Fixed and streaming containers
// differ by exactly one trailer; metadata intentionally needs no layout flag.
func ValidateV3ContentMeta(m ContentMeta) error {
	if err := validateV3Parameters(m); err != nil {
		return err
	}
	if m.CiphertextSize < V3HeaderSize {
		return fmt.Errorf("v3: ciphertext size is unknown or too small")
	}
	records := m.PlainSize / int64(m.ChunkSize)
	if m.PlainSize%int64(m.ChunkSize) != 0 {
		records++
	}
	// Index is uint32; a count of 2^32 uses the final legal index 2^32-1.
	if uint64(records) > uint64(1)<<32 {
		return fmt.Errorf("v3: record count exceeds nonce space")
	}
	payload := m.CiphertextSize - V3HeaderSize
	width := int64(m.ChunkSize) + 16
	matches := func(n int64) bool { return n >= 0 && n%width == 0 && n/width == records }
	if !matches(payload) && !matches(payload-V3TrailerSize) {
		return fmt.Errorf("v3: ciphertext record geometry does not match plaintext size")
	}
	return nil
}

// ParseV3ContentHeader recognizes V3 before legacy parsing. PlainSize=0 with a
// container larger than 48 bytes is unresolved: CompleteV3ContentMeta must read
// the trailer before this metadata is cached or used to answer plaintext HEAD.
func ParseV3ContentHeader(encType EncryptionType, prefix []byte, ciphertextSize int64) (ContentMeta, bool, error) {
	parsed, recognized, err := core.ParseV3Header(prefix, ciphertextSize)
	meta := ContentMetaFromV3Core(parsed, encType)
	if !recognized || err != nil {
		return meta, recognized, err
	}
	if prefix[7] != 0 || binary.BigEndian.Uint32(prefix[36:40]) != 16 || binary.BigEndian.Uint32(prefix[44:48]) != 0 {
		return meta, true, fmt.Errorf("v3: unsupported reserved fields or tag size")
	}
	// Core defaults malformed chunk sizes; never accept that repair for input.
	rawChunk := binary.BigEndian.Uint32(prefix[32:36])
	if rawChunk == 0 || rawChunk > 1<<30 {
		return meta, true, fmt.Errorf("v3: invalid raw chunk size %d", rawChunk)
	}
	if err = validateV3Parameters(meta); err != nil {
		return meta, true, err
	}
	if ciphertextSize < V3HeaderSize {
		return meta, true, fmt.Errorf("v3: ciphertext size must be known")
	}
	if meta.PlainSize == 0 && ciphertextSize > V3HeaderSize {
		payload := ciphertextSize - V3HeaderSize - V3TrailerSize
		if payload < 0 || payload%(int64(meta.ChunkSize)+16) != 0 || uint64(payload/(int64(meta.ChunkSize)+16)) > uint64(1)<<32 {
			return meta, true, fmt.Errorf("v3: invalid streaming container geometry")
		}
		return meta, true, nil
	}
	// A nonzero fixed header cannot carry a stream trailer.
	width := int64(meta.ChunkSize) + 16
	payload := ciphertextSize - V3HeaderSize
	count := meta.PlainSize / int64(meta.ChunkSize)
	if meta.PlainSize%int64(meta.ChunkSize) != 0 {
		count++
	}
	if payload%width != 0 || payload/width != count {
		return meta, true, fmt.Errorf("v3: fixed container geometry mismatch")
	}
	return meta, true, ValidateV3ContentMeta(meta)
}

// trailerReaderAt adapts an exact tiny tail response to the shared trailer API.
// The offset check prevents accidentally interpreting a 200 body's prefix as a
// requested tail; HTTP range validation remains the probing caller's duty.
type v3TrailerReaderAt struct {
	tail   []byte
	offset int64
}

func (r v3TrailerReaderAt) ReadAt(dst []byte, offset int64) (int, error) {
	if offset != r.offset {
		return 0, fmt.Errorf("v3: unexpected trailer offset")
	}
	n := copy(dst, r.tail)
	if n != len(dst) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func CompleteV3ContentMeta(meta ContentMeta, trailer []byte) (ContentMeta, error) {
	if err := validateV3Parameters(meta); err != nil {
		return meta, err
	}
	if meta.PlainSize != 0 || meta.CiphertextSize < V3HeaderSize+V3TrailerSize || len(trailer) != V3TrailerSize {
		return meta, fmt.Errorf("v3: incomplete or unexpected stream trailer")
	}
	if binary.BigEndian.Uint32(trailer[4:8]) != 0 {
		return meta, fmt.Errorf("v3: unsupported trailer reserved field")
	}
	plain, err := core.ReadTrailerV3(v3TrailerReaderAt{tail: trailer, offset: meta.CiphertextSize - V3TrailerSize}, meta.CiphertextSize)
	if err != nil {
		return meta, err
	}
	meta.PlainSize = plain
	if err = ValidateV3ContentMeta(meta); err != nil {
		return meta, err
	}
	// Completion specifically requires stream geometry, not the fixed variant.
	payload := meta.CiphertextSize - V3HeaderSize - V3TrailerSize
	width := int64(meta.ChunkSize) + 16
	count := plain / int64(meta.ChunkSize)
	if plain%int64(meta.ChunkSize) != 0 {
		count++
	}
	if payload < 0 || payload%width != 0 || payload/width != count {
		return meta, fmt.Errorf("v3: trailer record geometry mismatch")
	}
	return meta, nil
}
