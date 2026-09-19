package encryption

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

// Content version 3 ("true V3") is the chunked AEAD content format.
//
// V1/V2 rely on raw stream ciphers with no integrity check, so ciphertext
// tampering is undetectable. V3 instead splits the plaintext into fixed-size
// chunks and authenticates each chunk independently with AES-256-GCM:
//
//   - any bit flip / truncation / reorder in a stored chunk is detected and
//     reported as a decrypt error instead of silently producing garbage;
//   - a single chunk can be decrypted without reading the whole container, so
//     Range 播放/下载 only pulls the needed chunk into memory.
//
// Container layout (fixed-width chunk records make it seek-friendly):
//
//	[ 48-byte header ]
//	  magic   "V3GCM3"   6 bytes
//	  version            1 byte  = 3
//	  reserved           1 byte
//	  nonce field        16 bytes  (KDF salt + AEAD nonce base)
//	  plain size         int64 BE
//	  chunk size         uint32 BE  (semantic plaintext chunk size)
//	  tag size           uint32 BE  (16 for AES-GCM)
//	  kdf iterations     uint32 BE
//	[ repeated chunk records ]
//	  each record: chunkSize bytes (ciphertext) + 16-byte GCM tag
//
// Plaintext chunk i occupies record i at file offset
// V3HeaderSize + i*(chunkSize+16). The final chunk is padded to chunkSize with
// zeros before sealing and trimmed back on decrypt using PlainSize.
const (
	ContentVersionV3   = 3
	V3HeaderSize       = 48
	v3Magic            = "V3GCM3"
	v3MagicLen         = 6
	v3NonceFieldLen    = 16
	v3TagSize          = 16
	v3DefaultChunkSize = 16 * 1024 * 1024 // 16 MiB
	v3MaxChunkSize     = 1 << 30          // 1 GiB sanity cap
	v3AEADNonceSize    = 12               // AES-GCM nonce length
)

var errV3TagMismatch = errors.New("v3: chunk authentication failed (ciphertext tampered)")

var v3MagicBytes = []byte(v3Magic)

// IsV3Prefix reports whether the given byte slice begins with the V3
// container magic. It is safe on short slices.
func IsV3Prefix(prefix []byte) bool {
	return len(prefix) >= v3MagicLen && bytes.Equal(prefix[:v3MagicLen], v3MagicBytes)
}

// V3ChunkCipher seals/unseals single chunks with AES-256-GCM. It is created
// from the 32-byte per-file key material and the container's 16-byte nonce.
type V3ChunkCipher struct {
	aead  cipher.AEAD
	nonce []byte // 16-byte container nonce (KDF salt + nonce base)
}

// NewV3ChunkCipher builds an AES-256-GCM chunk cipher from 32 bytes of key
// material and the 16-byte container nonce field.
func NewV3ChunkCipher(key, nonce []byte) (*V3ChunkCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("v3: key material must be 32 bytes, got %d", len(key))
	}
	if len(nonce) != v3NonceFieldLen {
		return nil, fmt.Errorf("v3: nonce must be %d bytes, got %d", v3NonceFieldLen, len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &V3ChunkCipher{aead: aead, nonce: append([]byte(nil), nonce...)}, nil
}

// chunkNonce derives the 12-byte AEAD nonce for a chunk index: the first 8
// bytes come from the container nonce and the last 4 bytes are the big-endian
// chunk index. Each chunk always maps to the same, unique nonce, so seekable
// per-chunk decryption needs no extra key state.
func (c *V3ChunkCipher) chunkNonce(index uint64) []byte {
	n := make([]byte, v3AEADNonceSize)
	copy(n[:v3AEADNonceSize-4], c.nonce[:v3AEADNonceSize-4])
	binary.BigEndian.PutUint32(n[v3AEADNonceSize-4:], uint32(index))
	return n
}

// Seal encrypts a single plaintext chunk (any length up to v3MaxChunkSize) and
// returns the ciphertext plus the 16-byte GCM tag.
func (c *V3ChunkCipher) Seal(index uint64, plaintext []byte) ([]byte, error) {
	if len(plaintext) > v3MaxChunkSize {
		return nil, fmt.Errorf("v3: chunk too large: %d bytes", len(plaintext))
	}
	return c.aead.Seal(nil, c.chunkNonce(index), plaintext, nil), nil
}

// Open authenticates and decrypts a chunk ciphertext (the input must be
// plaintextLen + 16 bytes). A non-nil error means the chunk failed
// authentication or was the wrong size.
func (c *V3ChunkCipher) Open(index uint64, data []byte) ([]byte, error) {
	if uint64(len(data)) < v3TagSize || uint64(len(data)) > v3MaxChunkSize+v3TagSize {
		return nil, fmt.Errorf("v3: invalid chunk ciphertext length %d", len(data))
	}
	pt, err := c.aead.Open(nil, c.chunkNonce(index), data, nil)
	if err != nil {
		return nil, fmt.Errorf("%w at chunk %d", errV3TagMismatch, index)
	}
	return pt, nil
}

// ---------------------------------------------------------------------------
// Container geometry helpers — the fixed-width chunk records make the
// container fully seekable.

// V3ChunkCount returns the number of plaintext chunks for a plaintext size.
func V3ChunkCount(plainSize, chunkSize int64) uint64 {
	if plainSize <= 0 {
		return 0
	}
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	return uint64((plainSize + chunkSize - 1) / chunkSize)
}

// V3CiphertextSize returns the on-disk size of a V3 container.
func V3CiphertextSize(plainSize, chunkSize int64) int64 {
	if plainSize <= 0 {
		return V3HeaderSize
	}
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	return V3HeaderSize + int64(V3ChunkCount(plainSize, chunkSize))*(chunkSize+v3TagSize)
}

// V3ChunkForOffset maps a plaintext offset to (chunk index, offset within the
// chunk).
func V3ChunkForOffset(plainOffset, chunkSize int64) (uint64, int64) {
	if plainOffset <= 0 {
		return 0, 0
	}
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	return uint64(plainOffset / chunkSize), plainOffset % chunkSize
}

// V3ChunkCipherOffset returns the container file offset of the first byte of
// chunk id's record.
func V3ChunkCipherOffset(index uint64, chunkSize int64) int64 {
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	return V3HeaderSize + int64(index)*(chunkSize+v3TagSize)
}

// V3ChunkCipherLen returns the fixed record length of one chunk.
func V3ChunkCipherLen(chunkSize int64) int64 {
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	return chunkSize + v3TagSize
}

// V3RemainingInChunk returns how many plaintext bytes are still readable from
// plainOff to the end of its chunk (bounded by the container's plainSize).
func V3RemainingInChunk(plainSize, plainOff, chunkSize int64) int64 {
	_, off := V3ChunkForOffset(plainOff, chunkSize)
	n := chunkSize - off
	if rest := plainSize - plainOff; n > rest {
		n = rest
	}
	if n < 0 {
		return 0
	}
	return n
}

// ---------------------------------------------------------------------------
// Header encode / parse.

// NewV3Header builds the fixed V3HeaderSize container header.
func NewV3Header(plainSize int64, nonceField []byte, chunkSize int64, kdfIterations uint32) ([]byte, error) {
	if plainSize < 0 {
		return nil, fmt.Errorf("v3: plain size must not be negative")
	}
	if len(nonceField) != v3NonceFieldLen {
		return nil, fmt.Errorf("v3: nonce field must be %d bytes, got %d", v3NonceFieldLen, len(nonceField))
	}
	if chunkSize <= 0 || chunkSize > v3MaxChunkSize {
		return nil, fmt.Errorf("v3: invalid chunk size %d", chunkSize)
	}
	h := make([]byte, V3HeaderSize)
	copy(h[0:v3MagicLen], v3MagicBytes)
	h[6] = byte(ContentVersionV3)
	h[7] = 0 // reserved
	copy(h[8:8+v3NonceFieldLen], nonceField)
	binary.BigEndian.PutUint64(h[24:32], uint64(plainSize))
	binary.BigEndian.PutUint32(h[32:36], uint32(chunkSize))
	binary.BigEndian.PutUint32(h[36:40], v3TagSize)
	binary.BigEndian.PutUint32(h[40:44], kdfIterations)
	return h, nil
}

// ParseV3Header attempts to parse a V3 header from a container prefix. It
// returns (meta, true, nil) for a valid V3 header, (meta, false, nil) when the
// prefix is not the V3 magic (caller should fall back to V2), or
// (meta, true, err) for a malformed V3 header.
func ParseV3Header(prefix []byte, ciphertextSize int64) (ContentMeta, bool, error) {
	meta := ContentMeta{Version: ContentVersionV3, HeaderLen: V3HeaderSize}
	if len(prefix) < v3MagicLen {
		return meta, false, nil
	}
	if !bytes.Equal(prefix[:v3MagicLen], v3MagicBytes) {
		return meta, false, nil
	}
	if len(prefix) < V3HeaderSize {
		return meta, true, fmt.Errorf("v3: incomplete content header")
	}
	if prefix[6] != byte(ContentVersionV3) {
		return meta, true, fmt.Errorf("v3: unsupported content version: %d", prefix[6])
	}
	meta.PlainSize = int64(binary.BigEndian.Uint64(prefix[24:32]))
	meta.NonceField = append([]byte(nil), prefix[8:24]...)
	meta.ChunkSize = binary.BigEndian.Uint32(prefix[32:36])
	if meta.ChunkSize == 0 || meta.ChunkSize > v3MaxChunkSize {
		meta.ChunkSize = uint32(v3DefaultChunkSize)
	}
	meta.KDFIterations = binary.BigEndian.Uint32(prefix[40:44])
	if ciphertextSize >= V3HeaderSize {
		meta.CiphertextSize = ciphertextSize
	} else {
		meta.CiphertextSize = V3CiphertextSize(meta.PlainSize, int64(meta.ChunkSize))
	}
	return meta, true, nil
}

// ParseFrontMatter inspects a content prefix and returns the strongest
// metadata it can: a V3 container prefix is recognized by its magic, otherwise
// the V2 header parser (which also covers legacy V1) is used.
func ParseFrontMatter(encType EncType, prefix []byte, ciphertextSize int64) (ContentMeta, bool, error) {
	if len(prefix) >= v3MagicLen && bytes.Equal(prefix[:v3MagicLen], v3MagicBytes) {
		return ParseV3Header(prefix, ciphertextSize)
	}
	return ParseContentHeader(encType, prefix, ciphertextSize)
}

// V3DefaultChunkSize returns the standard chunk size used when a container's
// header omits one (16 MiB).
func V3DefaultChunkSize() int64 { return v3DefaultChunkSize }

// V3ChunkRecordSize returns the on-disk size of one chunk record.
func V3ChunkRecordSize(chunkSize int64) int64 {
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	return chunkSize + v3TagSize
}

// V3ChunkWindow maps a plaintext byte interval [plainStart, plainEnd]
// (inclusive, both outside the V3 header) to the contiguous ciphertext range
// that covers every chunk record it touches. Because records are fixed width
// the window is contiguous even when the client range crosses chunk bounds.
func V3ChunkWindow(plainStart, plainEnd, chunkSize int64) (cipherStart, cipherEnd int64) {
	if chunkSize <= 0 {
		chunkSize = v3DefaultChunkSize
	}
	a := plainStart / chunkSize
	b := plainEnd / chunkSize
	cipherStart = V3HeaderSize + a*V3ChunkRecordSize(chunkSize)
	cipherEnd = V3HeaderSize + (b+1)*V3ChunkRecordSize(chunkSize) - 1
	return cipherStart, cipherEnd
}

// V3NonceFieldLen returns the fixed length of a V3 container nonce (16 bytes).
func V3NonceFieldLen() int64 { return v3NonceFieldLen }
