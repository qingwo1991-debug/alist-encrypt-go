package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	ContentVersionV1 = 1
	ContentVersionV2 = 2

	pbkdf2IterationsLegacy = 1000
	pbkdf2IterationsModern = 600000

	contentHeaderMagicLen = 6
	contentHeaderSize     = 32
	contentHeaderReserved = 0
)

// TODO(V3): Consider using ChaCha20-Poly1305 or AES-GCM (AEAD modes) for
// authenticated encryption. Current V2 uses plain stream ciphers without
// integrity verification, making ciphertext tampering undetectable.

func ContentHeaderSize() int64 {
	return contentHeaderSize
}

var contentHeaderMagic = map[EncType]string{
	EncTypeAESCTR:   "AECTR2",
	EncTypeChaCha20: "CHC202",
	EncTypeRC4MD5:   "RC4MD2",
}

type ContentMeta struct {
	EncType        EncType
	Version        int
	HeaderLen      int64
	PlainSize      int64
	CiphertextSize int64
	NonceField     []byte
}

func LegacyContentMeta(encType EncType, ciphertextSize int64) ContentMeta {
	return ContentMeta{
		EncType:        encType,
		Version:        ContentVersionV1,
		HeaderLen:      0,
		PlainSize:      ciphertextSize,
		CiphertextSize: ciphertextSize,
	}
}

func (m ContentMeta) IsV2() bool {
	return m.Version == ContentVersionV2
}

func (m ContentMeta) UpstreamOffset(plainOffset int64) int64 {
	if !m.IsV2() {
		return plainOffset
	}
	return m.HeaderLen + plainOffset
}

func (m ContentMeta) TotalCiphertextSize() int64 {
	if m.CiphertextSize > 0 {
		return m.CiphertextSize
	}
	if m.IsV2() && m.PlainSize > 0 {
		return m.PlainSize + m.HeaderLen
	}
	return m.PlainSize
}

func generateRandomNonceField() ([]byte, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func BuildV2Header(encType EncType, plainSize int64, nonceField []byte) ([]byte, error) {
	magic, ok := contentHeaderMagic[encType]
	if !ok {
		return nil, fmt.Errorf("unsupported v2 content header encType: %s", encType)
	}
	if plainSize < 0 {
		return nil, fmt.Errorf("plain size cannot be negative")
	}
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	header := make([]byte, contentHeaderSize)
	copy(header[:contentHeaderMagicLen], []byte(magic))
	header[6] = byte(ContentVersionV2)
	header[7] = contentHeaderReserved
	copy(header[8:24], nonceField)
	binary.BigEndian.PutUint64(header[24:32], uint64(plainSize))
	return header, nil
}

func ParseContentHeader(encType EncType, prefix []byte, ciphertextSize int64) (ContentMeta, bool, error) {
	meta := LegacyContentMeta(encType, ciphertextSize)
	if len(prefix) < contentHeaderMagicLen {
		return meta, false, nil
	}
	magic, ok := contentHeaderMagic[encType]
	if !ok || !bytes.Equal(prefix[:contentHeaderMagicLen], []byte(magic)) {
		return meta, false, nil
	}
	if len(prefix) < contentHeaderSize {
		return meta, false, fmt.Errorf("incomplete v2 content header")
	}
	version := int(prefix[6])
	if version != ContentVersionV2 {
		return meta, false, fmt.Errorf("unsupported content version: %d", version)
	}
	plainSize := int64(binary.BigEndian.Uint64(prefix[24:32]))
	if plainSize < 0 {
		return meta, false, fmt.Errorf("invalid plaintext size in content header")
	}
	nonceField := append([]byte(nil), prefix[8:24]...)
	meta = ContentMeta{
		EncType:        encType,
		Version:        ContentVersionV2,
		HeaderLen:      contentHeaderSize,
		PlainSize:      plainSize,
		CiphertextSize: ciphertextSize,
		NonceField:     nonceField,
	}
	if meta.CiphertextSize <= 0 {
		meta.CiphertextSize = meta.PlainSize + meta.HeaderLen
	}
	return meta, true, nil
}

func AutoDecryptReader(password string, encType EncType, ciphertext io.Reader, ciphertextSize int64) (io.Reader, ContentMeta, error) {
	encType = EncType(normalizeEncType(string(encType)))
	if encType == "" {
		encType = EncTypeAESCTR
	}
	prefix := make([]byte, contentHeaderSize)
	n, err := io.ReadFull(ciphertext, prefix)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			prefix = prefix[:n]
		} else {
			return nil, ContentMeta{}, err
		}
	}

	meta, ok, err := ParseContentHeader(encType, prefix, ciphertextSize)
	if err != nil {
		return nil, ContentMeta{}, err
	}
	if ok {
		cipherImpl, err := NewCipherV2(encType, password, meta.PlainSize, meta.NonceField)
		if err != nil {
			return nil, ContentMeta{}, err
		}
		return cipherImpl.DecryptReader(ciphertext), meta, nil
	}

	legacy := io.MultiReader(bytes.NewReader(prefix[:n]), ciphertext)
	cipherImpl, err := NewCipher(encType, password, ciphertextSize)
	if err != nil {
		return nil, ContentMeta{}, err
	}
	return cipherImpl.DecryptReader(legacy), meta, nil
}

type ContentEncryptor struct {
	Cipher Cipher
	Meta   ContentMeta
	Header []byte
}

func NewLatestContentEncryptor(password, encType string, plainSize int64) (*ContentEncryptor, error) {
	normalized := EncType(normalizeEncType(encType))
	if normalized == "" {
		normalized = EncTypeAESCTR
	}
	nonceField, err := generateRandomNonceField()
	if err != nil {
		return nil, err
	}
	meta := ContentMeta{
		EncType:        normalized,
		Version:        ContentVersionV2,
		HeaderLen:      contentHeaderSize,
		PlainSize:      plainSize,
		CiphertextSize: plainSize + contentHeaderSize,
		NonceField:     nonceField,
	}
	header, err := BuildV2Header(normalized, plainSize, nonceField)
	if err != nil {
		return nil, err
	}
	cipherImpl, err := NewCipherV2(normalized, password, plainSize, nonceField)
	if err != nil {
		return nil, err
	}
	return &ContentEncryptor{
		Cipher: cipherImpl,
		Meta:   meta,
		Header: header,
	}, nil
}

func (e *ContentEncryptor) EncryptReader(r io.Reader, startOffset int64) (io.Reader, error) {
	if e == nil || e.Cipher == nil {
		return nil, fmt.Errorf("content encryptor is nil")
	}
	if startOffset < 0 {
		return nil, fmt.Errorf("start offset cannot be negative")
	}
	if startOffset > 0 {
		if err := e.Cipher.SetPosition(startOffset); err != nil {
			return nil, err
		}
		return e.Cipher.EncryptReader(r), nil
	}
	return io.MultiReader(bytes.NewReader(e.Header), e.Cipher.EncryptReader(r)), nil
}
