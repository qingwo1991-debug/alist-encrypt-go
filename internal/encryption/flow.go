package encryption

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// EncType represents encryption type
type EncType string

const (
	EncTypeAESCTR   EncType = "aesctr"
	EncTypeRC4MD5   EncType = "rc4md5"
	EncTypeChaCha20 EncType = "chacha20"
)

// Cipher interface for encryption/decryption
type Cipher interface {
	SetPosition(position int64) error
	Encrypt(data []byte)
	Decrypt(data []byte)
	EncryptReader(r io.Reader) io.Reader
	DecryptReader(r io.Reader) io.Reader
}

// FlowEnc is the encryption dispatcher that uses the cipher registry
type FlowEnc struct {
	cipher   Cipher
	encType  EncType
	password string
	fileSize int64
}

// NewFlowEnc creates a new FlowEnc instance using the cipher registry
func NewFlowEnc(password string, encType string, fileSize int64) (*FlowEnc, error) {
	f := &FlowEnc{
		password: password,
		fileSize: fileSize,
		encType:  EncType(encType),
	}

	// Handle empty encType - default to AES-CTR
	if f.encType == "" {
		f.encType = EncTypeAESCTR
	}

	// Use the registry to create the cipher
	cipher, err := NewCipher(f.encType, password, fileSize)
	if err != nil {
		return nil, err
	}
	f.cipher = cipher

	return f, nil
}

// SetPosition sets the stream position for seeking
func (f *FlowEnc) SetPosition(position int64) error {
	return f.cipher.SetPosition(position)
}

// Encrypt encrypts data in place
func (f *FlowEnc) Encrypt(data []byte) {
	f.cipher.Encrypt(data)
}

// Decrypt decrypts data in place
func (f *FlowEnc) Decrypt(data []byte) {
	f.cipher.Decrypt(data)
}

// EncryptReader wraps a reader with encryption
func (f *FlowEnc) EncryptReader(r io.Reader) io.Reader {
	return f.cipher.EncryptReader(r)
}

// DecryptReader wraps a reader with decryption
func (f *FlowEnc) DecryptReader(r io.Reader) io.Reader {
	return f.cipher.DecryptReader(r)
}

// GetEncType returns the encryption type
func (f *FlowEnc) GetEncType() EncType {
	return f.encType
}

// GetCipher returns the underlying cipher (for advanced use)
func (f *FlowEnc) GetCipher() Cipher {
	return f.cipher
}

// GetPasswdOutward generates the outward password key for filename encryption
// This matches the Node.js FlowEnc.getPassWdOutward implementation
func GetPasswdOutward(password, encType string) string {
	salt := "AES-CTR"
	switch encType {
	case "rc4md5":
		salt = "RC4-MD5"
	case "chacha20":
		salt = "ChaCha20"
	}
	key := pbkdf2.Key([]byte(password), []byte(salt), 1000, 16, sha256.New)
	return hex.EncodeToString(key)
}
