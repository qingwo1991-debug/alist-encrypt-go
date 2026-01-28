package encryption

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// EncType represents encryption type
type EncType string

const (
	EncTypeAESCTR EncType = "aesctr"
	EncTypeRC4MD5 EncType = "rc4md5"
)

// Cipher interface for encryption/decryption
type Cipher interface {
	SetPosition(position int64) error
	Encrypt(data []byte)
	Decrypt(data []byte)
	EncryptReader(r io.Reader) io.Reader
	DecryptReader(r io.Reader) io.Reader
}

// FlowEnc is the encryption dispatcher
type FlowEnc struct {
	cipher   Cipher
	encType  EncType
	password string
	fileSize int64
}

// NewFlowEnc creates a new FlowEnc instance
func NewFlowEnc(password string, encType string, fileSize int64) (*FlowEnc, error) {
	f := &FlowEnc{
		password: password,
		fileSize: fileSize,
		encType:  EncType(encType),
	}

	var err error
	switch f.encType {
	case EncTypeAESCTR, "":
		f.cipher, err = NewAESCTR(password, fileSize)
		if f.encType == "" {
			f.encType = EncTypeAESCTR
		}
	case EncTypeRC4MD5:
		f.cipher, err = NewRC4MD5(password, fileSize)
	default:
		return nil, fmt.Errorf("unsupported encryption type: %s", encType)
	}

	if err != nil {
		return nil, err
	}

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

// GetPasswdOutward generates the outward password key for filename encryption
// This matches the Node.js FlowEnc.getPassWdOutward implementation
func GetPasswdOutward(password, encType string) string {
	salt := "AES-CTR"
	if encType == "rc4md5" {
		salt = "RC4-MD5"
	}
	key := pbkdf2.Key([]byte(password), []byte(salt), 1000, 16, sha256.New)
	return hex.EncodeToString(key)
}
