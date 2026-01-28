package encryption

import (
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"io"
)

// RC4MD5 implements RC4-MD5 encryption
type RC4MD5 struct {
	password string
	fileSize int64
	key      []byte
	cipher   *rc4.Cipher
	position int64
}

// NewRC4MD5 creates a new RC4-MD5 cipher instance
func NewRC4MD5(password string, fileSize int64) (*RC4MD5, error) {
	r := &RC4MD5{
		password: password,
		fileSize: fileSize,
	}

	// Generate key using MD5(password + fileSize)
	keyStr := password + fmt.Sprintf("%d", fileSize)
	keyHash := md5.Sum([]byte(keyStr))
	r.key = keyHash[:]

	// Create RC4 cipher
	cipher, err := rc4.NewCipher(r.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create RC4 cipher: %w", err)
	}
	r.cipher = cipher

	return r, nil
}

// SetPosition sets the stream position (re-initializes cipher and discards bytes)
func (r *RC4MD5) SetPosition(position int64) error {
	if position < 0 {
		return fmt.Errorf("position cannot be negative")
	}

	// RC4 is a stream cipher, so we need to regenerate and skip
	cipher, err := rc4.NewCipher(r.key)
	if err != nil {
		return fmt.Errorf("failed to recreate RC4 cipher: %w", err)
	}
	r.cipher = cipher

	// Discard bytes up to position (in chunks to save memory)
	remaining := position
	buf := make([]byte, 8192)
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}
		r.cipher.XORKeyStream(buf[:n], buf[:n])
		remaining -= n
	}

	r.position = position
	return nil
}

// Encrypt encrypts data in place
func (r *RC4MD5) Encrypt(data []byte) {
	r.cipher.XORKeyStream(data, data)
	r.position += int64(len(data))
}

// Decrypt decrypts data in place (same as encrypt for RC4)
func (r *RC4MD5) Decrypt(data []byte) {
	r.Encrypt(data)
}

// EncryptReader wraps a reader with encryption
func (r *RC4MD5) EncryptReader(reader io.Reader) io.Reader {
	return &rc4Reader{
		reader: reader,
		cipher: r,
	}
}

// DecryptReader wraps a reader with decryption
func (r *RC4MD5) DecryptReader(reader io.Reader) io.Reader {
	return r.EncryptReader(reader)
}

type rc4Reader struct {
	reader io.Reader
	cipher *RC4MD5
}

func (r *rc4Reader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.cipher.Decrypt(p[:n])
	}
	return n, err
}

// KeyHex returns the hex-encoded key for debugging
func (r *RC4MD5) KeyHex() string {
	return hex.EncodeToString(r.key)
}
