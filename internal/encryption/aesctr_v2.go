package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func NewAESCTRV2(password string, plainSize int64, nonceField []byte) (*AESCTR, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	a := &AESCTR{
		password: password,
		fileSize: plainSize,
	}
	key := pbkdf2.Key([]byte(password), []byte("AES-CTR-v2"), pbkdf2IterationsModern, 16, sha256.New)
	a.key = append([]byte(nil), key...)
	a.iv = append([]byte(nil), nonceField...)
	a.sourceIv = append([]byte(nil), nonceField...)
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	a.block = block
	a.stream = cipher.NewCTR(block, a.iv)
	return a, nil
}
