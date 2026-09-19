package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func NewAESCTRV2(password string, plainSize int64, nonceField []byte) (*AESCTR, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	a := &AESCTR{
		password: password,
		fileSize: plainSize,
	}
	key := cachedV2Key(password, "AES-CTR-v2", 16)
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
