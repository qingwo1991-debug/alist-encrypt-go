package encryption

import (
	"fmt"

	"golang.org/x/crypto/chacha20"
)

func NewChaCha20V2(password string, plainSize int64, nonceField []byte) (*ChaCha20Cipher, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	c := &ChaCha20Cipher{
		password: password,
		fileSize: plainSize,
	}
	key := cachedV2Key(password, "ChaCha20-v2", 32)
	c.key = append([]byte(nil), key...)
	c.nonce = append([]byte(nil), nonceField[:12]...)
	cipherImpl, err := chacha20.NewUnauthenticatedCipher(c.key, c.nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}
	c.cipher = cipherImpl
	return c, nil
}
