package encryption

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

func NewRC4MD5V2(password string, plainSize int64, nonceField []byte) (*RC4MD5, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	r := &RC4MD5{
		password: password,
		fileSize: plainSize,
	}
	baseKey := pbkdf2.Key([]byte(password), []byte("RC4-v2"), pbkdf2IterationsModern, 16, sha256.New)
	material := append(append([]byte(nil), baseKey...), nonceField...)
	hash := md5.Sum(material)
	r.fileHexKey = hex.EncodeToString(hash[:])
	key, err := hex.DecodeString(r.fileHexKey)
	if err != nil {
		return nil, err
	}
	r.key = key
	if err := r.resetKSA(); err != nil {
		return nil, err
	}
	return r, nil
}
