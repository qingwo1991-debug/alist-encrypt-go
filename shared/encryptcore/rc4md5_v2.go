package encryption

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
)

func NewRC4MD5V2(password string, plainSize int64, nonceField []byte) (*RC4MD5, error) {
	if len(nonceField) != 16 {
		return nil, fmt.Errorf("nonce field must be 16 bytes")
	}
	r := &RC4MD5{
		password: password,
		fileSize: plainSize,
	}
	baseKey := cachedV2Key(password, "RC4-v2", 16)
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
