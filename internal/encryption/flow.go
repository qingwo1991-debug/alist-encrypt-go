package encryption

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"

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

// passwdOutwardCache caches PBKDF2-derived keys to avoid repeated computation
// Key format: "password:encType"
var (
	passwdOutwardCache   = make(map[string]string)
	passwdOutwardCacheMu sync.RWMutex
)

// mixBase64Cache caches MixBase64 instances to avoid repeated KSA computation
// Key format: passwdOutward string
var (
	mixBase64Cache   = make(map[string]*MixBase64)
	mixBase64CacheMu sync.RWMutex
)

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
// Results are cached to avoid repeated PBKDF2 computation (1000 iterations)
func GetPasswdOutward(password, encType string) string {
	cacheKey := password + ":" + encType

	// Try read from cache first
	passwdOutwardCacheMu.RLock()
	if cached, ok := passwdOutwardCache[cacheKey]; ok {
		passwdOutwardCacheMu.RUnlock()
		return cached
	}
	passwdOutwardCacheMu.RUnlock()

	// Compute PBKDF2 key
	salt := "AES-CTR"
	switch encType {
	case "rc4md5":
		salt = "RC4-MD5"
	case "chacha20":
		salt = "ChaCha20"
	}
	key := pbkdf2.Key([]byte(password), []byte(salt), 1000, 16, sha256.New)
	result := hex.EncodeToString(key)

	// Store in cache
	passwdOutwardCacheMu.Lock()
	passwdOutwardCache[cacheKey] = result
	passwdOutwardCacheMu.Unlock()

	return result
}

// GetCachedMixBase64 returns a cached MixBase64 instance for the given passwdOutward
// This avoids repeated KSA computation which involves SHA256 and S-box shuffling
func GetCachedMixBase64(passwdOutward string) *MixBase64 {
	// Try read from cache first
	mixBase64CacheMu.RLock()
	if cached, ok := mixBase64Cache[passwdOutward]; ok {
		mixBase64CacheMu.RUnlock()
		return cached
	}
	mixBase64CacheMu.RUnlock()

	// Create new instance
	mix64 := NewMixBase64(passwdOutward)

	// Store in cache
	mixBase64CacheMu.Lock()
	mixBase64Cache[passwdOutward] = mix64
	mixBase64CacheMu.Unlock()

	return mix64
}
