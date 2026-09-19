package encryption

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/sync/singleflight"
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

const cacheEntryTTL = 30 * time.Minute

type cacheEntry[V any] struct {
	value    V
	expireAt time.Time
}

// passwdOutwardCache caches PBKDF2-derived keys to avoid repeated computation
// Key format: "password:encType"
var (
	passwdOutwardCache   = make(map[string]*cacheEntry[string])
	passwdOutwardCacheMu sync.RWMutex
)

// v2KeyCache caches V2 PBKDF2-derived base keys (600K iterations) to avoid repeated computation.
// Key format: "sha256(password):encType:keyLen". The per-file nonce is applied by each cipher after
// PBKDF2; it is not part of the PBKDF2 salt.
var (
	v2KeyCache           = make(map[string]*cacheEntry[[]byte])
	v2KeyCacheMu         sync.RWMutex
	v2KeyDerivationGroup singleflight.Group
	v2KeyCacheTTL        = 24 * time.Hour
	v2KeyCacheTTLMu      sync.RWMutex
)

const v2KeyCacheMaxEntries = 128

// SetV2KeyCacheTTL configures how long V2 PBKDF2 base keys stay hot in memory.
// Non-positive values keep the current TTL.
func SetV2KeyCacheTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	v2KeyCacheTTLMu.Lock()
	v2KeyCacheTTL = ttl
	v2KeyCacheTTLMu.Unlock()
}

func currentV2KeyCacheTTL() time.Duration {
	v2KeyCacheTTLMu.RLock()
	ttl := v2KeyCacheTTL
	v2KeyCacheTTLMu.RUnlock()
	if ttl <= 0 {
		return 24 * time.Hour
	}
	return ttl
}

type v2KeyDeriver func(password, encType string, keyLen int) []byte

func deriveV2KeyPBKDF2(password, encType string, keyLen int) []byte {
	return pbkdf2.Key([]byte(password), []byte(encType), pbkdf2IterationsModern, keyLen, sha256.New)
}

func v2KeyCacheKey(password, encType string, keyLen int) string {
	passHash := sha256.Sum256([]byte(password))
	return fmt.Sprintf("%x:%s:%d", passHash, encType, keyLen)
}

func loadCachedV2Key(cacheKey string, now time.Time, ttl time.Duration) ([]byte, bool) {
	v2KeyCacheMu.Lock()
	defer v2KeyCacheMu.Unlock()

	entry, ok := v2KeyCache[cacheKey]
	if !ok {
		return nil, false
	}
	if !now.Before(entry.expireAt) {
		delete(v2KeyCache, cacheKey)
		return nil, false
	}
	entry.expireAt = now.Add(ttl)
	return append([]byte(nil), entry.value...), true
}

func storeCachedV2Key(cacheKey string, key []byte, now time.Time, ttl time.Duration) {
	v2KeyCacheMu.Lock()
	defer v2KeyCacheMu.Unlock()

	if _, exists := v2KeyCache[cacheKey]; !exists && len(v2KeyCache) >= v2KeyCacheMaxEntries {
		for candidate, entry := range v2KeyCache {
			if !now.Before(entry.expireAt) {
				delete(v2KeyCache, candidate)
			}
		}
	}
	if _, exists := v2KeyCache[cacheKey]; !exists && len(v2KeyCache) >= v2KeyCacheMaxEntries {
		var oldestKey string
		var oldestExpiry time.Time
		for candidate, entry := range v2KeyCache {
			if oldestKey == "" || entry.expireAt.Before(oldestExpiry) {
				oldestKey = candidate
				oldestExpiry = entry.expireAt
			}
		}
		if oldestKey != "" {
			delete(v2KeyCache, oldestKey)
		}
	}
	v2KeyCache[cacheKey] = &cacheEntry[[]byte]{
		value:    append([]byte(nil), key...),
		expireAt: now.Add(ttl),
	}
}

// cachedV2Key returns a cached PBKDF2 key for V2 ciphers, computing it only on cache miss.
func cachedV2Key(password, encType string, keyLen int) []byte {
	return cachedV2KeyWithDeriver(password, encType, keyLen, deriveV2KeyPBKDF2)
}

func cachedV2KeyWithDeriver(password, encType string, keyLen int, derive v2KeyDeriver) []byte {
	cacheKey := v2KeyCacheKey(password, encType, keyLen)
	now := time.Now()
	ttl := currentV2KeyCacheTTL()
	if key, ok := loadCachedV2Key(cacheKey, now, ttl); ok {
		return key
	}

	value, _, _ := v2KeyDerivationGroup.Do(cacheKey, func() (interface{}, error) {
		ttl := currentV2KeyCacheTTL()
		if key, ok := loadCachedV2Key(cacheKey, time.Now(), ttl); ok {
			return key, nil
		}
		key := derive(password, encType, keyLen)
		storeCachedV2Key(cacheKey, key, time.Now(), ttl)
		return key, nil
	})
	return append([]byte(nil), value.([]byte)...)
}

// mixBase64Cache caches MixBase64 instances to avoid repeated KSA computation
// Key format: passwdOutward string
var (
	mixBase64Cache   = make(map[string]*cacheEntry[*MixBase64])
	mixBase64CacheMu sync.RWMutex
)

// NewFlowEnc creates a new FlowEnc instance using the cipher registry
func NewFlowEnc(password string, encType string, fileSize int64) (*FlowEnc, error) {
	encType = normalizeEncType(encType)
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
	encType = normalizeEncType(encType)
	cacheKey := password + ":" + encType

	// Try read from cache first (TTL check)
	passwdOutwardCacheMu.RLock()
	if entry, ok := passwdOutwardCache[cacheKey]; ok && time.Now().Before(entry.expireAt) {
		passwdOutwardCacheMu.RUnlock()
		return entry.value
	}
	passwdOutwardCacheMu.RUnlock()

	// Compute PBKDF2 key
	salt := "AES-CTR"
	switch encType {
	case "rc4md5":
		salt = "RC4" // Match Node.js alist-encrypt rc4Md5.js PBKDF2 salt
	case "chacha20":
		salt = "ChaCha20"
	}
	key := pbkdf2.Key([]byte(password), []byte(salt), 1000, 16, sha256.New)
	result := hex.EncodeToString(key)

	// Store in cache with TTL
	passwdOutwardCacheMu.Lock()
	passwdOutwardCache[cacheKey] = &cacheEntry[string]{
		value:    result,
		expireAt: time.Now().Add(cacheEntryTTL),
	}
	passwdOutwardCacheMu.Unlock()

	return result
}

func normalizeEncType(encType string) string {
	encType = strings.ToLower(strings.TrimSpace(encType))
	switch encType {
	case "", "aesctr", "chacha20", "rc4md5":
		return encType
	case "aes-ctr", "aes_ctr":
		return "aesctr"
	case "rc4":
		return "rc4md5"
	case "rc4-md5", "rc4_md5":
		return "rc4md5"
	default:
		return encType
	}
}

// GetCachedMixBase64 returns a cached MixBase64 instance for the given passwdOutward
// This avoids repeated KSA computation which involves SHA256 and S-box shuffling
func GetCachedMixBase64(passwdOutward string) *MixBase64 {
	// Try read from cache first (TTL check)
	mixBase64CacheMu.RLock()
	if entry, ok := mixBase64Cache[passwdOutward]; ok && time.Now().Before(entry.expireAt) {
		mixBase64CacheMu.RUnlock()
		return entry.value
	}
	mixBase64CacheMu.RUnlock()

	// Create new instance
	mix64 := NewMixBase64(passwdOutward)

	// Store in cache with TTL
	mixBase64CacheMu.Lock()
	mixBase64Cache[passwdOutward] = &cacheEntry[*MixBase64]{
		value:    mix64,
		expireAt: time.Now().Add(cacheEntryTTL),
	}
	mixBase64CacheMu.Unlock()

	return mix64
}
