package encryption

import (
	"fmt"
	"sync"
)

// CipherFactory creates a new cipher instance
type CipherFactory func(password string, fileSize int64) (Cipher, error)

// registry holds registered cipher factories
var (
	registryMu sync.RWMutex
	registry   = make(map[EncType]CipherFactory)
)

func init() {
	// Register built-in cipher types
	Register(EncTypeAESCTR, func(password string, fileSize int64) (Cipher, error) {
		return NewAESCTR(password, fileSize)
	})
	Register(EncTypeRC4MD5, func(password string, fileSize int64) (Cipher, error) {
		return NewRC4MD5(password, fileSize)
	})
	Register(EncTypeChaCha20, func(password string, fileSize int64) (Cipher, error) {
		return NewChaCha20(password, fileSize)
	})
}

// Register adds a cipher factory to the registry
func Register(encType EncType, factory CipherFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[encType] = factory
}

// NewCipher creates a cipher using the registry
func NewCipher(encType EncType, password string, fileSize int64) (Cipher, error) {
	registryMu.RLock()
	factory, ok := registry[encType]
	registryMu.RUnlock()

	if !ok {
		// Default to AES-CTR for unknown or empty type
		if encType == "" {
			return NewAESCTR(password, fileSize)
		}
		return nil, fmt.Errorf("unsupported encryption type: %s", encType)
	}

	return factory(password, fileSize)
}

// ListRegistered returns all registered cipher types
func ListRegistered() []EncType {
	registryMu.RLock()
	defer registryMu.RUnlock()

	types := make([]EncType, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	return types
}

// IsRegistered checks if an encryption type is registered
func IsRegistered(encType EncType) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[encType]
	return ok
}
