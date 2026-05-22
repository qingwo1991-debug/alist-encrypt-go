package encrypt

import (
	"fmt"
	"sync"
)

// EncryptorFactory 创建 FlowEncryptor 的工厂函数类型
type EncryptorFactory func(password, passwdOutward string, fileSize int64) (FlowEncryptor, error)

var (
	registryMu sync.RWMutex
	registry   = make(map[EncryptionType]EncryptorFactory)
)

func init() {
	// 注册内置算法
	RegisterEncryptor(EncTypeAESCTR, func(password, passwdOutward string, fileSize int64) (FlowEncryptor, error) {
		return NewAESCTREncryptor(password, passwdOutward, fileSize)
	})
	RegisterEncryptor(EncTypeRC4, func(password, passwdOutward string, fileSize int64) (FlowEncryptor, error) {
		return NewRC4MD5Encryptor(password, passwdOutward, fileSize)
	})
	RegisterEncryptor(EncTypeChaCha20, func(password, passwdOutward string, fileSize int64) (FlowEncryptor, error) {
		return NewChaCha20Encryptor(password, passwdOutward, fileSize)
	})
	RegisterEncryptor(EncTypeMix, func(password, passwdOutward string, fileSize int64) (FlowEncryptor, error) {
		return NewMixEncryptor(password, fileSize)
	})
}

// RegisterEncryptor 注册一个加密算法工厂（支持外部扩展）
func RegisterEncryptor(encType EncryptionType, factory EncryptorFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[encType] = factory
}

// IsEncryptorRegistered 检查算法是否已注册
func IsEncryptorRegistered(encType EncryptionType) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[encType]
	return ok
}

// ListRegisteredEncryptors 列出所有已注册算法
func ListRegisteredEncryptors() []EncryptionType {
	registryMu.RLock()
	defer registryMu.RUnlock()
	types := make([]EncryptionType, 0, len(registry))
	for t := range registry {
		types = append(types, t)
	}
	return types
}

// NewFlowEncryptorFromRegistry 通过注册表创建加密器（替代原 switch-case 工厂）
// 注意：此函数与原 NewFlowEncryptor 共存，不强制替换，让调用方逐步迁移
func NewFlowEncryptorFromRegistry(password string, encType EncryptionType, fileSize int64) (FlowEncryptor, error) {
	registryMu.RLock()
	factory, ok := registry[encType]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unsupported encryption type: %s", encType)
	}

	passwdOutward := GetPasswdOutward(password, encType)
	return factory(password, passwdOutward, fileSize)
}
