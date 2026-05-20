package encryption

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// TestGenCrossCompatVectors 生成两项目共享的兼容性测试向量
// 运行: go test -run TestGenCrossCompatVectors -v
// 把输出的 hex 填入 OpenList-Encrypt 的 cross_compat_test.go
func TestGenCrossCompatVectors(t *testing.T) {
	vectors := []struct {
		password string
		fileSize int64
		encType  EncType
	}{
		{"test123", 123456, EncTypeAESCTR},
		{"test123", 123456, EncTypeRC4MD5},
		{"test123", 123456, EncTypeChaCha20},
	}

	plain := make([]byte, 16) // 全零明文

	for _, v := range vectors {
		cipher, err := NewCipher(v.encType, v.password, v.fileSize)
		if err != nil {
			t.Errorf("NewCipher(%s) failed: %v", v.encType, err)
			continue
		}

		data := make([]byte, len(plain))
		copy(data, plain)
		cipher.Encrypt(data)

		fmt.Printf("encType=%-10s password=%-10s fileSize=%-8d plain=%s ciphertext=%s\n",
			v.encType, v.password, v.fileSize,
			hex.EncodeToString(plain),
			hex.EncodeToString(data))
	}
}
