package encrypt

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// TestAESCTRKeyCompatibility 测试 AES-CTR 密钥派生与 Node.js 实现的兼容性
func TestAESCTRKeyCompatibility(t *testing.T) {
	// Node.js 实现的预期结果（使用密码 "test123" 和 fileSize 123456）
	// passwdOutward: 1533e0f3d2bf1da8b031e1d4ef6bc86a
	// passwdSalt: 1533e0f3d2bf1da8b031e1d4ef6bc86a123456
	// key: fd3f7e67b9f6771173fe626a6c2a5d14
	// iv: e10adc3949ba59abbe56e057f20f883e

	password := "test123"
	fileSize := int64(123456)
	expectedPasswdOutward := "1533e0f3d2bf1da8b031e1d4ef6bc86a"
	expectedKey := "fd3f7e67b9f6771173fe626a6c2a5d14"
	expectedIV := "e10adc3949ba59abbe56e057f20f883e"

	// 使用 Go 代码计算
	passwdOutward := GetPasswdOutward(password, EncTypeAESCTR)
	t.Logf("Go passwdOutward: %s", passwdOutward)
	t.Logf("Expected passwdOutward: %s", expectedPasswdOutward)

	if passwdOutward != expectedPasswdOutward {
		t.Errorf("passwdOutward mismatch: got %s, expected %s", passwdOutward, expectedPasswdOutward)
	}

	// 计算 key 和 iv
	sizeSalt := "123456"
	passwdSalt := passwdOutward + sizeSalt
	t.Logf("passwdSalt: %s", passwdSalt)

	keyHash := md5.Sum([]byte(passwdSalt))
	key := hex.EncodeToString(keyHash[:])
	t.Logf("Go key: %s", key)
	t.Logf("Expected key: %s", expectedKey)

	if key != expectedKey {
		t.Errorf("key mismatch: got %s, expected %s", key, expectedKey)
	}

	ivHash := md5.Sum([]byte(sizeSalt))
	iv := hex.EncodeToString(ivHash[:])
	t.Logf("Go iv: %s", iv)
	t.Logf("Expected iv: %s", expectedIV)

	if iv != expectedIV {
		t.Errorf("iv mismatch: got %s, expected %s", iv, expectedIV)
	}

	// 测试完整的加密器创建
	encryptor, err := NewFlowEncryptor(password, EncTypeAESCTR, fileSize)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// 加密和解密测试
	plaintext := []byte("Hello, World! 测试中文内容 123")
	encrypted, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 创建新的解密器
	decryptor, err := NewFlowEncryptor(password, EncTypeAESCTR, fileSize)
	if err != nil {
		t.Fatalf("Failed to create decryptor: %v", err)
	}

	decrypted, err := decryptor.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt mismatch: got %s, expected %s", string(decrypted), string(plaintext))
	}
}
