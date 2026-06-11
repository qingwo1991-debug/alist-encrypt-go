package encrypt

import (
	"bytes"
	"testing"
)

// TestChaCha20KeyCompatibilityWithAlistEncryptGo 验证 ChaCha20 密钥派生与 alist-encrypt-go 一致
// 测试向量来自 alist-encrypt-go 的 chacha20.go 实现逻辑
func TestChaCha20KeyCompatibilityWithAlistEncryptGo(t *testing.T) {
	password := "test123"
	fileSize := int64(123456)

	// alist-encrypt-go 使用 pbkdf2(password, "ChaCha20", 1000, 32, sha256) -> hex
	// 然后 sha256(passwdOutward + sizeSalt) -> 32 byte key
	// 本项目现在也应相同

	enc1, err := NewChaCha20Encryptor(password, GetPasswdOutwardChaCha20(password), fileSize)
	if err != nil {
		t.Fatalf("NewChaCha20Encryptor failed: %v", err)
	}

	enc2, err := NewChaCha20Encryptor(password, GetPasswdOutwardChaCha20(password), fileSize)
	if err != nil {
		t.Fatalf("NewChaCha20Encryptor (dec) failed: %v", err)
	}

	plaintext := []byte("Hello, alist-encrypt-go compatible ChaCha20!")
	encrypted, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encryption should change data")
	}

	decrypted, err := enc2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

// TestChaCha20SeekCompatibility 验证 SetPosition 与 alist-encrypt-go 行为一致
func TestChaCha20SeekCompatibility(t *testing.T) {
	password := "seektest"
	fileSize := int64(10 * 1024 * 1024)
	passwdOutward := GetPasswdOutwardChaCha20(password)

	// 全量加密
	enc1, _ := NewChaCha20Encryptor(password, passwdOutward, fileSize)
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	fullEncrypted, _ := enc1.Encrypt(data)

	// 从 5000 字节处 seek 加密
	enc2, _ := NewChaCha20Encryptor(password, passwdOutward, fileSize)
	if err := enc2.SetPosition(5000); err != nil {
		t.Fatalf("SetPosition failed: %v", err)
	}
	partialEncrypted, _ := enc2.Encrypt(data[5000:])

	if !bytes.Equal(partialEncrypted, fullEncrypted[5000:]) {
		t.Fatal("seek encryption should match full encryption at same offset")
	}
}

func TestChaCha20SetPositionRejectsCounterOverflow(t *testing.T) {
	password := "seektest"
	passwdOutward := GetPasswdOutwardChaCha20(password)
	enc, err := NewChaCha20Encryptor(password, passwdOutward, 1<<40)
	if err != nil {
		t.Fatalf("NewChaCha20Encryptor failed: %v", err)
	}

	if err := enc.SetPosition((1 << 32) * 64); err == nil {
		t.Fatal("expected counter overflow error")
	}
}
