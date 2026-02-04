package encryption

import (
	"bytes"
	"io"
	"testing"
)

// TestCipherRoundTrip tests encrypt/decrypt round-trip for all cipher types
func TestCipherRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		encType  EncType
		password string
		fileSize int64
		data     []byte
	}{
		{"AES-CTR small", EncTypeAESCTR, "testpassword", 1024, []byte("Hello, World!")},
		{"AES-CTR medium", EncTypeAESCTR, "testpassword", 1024 * 1024, make([]byte, 1024)},
		{"AES-CTR block boundary", EncTypeAESCTR, "testpassword", 1024, make([]byte, 16)},
		{"RC4-MD5 small", EncTypeRC4MD5, "testpassword", 1024, []byte("Hello, World!")},
		{"RC4-MD5 medium", EncTypeRC4MD5, "testpassword", 1024 * 1024, make([]byte, 1024)},
		{"ChaCha20 small", EncTypeChaCha20, "testpassword", 1024, []byte("Hello, World!")},
		{"ChaCha20 medium", EncTypeChaCha20, "testpassword", 1024 * 1024, make([]byte, 1024)},
		{"ChaCha20 block boundary", EncTypeChaCha20, "testpassword", 1024, make([]byte, 64)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill test data with pattern
			for i := range tc.data {
				tc.data[i] = byte(i % 256)
			}
			original := make([]byte, len(tc.data))
			copy(original, tc.data)

			// Create cipher for encryption
			cipher, err := NewCipher(tc.encType, tc.password, tc.fileSize)
			if err != nil {
				t.Fatalf("Failed to create cipher: %v", err)
			}

			// Encrypt
			encrypted := make([]byte, len(tc.data))
			copy(encrypted, tc.data)
			cipher.Encrypt(encrypted)

			// Verify encryption changed the data
			if bytes.Equal(encrypted, original) && len(original) > 0 {
				t.Error("Encryption did not change the data")
			}

			// Create new cipher for decryption
			cipher2, err := NewCipher(tc.encType, tc.password, tc.fileSize)
			if err != nil {
				t.Fatalf("Failed to create cipher for decryption: %v", err)
			}

			// Decrypt
			cipher2.Decrypt(encrypted)

			// Verify round-trip
			if !bytes.Equal(encrypted, original) {
				t.Errorf("Round-trip failed: got %v, want %v", encrypted[:min(10, len(encrypted))], original[:min(10, len(original))])
			}
		})
	}
}

// TestCipherSeek tests position seeking for video scrubbing
func TestCipherSeek(t *testing.T) {
	testCases := []struct {
		name     string
		encType  EncType
		position int64
	}{
		{"AES-CTR seek 0", EncTypeAESCTR, 0},
		{"AES-CTR seek 16", EncTypeAESCTR, 16},
		{"AES-CTR seek 100", EncTypeAESCTR, 100},
		{"AES-CTR seek 1MB", EncTypeAESCTR, 1024 * 1024},
		{"ChaCha20 seek 0", EncTypeChaCha20, 0},
		{"ChaCha20 seek 64", EncTypeChaCha20, 64},
		{"ChaCha20 seek 100", EncTypeChaCha20, 100},
		{"ChaCha20 seek 1MB", EncTypeChaCha20, 1024 * 1024},
		{"RC4-MD5 seek 0", EncTypeRC4MD5, 0},
		{"RC4-MD5 seek 100", EncTypeRC4MD5, 100},
		{"RC4-MD5 seek 1KB", EncTypeRC4MD5, 1024},
	}

	password := "testpassword"
	fileSize := int64(10 * 1024 * 1024) // 10MB file
	dataSize := 256

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create data and encrypt from position 0
			data := make([]byte, int(tc.position)+dataSize)
			for i := range data {
				data[i] = byte(i % 256)
			}

			cipher1, _ := NewCipher(tc.encType, password, fileSize)
			encrypted := make([]byte, len(data))
			copy(encrypted, data)
			cipher1.Encrypt(encrypted)

			// Create new cipher and seek to position
			cipher2, _ := NewCipher(tc.encType, password, fileSize)
			if err := cipher2.SetPosition(tc.position); err != nil {
				t.Fatalf("SetPosition failed: %v", err)
			}

			// Decrypt from position
			partialEncrypted := encrypted[tc.position:]
			cipher2.Decrypt(partialEncrypted)

			// Verify
			expected := data[tc.position:]
			if !bytes.Equal(partialEncrypted, expected) {
				t.Errorf("Seek decrypt failed at position %d", tc.position)
			}
		})
	}
}

// TestCipherReader tests io.Reader wrapper
func TestCipherReader(t *testing.T) {
	testCases := []struct {
		name    string
		encType EncType
	}{
		{"AES-CTR reader", EncTypeAESCTR},
		{"RC4-MD5 reader", EncTypeRC4MD5},
		{"ChaCha20 reader", EncTypeChaCha20},
	}

	password := "testpassword"
	fileSize := int64(1024)
	data := []byte("Hello, World! This is a test message for streaming encryption.")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt using reader
			cipher1, _ := NewCipher(tc.encType, password, fileSize)
			encReader := cipher1.EncryptReader(bytes.NewReader(data))
			encrypted, err := io.ReadAll(encReader)
			if err != nil {
				t.Fatalf("Failed to read encrypted: %v", err)
			}

			// Decrypt using reader
			cipher2, _ := NewCipher(tc.encType, password, fileSize)
			decReader := cipher2.DecryptReader(bytes.NewReader(encrypted))
			decrypted, err := io.ReadAll(decReader)
			if err != nil {
				t.Fatalf("Failed to read decrypted: %v", err)
			}

			if !bytes.Equal(decrypted, data) {
				t.Errorf("Reader round-trip failed: got %s, want %s", decrypted, data)
			}
		})
	}
}

// TestFlowEncCreation tests FlowEnc creation with different types
func TestFlowEncCreation(t *testing.T) {
	testCases := []struct {
		encType string
		wantErr bool
	}{
		{"aesctr", false},
		{"rc4md5", false},
		{"chacha20", false},
		{"", false}, // defaults to AES-CTR
		{"invalid", true},
	}

	for _, tc := range testCases {
		t.Run(tc.encType, func(t *testing.T) {
			_, err := NewFlowEnc("password", tc.encType, 1024)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewFlowEnc() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
