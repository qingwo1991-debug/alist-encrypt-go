package encryption

import (
	"bytes"
	"testing"
)

// FuzzCipherRoundTrip fuzzes cipher encryption/decryption
func FuzzCipherRoundTrip(f *testing.F) {
	// Seed corpus
	f.Add([]byte("Hello, World!"), "password123", int64(1024))
	f.Add([]byte(""), "pass", int64(100))
	f.Add([]byte{0, 1, 2, 3, 4, 5}, "testpass", int64(1000000))
	f.Add(make([]byte, 1024), "longpasswordhere", int64(1024*1024))

	f.Fuzz(func(t *testing.T, data []byte, password string, fileSize int64) {
		if len(password) == 0 || fileSize <= 0 {
			return
		}

		// Test AES-CTR
		cipher1, err := NewAESCTR(password, fileSize)
		if err != nil {
			return
		}

		original := make([]byte, len(data))
		copy(original, data)

		encrypted := make([]byte, len(data))
		copy(encrypted, data)
		cipher1.Encrypt(encrypted)

		cipher2, _ := NewAESCTR(password, fileSize)
		cipher2.Decrypt(encrypted)

		if !bytes.Equal(encrypted, original) {
			t.Errorf("AES-CTR round-trip failed for data len %d", len(data))
		}
	})
}

// FuzzFilenameEncryption fuzzes filename encryption
func FuzzFilenameEncryption(f *testing.F) {
	// Seed corpus
	f.Add("movie.mp4", "password123", "aesctr")
	f.Add("日本語ファイル.mkv", "testpass", "rc4md5")
	f.Add("file with spaces.txt", "pass", "aesctr")
	f.Add("", "password", "aesctr")

	f.Fuzz(func(t *testing.T, filename string, password string, encType string) {
		if len(password) == 0 || len(filename) == 0 {
			return
		}

		// Normalize encType
		switch encType {
		case "aesctr", "rc4md5", "chacha20":
			// valid
		default:
			encType = "aesctr"
		}

		encoded := EncodeName(password, encType, filename)
		if encoded == "" {
			t.Errorf("EncodeName returned empty for %q", filename)
			return
		}

		decoded := DecodeName(password, encType, encoded)
		if decoded != filename {
			t.Errorf("Filename round-trip failed: got %q, want %q", decoded, filename)
		}
	})
}

// FuzzMixBase64 fuzzes MixBase64 encoding
func FuzzMixBase64(f *testing.F) {
	// Seed corpus
	f.Add([]byte("Hello"), "password")
	f.Add([]byte{0, 255, 128}, "pass")
	f.Add(make([]byte, 100), "testpass")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		if len(password) == 0 {
			return
		}

		passwdOutward := GetPasswdOutward(password, "aesctr")
		mix64 := NewMixBase64(passwdOutward)

		encoded := mix64.Encode(data)
		decoded, err := mix64.Decode(encoded)
		if err != nil {
			t.Errorf("Decode error: %v", err)
			return
		}

		if !bytes.Equal(decoded, data) {
			t.Errorf("MixBase64 round-trip failed for data len %d", len(data))
		}
	})
}
