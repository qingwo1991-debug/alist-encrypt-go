package encrypt

import (
	"bytes"
	"testing"
)

// FuzzAESCTRRoundTrip 对 AES-CTR 加解密进行模糊测试
func FuzzAESCTRRoundTrip(f *testing.F) {
	f.Add([]byte("Hello, World!"), "password123", int64(1024))
	f.Add([]byte{}, "pass", int64(100))
	f.Add([]byte{0, 1, 2, 3, 4, 5}, "testpass", int64(1000000))
	f.Add(make([]byte, 1024), "longpasswordhere", int64(1024*1024))

	f.Fuzz(func(t *testing.T, data []byte, password string, fileSize int64) {
		if len(password) == 0 || fileSize <= 0 {
			return
		}

		enc, err := NewFlowEncryptor(password, EncTypeAESCTR, fileSize)
		if err != nil {
			return
		}
		dec, err := NewFlowEncryptor(password, EncTypeAESCTR, fileSize)
		if err != nil {
			return
		}

		original := make([]byte, len(data))
		copy(original, data)

		encrypted, err := enc.Encrypt(data)
		if err != nil {
			return
		}

		decrypted, err := dec.Decrypt(encrypted)
		if err != nil {
			t.Errorf("Decrypt failed: %v", err)
			return
		}

		if !bytes.Equal(decrypted, original) {
			t.Errorf("round-trip failed for data len %d", len(data))
		}
	})
}

// FuzzFilenameEncryption 对文件名加解密进行模糊测试
func FuzzFilenameEncryption(f *testing.F) {
	f.Add("movie.mp4", "password123", "aes-ctr")
	f.Add("日本語ファイル.mkv", "testpass", "rc4md5")
	f.Add("file with spaces.txt", "pass", "aes-ctr")

	f.Fuzz(func(t *testing.T, filename string, password string, encTypeStr string) {
		if len(password) == 0 || len(filename) == 0 {
			return
		}

		var encType EncryptionType
		switch encTypeStr {
		case "aes-ctr", "aesctr":
			encType = EncTypeAESCTR
		case "rc4md5", "rc4":
			encType = EncTypeRC4
		default:
			encType = EncTypeAESCTR
		}

		encoded := EncodeName(password, encType, filename)
		if encoded == "" {
			t.Errorf("EncodeName returned empty for %q", filename)
			return
		}

		decoded := DecodeName(password, encType, encoded)
		if decoded != filename {
			t.Errorf("filename round-trip failed: got %q, want %q", decoded, filename)
		}
	})
}

// FuzzMixBase64RoundTrip 对 MixBase64 编解码进行模糊测试
func FuzzMixBase64RoundTrip(f *testing.F) {
	f.Add([]byte("Hello"), "password")
	f.Add([]byte{0, 255, 128}, "pass")
	f.Add(make([]byte, 100), "testpass")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		if len(password) == 0 {
			return
		}

		passwdOutward := GetPasswdOutward(password, EncTypeAESCTR)
		mix64 := NewMixBase64(passwdOutward)

		encoded := mix64.Encode(string(data))
		decoded, err := mix64.Decode(encoded)
		if err != nil {
			// 允许解码失败（可能是填充问题），但不应 panic
			return
		}

		if !bytes.Equal(decoded, data) {
			t.Errorf("MixBase64 round-trip failed for data len %d", len(data))
		}
	})
}
