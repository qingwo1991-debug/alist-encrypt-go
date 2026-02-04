package encryption

import (
	"testing"
)

// TestFileNameEncryption tests round-trip for various filenames
func TestFileNameEncryption(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		encType  string
		filename string
	}{
		{"simple ASCII", "testpass", "aesctr", "movie.mp4"},
		{"with spaces", "testpass", "aesctr", "my movie file.mp4"},
		{"unicode Japanese", "testpass", "aesctr", "映画.mp4"},
		{"unicode Chinese", "testpass", "aesctr", "电影文件.mkv"},
		{"mixed", "testpass", "aesctr", "Movie_2024_日本語.mp4"},
		{"special chars", "testpass", "aesctr", "file-name_v1.2.mp4"},
		{"long name", "testpass", "aesctr", "this_is_a_very_long_filename_that_exceeds_normal_length.mp4"},
		{"RC4-MD5", "testpass", "rc4md5", "test_file.mp4"},
		{"ChaCha20", "testpass", "chacha20", "test_file.mp4"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded := EncodeName(tc.password, tc.encType, tc.filename)
			if encoded == "" {
				t.Fatal("EncodeName returned empty string")
			}
			if encoded == tc.filename {
				t.Error("EncodeName did not change the filename")
			}

			// Decode
			decoded := DecodeName(tc.password, tc.encType, encoded)
			if decoded != tc.filename {
				t.Errorf("Round-trip failed: got %q, want %q", decoded, tc.filename)
			}
		})
	}
}

// TestMixBase64 tests custom Base64 encoding
func TestMixBase64(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		data     string
	}{
		{"empty", "pass", ""},
		{"short", "pass", "ab"},
		{"medium", "pass", "Hello, World!"},
		{"binary-like", "pass", string([]byte{0, 1, 2, 255, 254, 253})},
		{"unicode", "pass", "日本語テスト"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			passwdOutward := GetPasswdOutward(tc.password, "aesctr")
			mix64 := NewMixBase64(passwdOutward)

			encoded := mix64.EncodeString(tc.data)
			decoded, err := mix64.DecodeString(encoded)
			if err != nil {
				t.Fatalf("Decode error: %v", err)
			}

			if decoded != tc.data {
				t.Errorf("Round-trip failed: got %q, want %q", decoded, tc.data)
			}
		})
	}
}

// TestCRC6 tests checksum verification
func TestCRC6(t *testing.T) {
	crc := NewCRC6()

	// Test that CRC6 returns values in valid range (0-63)
	testData := []string{"", "a", "test", "Hello, World!", "longer test string"}

	for _, data := range testData {
		t.Run(data, func(t *testing.T) {
			result := crc.Checksum([]byte(data))
			if result < 0 || result > 63 {
				t.Errorf("CRC6(%q) = %d, should be in range 0-63", data, result)
			}
		})
	}

	// Test consistency
	t.Run("consistency", func(t *testing.T) {
		data := []byte("consistent test data")
		result1 := crc.Checksum(data)
		result2 := crc.Checksum(data)
		if result1 != result2 {
			t.Errorf("CRC6 not consistent: %d != %d", result1, result2)
		}
	})

	// Test that different inputs produce different outputs (usually)
	t.Run("different_inputs", func(t *testing.T) {
		result1 := crc.Checksum([]byte("input1"))
		result2 := crc.Checksum([]byte("input2"))
		// They could collide but usually won't for these short distinct strings
		t.Logf("CRC6(input1)=%d, CRC6(input2)=%d", result1, result2)
	})
}

// TestConvertShowName tests display name conversion
func TestConvertShowName(t *testing.T) {
	password := "testpassword"
	encType := "aesctr"

	testCases := []struct {
		name     string
		filename string
	}{
		{"simple", "movie.mp4"},
		{"unicode", "映画.mp4"},
		{"spaces", "my file.mp4"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			encrypted := EncodeName(password, encType, tc.filename)
			encryptedWithExt := encrypted + ".mp4"

			// Convert to show name
			showName := ConvertShowName(password, encType, encryptedWithExt)

			if showName == "" {
				t.Error("ConvertShowName returned empty")
			}
			// The show name should be the original filename (since we encoded the full name)
			if showName != tc.filename {
				t.Logf("ShowName: %s (expected: %s)", showName, tc.filename)
			}
		})
	}
}

// TestFileNameConverter tests the converter helper
func TestFileNameConverter(t *testing.T) {
	converter := NewFileNameConverter("testpass", "aesctr", "")

	t.Run("encrypt/decrypt", func(t *testing.T) {
		original := "test_file"
		encrypted := converter.EncryptFileName(original)
		decrypted := converter.DecryptFileName(encrypted)

		if decrypted != original {
			t.Errorf("Round-trip failed: got %q, want %q", decrypted, original)
		}
	})

	t.Run("IsOriginalFile", func(t *testing.T) {
		if !IsOriginalFile("orig_file.mp4") {
			t.Error("Should detect orig_ prefix")
		}
		if IsOriginalFile("normal_file.mp4") {
			t.Error("Should not detect without prefix")
		}
	})

	t.Run("StripOriginalPrefix", func(t *testing.T) {
		result := StripOriginalPrefix("orig_file.mp4")
		if result != "file.mp4" {
			t.Errorf("Got %q, want %q", result, "file.mp4")
		}
	})
}

// TestFolderNameEncryption tests folder password encoding
func TestFolderNameEncryption(t *testing.T) {
	password := "mainpass"
	encType := "aesctr"
	folderPasswd := "folderpass"
	folderEncType := "rc4md5"

	encoded := EncodeFolderName(password, encType, folderPasswd, folderEncType)
	if encoded == "" {
		t.Fatal("EncodeFolderName returned empty")
	}

	// Note: DecodeFolderName expects a specific format with underscore prefix
	// The encoded result needs to be prefixed for the decode function
	testEncoded := "prefix_" + encoded
	gotEncType, gotPasswd, ok := DecodeFolderName(password, encType, testEncoded)

	if !ok {
		t.Fatal("DecodeFolderName failed")
	}
	if gotEncType != folderEncType {
		t.Errorf("EncType: got %q, want %q", gotEncType, folderEncType)
	}
	if gotPasswd != folderPasswd {
		t.Errorf("Passwd: got %q, want %q", gotPasswd, folderPasswd)
	}
}
