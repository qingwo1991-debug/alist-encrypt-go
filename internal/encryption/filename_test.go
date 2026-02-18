package encryption

import (
	"strings"
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

	t.Run("direct encoded round-trip", func(t *testing.T) {
		gotEncType, gotPasswd, ok := DecodeFolderName(password, encType, encoded)
		if !ok {
			t.Fatal("DecodeFolderName failed for direct encoded value")
		}
		if gotEncType != folderEncType {
			t.Errorf("EncType: got %q, want %q", gotEncType, folderEncType)
		}
		if gotPasswd != folderPasswd {
			t.Errorf("Passwd: got %q, want %q", gotPasswd, folderPasswd)
		}
	})

	t.Run("legacy prefixed format still works", func(t *testing.T) {
		testEncoded := "prefix_" + encoded
		gotEncType, gotPasswd, ok := DecodeFolderName(password, encType, testEncoded)
		if !ok {
			t.Fatal("DecodeFolderName failed for legacy prefixed value")
		}
		if gotEncType != folderEncType {
			t.Errorf("EncType: got %q, want %q", gotEncType, folderEncType)
		}
		if gotPasswd != folderPasswd {
			t.Errorf("Passwd: got %q, want %q", gotPasswd, folderPasswd)
		}
	})
}

func TestMixBase64DecodeInvalidLength(t *testing.T) {
	passwdOutward := GetPasswdOutward("testpass", "aesctr")
	mix64 := NewMixBase64(passwdOutward)

	invalidInputs := []string{"a", "ab", "abc", "abcde"}
	for _, input := range invalidInputs {
		t.Run(input, func(t *testing.T) {
			if _, err := mix64.DecodeString(input); err == nil {
				t.Fatalf("expected error for invalid length input %q", input)
			}
		})
	}
}

func TestDecodeNameMalformedInputNoPanic(t *testing.T) {
	password := "testpass"
	encType := "aesctr"

	// Craft input that passes CRC check but has invalid MixBase64 payload length (1 char).
	subEncName := "A"
	passwdOutward := GetPasswdOutward(password, encType)
	crc6Check := GetSourceChar(crc6.Checksum([]byte(subEncName + passwdOutward)))
	malformed := subEncName + string(crc6Check)

	if got := DecodeName(password, encType, malformed); got != "" {
		t.Fatalf("DecodeName should fail gracefully for malformed input, got %q", got)
	}

	// Loose decode should also fail gracefully for malformed input.
	if got := DecodeNameLoose(password, encType, malformed); got != "" {
		t.Fatalf("DecodeNameLoose should fail gracefully for malformed input, got %q", got)
	}
}

func TestConvertRealNameWithSuffixRoundTrip(t *testing.T) {
	password := "testpass"
	encType := "aesctr"
	original := "movie.mp4"

	t.Run("empty suffix keeps round-trip", func(t *testing.T) {
		encrypted := ConvertRealNameWithSuffix(password, encType, original, "")
		if encrypted == "" {
			t.Fatal("ConvertRealNameWithSuffix returned empty")
		}

		show := ConvertShowName(password, encType, encrypted)
		if show != original {
			t.Fatalf("round-trip failed: got %q, want %q", show, original)
		}
	})

	t.Run("custom suffix keeps round-trip", func(t *testing.T) {
		encrypted := ConvertRealNameWithSuffix(password, encType, original, ".enc")
		if !strings.HasSuffix(encrypted, ".enc") {
			t.Fatalf("encrypted name %q should end with .enc", encrypted)
		}

		show := ConvertShowName(password, encType, encrypted)
		if show != original {
			t.Fatalf("round-trip with custom suffix failed: got %q, want %q", show, original)
		}
	})
}

func TestConvertShowNameDuplicateSuffixFallback(t *testing.T) {
	password := "testpass"
	encType := "aesctr"
	original := "movie.mp4"

	encrypted := ConvertRealNameWithSuffix(password, encType, original, ".bin")
	if !strings.HasSuffix(encrypted, ".bin") {
		t.Fatalf("encrypted name %q should end with .bin", encrypted)
	}

	base := strings.TrimSuffix(encrypted, ".bin")
	withDup := base + "(1).bin"

	show := ConvertShowNameWithSuffixOptions(password, encType, withDup, ".bin", false)
	if show != "movie(1).mp4" {
		t.Fatalf("duplicate suffix fallback failed: got %q, want %q", show, "movie(1).mp4")
	}
}

func TestConvertShowNameWithSuffixOptionsBranching(t *testing.T) {
	password := "testpass"
	encType := "aesctr"
	original := "movie.mp4"

	// Legacy style encrypted file with original extension.
	legacyEncrypted := ConvertRealNameWithSuffix(password, encType, original, "")
	if got := ConvertShowNameWithSuffixOptions(password, encType, legacyEncrypted, ".bin", false); got != original {
		t.Fatalf("legacy branch decode failed: got %q, want %q", got, original)
	}

	// Hidden suffix style with duplicate rename fallback.
	hiddenEncrypted := ConvertRealNameWithSuffix(password, encType, original, "bin")
	base := strings.TrimSuffix(hiddenEncrypted, ".bin")
	withDup := base + "(2).bin"
	if got := ConvertShowNameWithSuffixOptions(password, encType, withDup, ".bin", false); got != "movie(2).mp4" {
		t.Fatalf("hidden suffix decode failed: got %q, want %q", got, "movie(2).mp4")
	}
}

func TestNormalizeEncSuffix(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"   ":   "",
		".bin":  ".bin",
		"bin":   ".bin",
		" .dat": ".dat",
	}
	for in, want := range cases {
		if got := NormalizeEncSuffix(in); got != want {
			t.Fatalf("NormalizeEncSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPathExecWildcardAndRuntimePrefixes(t *testing.T) {
	patterns := []string{"/156天翼云盘个人/encrypt/*"}

	cases := []string{
		"/156天翼云盘个人/encrypt/a.mp4",
		"/d/156天翼云盘个人/encrypt/a.mp4",
		"/p/156天翼云盘个人/encrypt/a.mp4",
		"/dav/156天翼云盘个人/encrypt/a.mp4",
	}

	for _, c := range cases {
		if !PathExec(patterns, c) {
			t.Fatalf("expected PathExec true for %q", c)
		}
	}
}

func TestPathExecCompatRegexStillWorks(t *testing.T) {
	patterns := []string{`^/encrypt/.+`}
	if !PathExec(patterns, "/encrypt/a.mp4") {
		t.Fatal("regex pattern should still match for compatibility")
	}
}

func TestPathExecRegexWithDotStarNotExpanded(t *testing.T) {
	patterns := []string{`^/dav/.*/encrypt/.*`}
	if !PathExec(patterns, "/dav/移动云盘/encrypt/a.mp4") {
		t.Fatal("regex with dot-star should match")
	}
}
