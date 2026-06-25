package encrypt

import (
	"path"
	"strings"
	"testing"
)

// TestFilenameDecryptCompat tests filename decryption compatibility.
// Uses synthetic test data — no real passwords or filenames.
func TestFilenameDecryptCompat(t *testing.T) {
	password := "testpass123"
	encType := EncTypeAESCTR

	// Generate cipher names at runtime so the test is self-consistent.
	plainNames := []string{
		"sample-video.mp4",
		"document.pdf",
		"photo_2024.jpg",
	}

	for _, plainName := range plainNames {
		cipherName := EncodeName(password, encType, plainName)
		if cipherName == "" {
			t.Fatalf("EncodeName returned empty for %q", plainName)
		}

		t.Run(plainName, func(t *testing.T) {
			decoded := DecodeName(password, encType, cipherName)
			if decoded != plainName {
				t.Errorf("Decode mismatch!\n  Cipher: %s\n  Expected: %s\n  Got: %s",
					cipherName, plainName, decoded)
			}

			// Verify re-encoding produces the same cipher
			reEncoded := EncodeName(password, encType, decoded)
			if reEncoded != cipherName {
				t.Errorf("Encode mismatch!\n  Plain: %s\n  Expected cipher: %s\n  Got: %s",
					decoded, cipherName, reEncoded)
			}
		})
	}
}

// TestFilenameKnownSyntheticVectors protects filename compatibility without
// embedding user passwords, private paths, or real media names. Unlike a
// runtime-generated round trip, these constants detect accidental format changes.
func TestFilenameKnownSyntheticVectors(t *testing.T) {
	const password = "testpass123"
	tests := []struct {
		plain  string
		cipher string
	}{
		{plain: "sample-video.mp4", cipher: "gMFVgb26CX9e9bQ-Cw1xUriiU"},
		{plain: "document.pdf", cipher: "9bIGlq16BSvhgbYwi"},
		{plain: "photo_2024.jpg", cipher: "gbp-lbIjtGraUH+Rgbgi4"},
	}

	for _, tc := range tests {
		t.Run(tc.plain, func(t *testing.T) {
			if got := EncodeName(password, EncTypeAESCTR, tc.plain); got != tc.cipher {
				t.Fatalf("EncodeName(%q) = %q, want fixed compatibility vector %q", tc.plain, got, tc.cipher)
			}
			if got := DecodeName(password, EncTypeAESCTR, tc.cipher); got != tc.plain {
				t.Fatalf("DecodeName(%q) = %q, want %q", tc.cipher, got, tc.plain)
			}
		})
	}
}

// TestFilenameDecryptWithStringEncType tests using string "aesctr" as encryption type,
// simulating values read from JSON config.
func TestFilenameDecryptWithStringEncType(t *testing.T) {
	password := "testpass123"
	encTypeFromConfig := EncryptionType("aesctr")

	plainName := "sample-video.mp4"
	cipherName := EncodeName(password, encTypeFromConfig, plainName)
	if cipherName == "" {
		t.Fatalf("EncodeName returned empty for %q", plainName)
	}

	// Compare passwdOutward with const version
	passwdOutward := GetPasswdOutward(password, encTypeFromConfig)
	passwdOutwardConst := GetPasswdOutward(password, EncTypeAESCTR)
	if passwdOutward != passwdOutwardConst {
		t.Errorf("passwdOutward mismatch between string and const encType")
	}

	decoded := DecodeName(password, encTypeFromConfig, cipherName)
	if decoded != plainName {
		t.Errorf("Decode mismatch with string encType!\n  Cipher: %s\n  Expected: %s\n  Got: %s",
			cipherName, plainName, decoded)
	}
}

// TestFilenameEncryptCompat tests filename encryption compatibility.
func TestFilenameEncryptCompat(t *testing.T) {
	password := "testpass123"
	encType := EncTypeAESCTR

	plainNames := []string{
		"sample-video.mp4",
		"document.pdf",
		"photo_2024.jpg",
	}

	for _, plainName := range plainNames {
		t.Run(plainName, func(t *testing.T) {
			encoded := EncodeName(password, encType, plainName)
			if encoded == "" {
				t.Fatalf("EncodeName returned empty for %q", plainName)
			}

			// Verify roundtrip: decode should return original
			decoded := DecodeName(password, encType, encoded)
			if decoded != plainName {
				t.Errorf("Roundtrip failed!\n  Plain: %s\n  Encoded: %s\n  Decoded: %s",
					plainName, encoded, decoded)
			}
		})
	}
}

// TestConvertShowNameCompat tests ConvertShowName compatibility.
func TestConvertShowNameCompat(t *testing.T) {
	password := "testpass123"
	encType := EncTypeAESCTR

	plainNames := []string{
		"sample-video.mp4",
		"document.pdf",
		"photo_2024.jpg",
	}

	for _, plainName := range plainNames {
		// Generate the server-side encrypted filename
		cipherBase := EncodeName(password, encType, plainName)
		ext := path.Ext(plainName)
		serverFileName := cipherBase + ext

		t.Run(serverFileName, func(t *testing.T) {
			showName := ConvertShowName(password, encType, serverFileName)
			if showName != plainName {
				t.Errorf("ConvertShowName mismatch!\n  Input: %s\n  Expected: %s\n  Got: %s",
					serverFileName, plainName, showName)
			}
		})
	}
}

// TestMixBase64Compat tests MixBase64 encode/decode roundtrip.
func TestMixBase64Compat(t *testing.T) {
	password := "testpass123"
	encType := EncTypeAESCTR
	passwdOutward := GetPasswdOutward(password, encType)

	mix64 := NewMixBase64(passwdOutward)

	// Test simple strings
	testStrings := []string{"test123", "hello_world", "file.mp4"}
	for _, testStr := range testStrings {
		encoded := mix64.Encode(testStr)
		decoded, err := mix64.Decode(encoded)
		if err != nil {
			t.Errorf("MixBase64 decode error for %q: %v", testStr, err)
		}
		if string(decoded) != testStr {
			t.Errorf("MixBase64 roundtrip failed: got %s, want %s", string(decoded), testStr)
		}
	}
}

// TestCRC6Compat tests CRC6 checksum.
func TestCRC6Compat(t *testing.T) {
	password := "testpass123"
	encType := EncTypeAESCTR
	passwdOutward := GetPasswdOutward(password, encType)

	testData := "testEncodedString" + passwdOutward
	checksum := crc6.Checksum([]byte(testData))
	checkChar := MixBase64GetSourceChar(int(checksum))

	// Verify range
	if checksum > 63 {
		t.Errorf("CRC6 checksum out of range: %d > 63", checksum)
	}
	_ = checkChar // just ensure it doesn't panic
}

// TestConvertRealNameBehavior tests ConvertRealName behavior:
// always encrypts (unless orig_ prefix present).
func TestConvertRealNameBehavior(t *testing.T) {
	password := "testpass123"
	encType := EncTypeAESCTR

	// Generate expected cipher at runtime
	plainName := "sample-video.mp4"
	expectedCipher := EncodeName(password, encType, plainName) + ".mp4"

	testCases := []struct {
		name           string
		inputPath      string
		expectedOutput string // expected output filename, or "!ENCRYPTED!" for any encrypted result
		description    string
	}{
		{
			name:           "plain filename gets encrypted",
			inputPath:      "/storage/encrypt/sample-video.mp4",
			expectedOutput: expectedCipher,
			description:    "plain filename should be encrypted",
		},
		{
			name:           "orig prefix stripped",
			inputPath:      "/storage/encrypt/orig_test.mp4",
			expectedOutput: "test.mp4",
			description:    "orig_ prefix filename should have prefix removed",
		},
		{
			name:           "encrypted-looking filename still gets encrypted",
			inputPath:      "/storage/encrypt/" + expectedCipher,
			expectedOutput: "!ENCRYPTED!",
			description:    "even if filename looks encrypted, it should be encrypted again",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ConvertRealName(password, encType, tc.inputPath)

			if tc.expectedOutput == "!ENCRYPTED!" {
				inputFileName := path.Base(tc.inputPath)
				if result == inputFileName {
					t.Errorf("ConvertRealName failed! Filename was not encrypted!\n  Input: %s\n  Got: %s (same as input)\n  Description: %s",
						tc.inputPath, result, tc.description)
				}
			} else if result != tc.expectedOutput {
				t.Errorf("ConvertRealName failed!\n  Input: %s\n  Expected: %s\n  Got: %s\n  Description: %s",
					tc.inputPath, tc.expectedOutput, result, tc.description)
			}
		})
	}
}

func TestStripExternalSuffixVariants(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantStripped string
		wantSuffix   string
	}{
		{
			name:         "space parenthesized suffix",
			input:        "video (1)",
			wantStripped: "video",
			wantSuffix:   " (1)",
		},
		{
			name:         "parenthesized suffix without space",
			input:        "video(1)",
			wantStripped: "video",
			wantSuffix:   "(1)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotSuffix := stripExternalSuffix(tc.input)
			if gotName != tc.wantStripped || gotSuffix != tc.wantSuffix {
				t.Fatalf("stripExternalSuffix(%q) = (%q, %q), want (%q, %q)", tc.input, gotName, gotSuffix, tc.wantStripped, tc.wantSuffix)
			}
		})
	}
}

func TestConvertShowNameWithSuffixCompat(t *testing.T) {
	password := "testpass"
	encType := EncTypeAESCTR
	plain := "movie.mp4"

	encrypted := ConvertRealNameWithSuffix(password, encType, plain, ".bin")
	if path.Ext(encrypted) != ".bin" {
		t.Fatalf("encrypted ext should be .bin, got %q", path.Ext(encrypted))
	}

	withDup := strings.TrimSuffix(encrypted, ".bin") + "(1).bin"
	show := ConvertShowNameWithSuffix(password, encType, withDup, ".bin")
	if show != "movie{__esuffix__(1)}.mp4" {
		t.Fatalf("unexpected show name: got %q", show)
	}

	real := ConvertRealNameWithSuffix(password, encType, show, ".bin")
	if real != withDup {
		t.Fatalf("round-trip with duplicate suffix failed: got %q, want %q", real, withDup)
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
