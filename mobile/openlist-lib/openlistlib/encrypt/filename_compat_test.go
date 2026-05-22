package encrypt

import (
	"path"
	"strings"
	"testing"
)

// TestFilenameDecryptCompat 测试文件名解密兼容性
// 使用用户提供的真实测试数据
func TestFilenameDecryptCompat(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := EncTypeAESCTR

	testCases := []struct {
		cipherName string // 服务器上的加密文件名（不含扩展名）
		plainName  string // 期望解密后的明文文件名
	}{
		{
			cipherName: "87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y",
			plainName:  "hhd800.com@PPX-024.mp4",
		},
		{
			cipherName: "F6~klZ33OGXyIf03H",
			plainName:  "waaa-458.mp4",
		},
		{
			cipherName: "87kdQg0Y5VOWIUjiGUwG5GMHOZHtage-r",
			plainName:  "hhd800.com@YMDS-195.mp4",
		},
		// 用户提供的谷歌云盘测试用例
		{
			cipherName: "cGlHlVLp5VOWIUjGG3H~5GUbQmRIO7tF5V+AFX--r",
			plainName:  "169bbs.com@SONE-519_[4k].mkv",
		},
	}

	// 先打印 passwdOutward
	passwdOutward := GetPasswdOutward(password, encType)
	t.Logf("Password: %s", password)
	t.Logf("EncType: %s", encType)
	t.Logf("PasswdOutward: %s (len=%d)", passwdOutward, len(passwdOutward))

	for _, tc := range testCases {
		t.Run(tc.cipherName, func(t *testing.T) {
			// 测试解码
			decoded := DecodeName(password, encType, tc.cipherName)
			t.Logf("Cipher: %s", tc.cipherName)
			t.Logf("Expected: %s", tc.plainName)
			t.Logf("Decoded: %s", decoded)

			if decoded != tc.plainName {
				t.Errorf("Decode mismatch!\n  Cipher: %s\n  Expected: %s\n  Got: %s",
					tc.cipherName, tc.plainName, decoded)
			}

			// 如果解码成功，验证编码能否还原
			if decoded != "" {
				encoded := EncodeName(password, encType, decoded)
				t.Logf("Re-encoded: %s", encoded)
				if encoded != tc.cipherName {
					t.Errorf("Encode mismatch!\n  Plain: %s\n  Expected cipher: %s\n  Got: %s",
						decoded, tc.cipherName, encoded)
				}
			}
		})
	}
}

// TestFilenameDecryptWithStringEncType 测试使用字符串 "aesctr" 作为加密类型
// 这模拟了实际配置中可能出现的情况
func TestFilenameDecryptWithStringEncType(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	// 模拟从 JSON 配置读取的字符串值
	encTypeFromConfig := EncryptionType("aesctr")

	testCases := []struct {
		cipherName string
		plainName  string
	}{
		{
			cipherName: "87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y",
			plainName:  "hhd800.com@PPX-024.mp4",
		},
		{
			cipherName: "F6~klZ33OGXyIf03H",
			plainName:  "waaa-458.mp4",
		},
	}

	passwdOutward := GetPasswdOutward(password, encTypeFromConfig)
	t.Logf("EncType from config: %q", encTypeFromConfig)
	t.Logf("PasswdOutward: %s", passwdOutward)

	// 对比使用常量的结果
	passwdOutwardConst := GetPasswdOutward(password, EncTypeAESCTR)
	t.Logf("PasswdOutward (const): %s", passwdOutwardConst)
	t.Logf("Match: %v", passwdOutward == passwdOutwardConst)

	for _, tc := range testCases {
		t.Run(tc.cipherName, func(t *testing.T) {
			decoded := DecodeName(password, encTypeFromConfig, tc.cipherName)
			t.Logf("Cipher: %s", tc.cipherName)
			t.Logf("Expected: %s", tc.plainName)
			t.Logf("Decoded: %s", decoded)

			if decoded != tc.plainName {
				t.Errorf("Decode mismatch with string encType!\n  Cipher: %s\n  Expected: %s\n  Got: %s",
					tc.cipherName, tc.plainName, decoded)
			}
		})
	}
}

// TestFilenameEncryptCompat 测试文件名加密兼容性
func TestFilenameEncryptCompat(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := EncTypeAESCTR

	testCases := []struct {
		plainName  string
		cipherName string
	}{
		{
			plainName:  "hhd800.com@PPX-024.mp4",
			cipherName: "87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y",
		},
		{
			plainName:  "waaa-458.mp4",
			cipherName: "F6~klZ33OGXyIf03H",
		},
		{
			plainName:  "hhd800.com@YMDS-195.mp4",
			cipherName: "87kdQg0Y5VOWIUjiGUwG5GMHOZHtage-r",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.plainName, func(t *testing.T) {
			encoded := EncodeName(password, encType, tc.plainName)
			t.Logf("Plain: %s", tc.plainName)
			t.Logf("Expected cipher: %s", tc.cipherName)
			t.Logf("Encoded: %s", encoded)

			if encoded != tc.cipherName {
				t.Errorf("Encode mismatch!\n  Plain: %s\n  Expected: %s\n  Got: %s",
					tc.plainName, tc.cipherName, encoded)
			}
		})
	}
}

// TestConvertShowNameCompat 测试 ConvertShowName 兼容性
func TestConvertShowNameCompat(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := EncTypeAESCTR

	// 服务器返回的完整文件名（密文+扩展名）
	testCases := []struct {
		serverFileName string // 服务器上的完整文件名
		expectedShow   string // 期望的显示名
	}{
		{
			serverFileName: "87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4",
			expectedShow:   "hhd800.com@PPX-024.mp4",
		},
		{
			serverFileName: "F6~klZ33OGXyIf03H.mp4",
			expectedShow:   "waaa-458.mp4",
		},
		{
			serverFileName: "87kdQg0Y5VOWIUjiGUwG5GMHOZHtage-r.mp4",
			expectedShow:   "hhd800.com@YMDS-195.mp4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.serverFileName, func(t *testing.T) {
			showName := ConvertShowName(password, encType, tc.serverFileName)
			t.Logf("Server file: %s", tc.serverFileName)
			t.Logf("Expected show: %s", tc.expectedShow)
			t.Logf("Got show: %s", showName)

			if showName != tc.expectedShow {
				t.Errorf("ConvertShowName mismatch!\n  Input: %s\n  Expected: %s\n  Got: %s",
					tc.serverFileName, tc.expectedShow, showName)
			}
		})
	}
}

// TestMixBase64Compat 测试 MixBase64 编码解码
func TestMixBase64Compat(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := EncTypeAESCTR
	passwdOutward := GetPasswdOutward(password, encType)

	t.Logf("PasswdOutward: %s", passwdOutward)

	mix64 := NewMixBase64(passwdOutward)

	// 测试简单字符串
	testStr := "test123"
	encoded := mix64.Encode(testStr)
	decoded, err := mix64.Decode(encoded)

	t.Logf("Original: %s", testStr)
	t.Logf("Encoded: %s", encoded)
	t.Logf("Decoded: %s, err: %v", string(decoded), err)

	if string(decoded) != testStr {
		t.Errorf("MixBase64 roundtrip failed: got %s, want %s", string(decoded), testStr)
	}
}

// TestCRC6Compat 测试 CRC6 校验
func TestCRC6Compat(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := EncTypeAESCTR
	passwdOutward := GetPasswdOutward(password, encType)

	// 测试 CRC6 校验
	testData := "testEncodedString" + passwdOutward
	checksum := crc6.Checksum([]byte(testData))
	checkChar := MixBase64GetSourceChar(int(checksum))

	t.Logf("Test data: %s", testData)
	t.Logf("CRC6 checksum: %d", checksum)
	t.Logf("Check char: %c", checkChar)

	// 验证范围
	if checksum > 63 {
		t.Errorf("CRC6 checksum out of range: %d > 63", checksum)
	}
}

// TestConvertRealNameBehavior 测试 ConvertRealName 的行为
// 与 alist-encrypt 一致：总是加密（除非有 orig_ 前缀）
func TestConvertRealNameBehavior(t *testing.T) {
	password := "T5Fo3sQgRzgazbFG@$vv^7s"
	encType := EncTypeAESCTR

	testCases := []struct {
		name           string
		inputPath      string
		expectedOutput string // 期望输出的文件名
		description    string
	}{
		{
			name:           "plain filename gets encrypted",
			inputPath:      "/移动云盘156/encrypt/hhd800.com@PPX-024.mp4",
			expectedOutput: "87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4", // 明文加密后的结果
			description:    "明文文件名应该被加密",
		},
		{
			name:           "orig prefix stripped",
			inputPath:      "/移动云盘156/encrypt/orig_test.mp4",
			expectedOutput: "test.mp4", // orig_ 前缀被移除
			description:    "orig_ 前缀的文件名去掉前缀后返回",
		},
		{
			name:           "encrypted-looking filename still gets encrypted",
			inputPath:      "/移动云盘156/encrypt/87kdQg0Y5VOWIUjeU~Xtcg435V+YO0--y.mp4",
			expectedOutput: "!ENCRYPTED!", // 即使看起来像加密名，也会被加密
			description:    "即使文件名看起来像加密名，也应该被加密（与 alist-encrypt 一致）",
		},
		{
			name:           "waaa filename gets encrypted",
			inputPath:      "/移动云盘156/encrypt/waaa-458.mp4",
			expectedOutput: "F6~klZ33OGXyIf03H.mp4", // 明文加密后的结果
			description:    "waaa-458.mp4 应该被加密为 F6~klZ33OGXyIf03H.mp4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ConvertRealName(password, encType, tc.inputPath)
			t.Logf("Input path: %s", tc.inputPath)
			t.Logf("Expected: %s", tc.expectedOutput)
			t.Logf("Got: %s", result)
			t.Logf("Description: %s", tc.description)

			if tc.expectedOutput == "!ENCRYPTED!" {
				// 特殊情况：只验证结果不是原文件名
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
