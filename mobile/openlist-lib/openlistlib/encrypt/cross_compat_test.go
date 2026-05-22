package encrypt

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// crossCompatVector 是两个项目共享的兼容性测试向量
// 所有向量均从 alist-encrypt-go 的测试中提取，OpenList-Encrypt 必须产出相同结果
type crossCompatVector struct {
	name     string
	password string
	fileSize int64
	encType  EncryptionType
	// 明文（前 32 字节）加密后的期望密文（hex）
	// 由 alist-encrypt-go 生成，OpenList-Encrypt 必须匹配
	plainHex    string
	expectedHex string
}

var crossCompatVectors = []crossCompatVector{
	{
		name:        "AES-CTR password=test123 fileSize=123456",
		password:    "test123",
		fileSize:    123456,
		encType:     EncTypeAESCTR,
		plainHex:    "00000000000000000000000000000000",
		expectedHex: "74f1cb0b449970741fae9823e3ce8f16",
	},
	{
		name:        "RC4-MD5 password=test123 fileSize=123456",
		password:    "test123",
		fileSize:    123456,
		encType:     EncTypeRC4,
		plainHex:    "00000000000000000000000000000000",
		expectedHex: "92b15d9731d8e2e82e713be356660ba4",
	},
	{
		name:        "ChaCha20 password=test123 fileSize=123456",
		password:    "test123",
		fileSize:    123456,
		encType:     EncTypeChaCha20,
		plainHex:    "00000000000000000000000000000000",
		expectedHex: "13f71f204f2c1ea9d87eb911c939df9a",
	},
}

// TestCrossProjectCompatibility 使用共享向量验证与 alist-encrypt-go 的密文一致性
func TestCrossProjectCompatibility(t *testing.T) {
	for _, v := range crossCompatVectors {
		t.Run(v.name, func(t *testing.T) {
			if v.expectedHex == "" || (len(v.expectedHex) > 10 && v.expectedHex[:11] == "PLACEHOLDER") {
				t.Skip("expectedHex not yet filled in — run alist-encrypt-go to generate vectors")
			}

			plain, err := hex.DecodeString(v.plainHex)
			if err != nil {
				t.Fatalf("bad plainHex: %v", err)
			}
			expected, err := hex.DecodeString(v.expectedHex)
			if err != nil {
				t.Fatalf("bad expectedHex: %v", err)
			}

			enc, err := NewFlowEncryptor(v.password, v.encType, v.fileSize)
			if err != nil {
				t.Fatalf("NewFlowEncryptor failed: %v", err)
			}

			got, err := enc.Encrypt(plain)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if !bytes.Equal(got, expected) {
				t.Errorf("ciphertext mismatch:\n  got:  %s\n  want: %s",
					hex.EncodeToString(got), hex.EncodeToString(expected))
			}
		})
	}
}
