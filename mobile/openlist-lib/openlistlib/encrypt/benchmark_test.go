package encrypt

import (
	"crypto/rand"
	"testing"
)

// BenchmarkEncryptors 测试各加密算法在不同数据大小下的吞吐量
func BenchmarkEncryptors(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	encTypes := []EncryptionType{EncTypeAESCTR, EncTypeRC4, EncTypeChaCha20}

	for _, size := range sizes {
		for _, encType := range encTypes {
			b.Run(string(encType)+"/"+size.name, func(b *testing.B) {
				data := make([]byte, size.size)
				rand.Read(data) //nolint:errcheck

				enc, err := NewFlowEncryptor("benchmarkpassword", encType, int64(size.size))
				if err != nil {
					b.Fatalf("NewFlowEncryptor failed: %v", err)
				}

				b.SetBytes(int64(size.size))
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					enc.Encrypt(data) //nolint:errcheck
				}
			})
		}
	}
}

// BenchmarkSetPosition 测试 seek 性能（对视频拖动播放至关重要）
func BenchmarkSetPosition(b *testing.B) {
	positions := []struct {
		name string
		pos  int64
	}{
		{"0", 0},
		{"1MB", 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	encTypes := []EncryptionType{EncTypeAESCTR, EncTypeChaCha20}
	fileSize := int64(1024 * 1024 * 1024) // 1GB

	for _, pos := range positions {
		for _, encType := range encTypes {
			b.Run(string(encType)+"/"+pos.name, func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					enc, err := NewFlowEncryptor("benchmarkpassword", encType, fileSize)
					if err != nil {
						b.Fatalf("NewFlowEncryptor failed: %v", err)
					}
					enc.SetPosition(pos.pos) //nolint:errcheck
				}
			})
		}
	}
}

// BenchmarkMixBase64 测试文件名编解码性能
func BenchmarkMixBase64(b *testing.B) {
	password := "testpassword"
	passwdOutward := GetPasswdOutward(password, EncTypeAESCTR)
	mix64 := NewMixBase64(passwdOutward)
	filename := "test_filename_with_unicode_日本語.mp4"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded := mix64.Encode(filename)
		mix64.Decode(encoded) //nolint:errcheck
	}
}
