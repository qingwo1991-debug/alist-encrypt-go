package encryption

import (
	"crypto/rand"
	"testing"
)

// BenchmarkCipherEncrypt benchmarks encryption throughput
func BenchmarkCipherEncrypt(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
	}

	encTypes := []EncType{EncTypeAESCTR, EncTypeRC4MD5, EncTypeChaCha20}

	for _, size := range sizes {
		for _, encType := range encTypes {
			b.Run(string(encType)+"/"+size.name, func(b *testing.B) {
				data := make([]byte, size.size)
				rand.Read(data)

				cipher, _ := NewCipher(encType, "benchmarkpassword", int64(size.size))

				b.SetBytes(int64(size.size))
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					cipher.Encrypt(data)
				}
			})
		}
	}
}

// BenchmarkCipherSetPosition benchmarks seek performance
func BenchmarkCipherSetPosition(b *testing.B) {
	positions := []struct {
		name string
		pos  int64
	}{
		{"0", 0},
		{"1KB", 1024},
		{"1MB", 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	encTypes := []EncType{EncTypeAESCTR, EncTypeRC4MD5, EncTypeChaCha20}
	fileSize := int64(1024 * 1024 * 1024) // 1GB file

	for _, pos := range positions {
		for _, encType := range encTypes {
			b.Run(string(encType)+"/"+pos.name, func(b *testing.B) {
				cipher, _ := NewCipher(encType, "benchmarkpassword", fileSize)

				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					cipher.SetPosition(pos.pos)
				}
			})
		}
	}
}

// BenchmarkCipherReader benchmarks streaming performance
func BenchmarkCipherReader(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	encTypes := []EncType{EncTypeAESCTR, EncTypeChaCha20}

	for _, size := range sizes {
		for _, encType := range encTypes {
			b.Run(string(encType)+"/"+size.name, func(b *testing.B) {
				data := make([]byte, size.size)
				rand.Read(data)

				b.SetBytes(int64(size.size))
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					cipher, _ := NewCipher(encType, "benchmarkpassword", int64(size.size))
					buf := make([]byte, size.size)
					copy(buf, data)
					cipher.Decrypt(buf)
				}
			})
		}
	}
}

// BenchmarkMixBase64 benchmarks filename encoding
func BenchmarkMixBase64(b *testing.B) {
	password := "testpassword"
	passwdOutward := GetPasswdOutward(password, "aesctr")
	mix64 := NewMixBase64(passwdOutward)
	data := []byte("test_filename_with_unicode_日本語.mp4")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encoded := mix64.Encode(data)
		mix64.Decode(encoded)
	}
}
