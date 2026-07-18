package encryption

import (
	"bytes"
	"fmt"
	"testing"
)

var (
	playbackBenchmarkCipher Cipher
	playbackBenchmarkMeta   ContentMeta
	playbackBenchmarkOK     bool
)

// BenchmarkPlaybackV2KeySetup separates the expensive first derivation of a
// V2 key from the normal cached constructor path used by subsequent playback
// and seek requests. It is intentionally network-free and uses a fixed nonce.
func BenchmarkPlaybackV2KeySetup(b *testing.B) {
	nonce := bytes.Repeat([]byte{0x5a}, 16)
	const plainSize = int64(4 * 1024 * 1024 * 1024)

	b.Run("cold_unique_password", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cipherImpl, err := NewCipherV2(
				EncTypeAESCTR,
				fmt.Sprintf("playback-benchmark-cold-%d", i),
				plainSize,
				nonce,
			)
			if err != nil {
				b.Fatal(err)
			}
			playbackBenchmarkCipher = cipherImpl
		}
	})

	b.Run("hot_cached_password", func(b *testing.B) {
		const password = "playback-benchmark-hot"
		if _, err := NewCipherV2(EncTypeAESCTR, password, plainSize, nonce); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cipherImpl, err := NewCipherV2(EncTypeAESCTR, password, plainSize, nonce)
			if err != nil {
				b.Fatal(err)
			}
			playbackBenchmarkCipher = cipherImpl
		}
	})
}

// BenchmarkPlaybackV2HeaderParse measures the local metadata work after the
// 32-byte prefix has arrived. It excludes all upstream I/O.
func BenchmarkPlaybackV2HeaderParse(b *testing.B) {
	nonce := bytes.Repeat([]byte{0x7c}, 16)
	header, err := BuildV2Header(EncTypeAESCTR, 4*1024*1024*1024, nonce)
	if err != nil {
		b.Fatal(err)
	}
	const ciphertextSize = int64(4*1024*1024*1024 + 32)

	b.ReportAllocs()
	b.SetBytes(int64(len(header)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		meta, ok, parseErr := ParseContentHeader(EncTypeAESCTR, header, ciphertextSize)
		if parseErr != nil || !ok {
			b.Fatalf("ParseContentHeader ok=%v err=%v", ok, parseErr)
		}
		playbackBenchmarkMeta = meta
		playbackBenchmarkOK = ok
	}
}

func BenchmarkPlaybackAESCTRSeek(b *testing.B) {
	nonce := bytes.Repeat([]byte{0x31}, 16)
	const (
		password  = "playback-benchmark-seek"
		plainSize = int64(4 * 1024 * 1024 * 1024)
		position  = int64(3*1024*1024*1024 + 7)
	)

	// Preheat the PBKDF2 cache so this benchmark isolates request setup and seek.
	if _, err := NewCipherV2(EncTypeAESCTR, password, plainSize, nonce); err != nil {
		b.Fatal(err)
	}

	b.Run("reuse_cipher_set_position", func(b *testing.B) {
		cipherImpl, err := NewCipherV2(EncTypeAESCTR, password, plainSize, nonce)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := cipherImpl.SetPosition(position); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("new_request_cached_key", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cipherImpl, err := NewCipherV2(EncTypeAESCTR, password, plainSize, nonce)
			if err != nil {
				b.Fatal(err)
			}
			if err := cipherImpl.SetPosition(position); err != nil {
				b.Fatal(err)
			}
			playbackBenchmarkCipher = cipherImpl
		}
	})
}

func BenchmarkPlaybackDecryptThroughput(b *testing.B) {
	const plainSize = int64(4 * 1024 * 1024 * 1024)
	nonce := bytes.Repeat([]byte{0x19}, 16)

	for _, size := range []int{64 * 1024, 1024 * 1024} {
		b.Run(fmt.Sprintf("aesctr_v2_%dKiB", size/1024), func(b *testing.B) {
			cipherImpl, err := NewCipherV2(EncTypeAESCTR, "playback-benchmark-throughput", plainSize, nonce)
			if err != nil {
				b.Fatal(err)
			}
			buf := bytes.Repeat([]byte{0xa5}, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cipherImpl.Decrypt(buf)
			}
		})
	}
}
