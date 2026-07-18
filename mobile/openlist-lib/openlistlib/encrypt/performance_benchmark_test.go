package encrypt

import (
	"bytes"
	"fmt"
	"testing"
)

var (
	mobilePlaybackBenchmarkCipher FlowEncryptor
	mobilePlaybackBenchmarkMeta   ContentMeta
	mobilePlaybackBenchmarkStart  int64
)

// BenchmarkMobilePlaybackV2KeySetup separates first-use PBKDF2 latency from
// the cached path used when a password has already played at least one file.
func BenchmarkMobilePlaybackV2KeySetup(b *testing.B) {
	nonce := bytes.Repeat([]byte{0x5a}, 16)
	const plainSize = int64(4 * 1024 * 1024 * 1024)

	b.Run("cold_unique_password", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cipherImpl, err := NewCipherV2(
				EncTypeAESCTR,
				fmt.Sprintf("mobile-playback-benchmark-cold-%d", i),
				plainSize,
				nonce,
			)
			if err != nil {
				b.Fatal(err)
			}
			mobilePlaybackBenchmarkCipher = cipherImpl
		}
	})

	b.Run("hot_cached_password", func(b *testing.B) {
		const password = "mobile-playback-benchmark-hot"
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
			mobilePlaybackBenchmarkCipher = cipherImpl
		}
	})
}

func BenchmarkMobilePlaybackV2HeaderParse(b *testing.B) {
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
		mobilePlaybackBenchmarkMeta = meta
	}
}

func BenchmarkMobilePlaybackRangeParse(b *testing.B) {
	const fileSize = int64(4 * 1024 * 1024 * 1024)
	for _, tc := range []struct {
		name   string
		header string
	}{
		{name: "first_frame", header: "bytes=0-2097151"},
		{name: "bounded_seek", header: "bytes=3221225472-3222274047"},
		{name: "open_ended_seek", header: "bytes=3221225472-"},
		{name: "suffix_probe", header: "bytes=-1048576"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				start, _, hasRange, err := parseSingleRange(tc.header, fileSize)
				if err != nil || !hasRange {
					b.Fatalf("parseSingleRange hasRange=%v err=%v", hasRange, err)
				}
				mobilePlaybackBenchmarkStart = start
			}
		})
	}
}

func BenchmarkMobilePlaybackAESCTRSeek(b *testing.B) {
	nonce := bytes.Repeat([]byte{0x31}, 16)
	const (
		password  = "mobile-playback-benchmark-seek"
		plainSize = int64(4 * 1024 * 1024 * 1024)
		position  = int64(3*1024*1024*1024 + 7)
	)

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
			mobilePlaybackBenchmarkCipher = cipherImpl
		}
	})
}

func BenchmarkMobilePlaybackDecryptThroughput(b *testing.B) {
	const plainSize = int64(4 * 1024 * 1024 * 1024)
	nonce := bytes.Repeat([]byte{0x19}, 16)

	for _, size := range []int{64 * 1024, 1024 * 1024} {
		b.Run(fmt.Sprintf("aesctr_v2_%dKiB", size/1024), func(b *testing.B) {
			cipherImpl, err := NewCipherV2(EncTypeAESCTR, "mobile-playback-benchmark-throughput", plainSize, nonce)
			if err != nil {
				b.Fatal(err)
			}
			inplace, ok := cipherImpl.(InplaceFlowEncryptor)
			if !ok {
				b.Fatal("AES-CTR V2 does not implement in-place decryption")
			}
			buf := bytes.Repeat([]byte{0xa5}, size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := inplace.DecryptInplace(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
