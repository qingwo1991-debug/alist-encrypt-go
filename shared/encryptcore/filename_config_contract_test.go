package encryption

import (
	"strings"
	"testing"
)

func TestBoundedFilenameUsesConfiguredCipherAndSuffix(t *testing.T) {
	for _, algorithm := range []string{"aesctr", "rc4md5", "chacha20"} {
		for _, suffix := range []string{".bin", ".private", ".mp4"} {
			t.Run(algorithm+suffix, func(t *testing.T) {
				original := strings.Repeat("超长原始名称", 40) + ".mkv"
				encoded, short, err := BoundEncryptedFilename("synthetic-configured-password", algorithm, original, suffix, 100)
				if err != nil {
					t.Fatal(err)
				}
				if len(encoded) > 100 || !strings.HasSuffix(encoded, suffix) {
					t.Fatalf("configured limit/suffix ignored: %q", encoded)
				}
				if encoded == original || encoded == short+suffix || strings.Contains(encoded, "超长") {
					t.Fatal("plaintext name used as cloud filename")
				}
				if got := DecodeName("synthetic-configured-password", algorithm, strings.TrimSuffix(encoded, suffix)); got != short {
					t.Fatalf("configured cipher roundtrip failed: %q", got)
				}
				if !strings.HasSuffix(short, ".mkv") {
					t.Fatal("original extension lost inside encrypted name")
				}
			})
		}
	}
}
