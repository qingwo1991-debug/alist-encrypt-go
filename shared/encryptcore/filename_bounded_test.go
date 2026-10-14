package encryption

import (
	"path"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBoundEncryptedFilenameRoundTrip(t *testing.T) {
	for _, name := range []string{
		"movie.mp4",
		strings.Repeat("a", 65) + ".mp4", // 69 bytes: exact unchanged budget.
		strings.Repeat("a", 66) + ".mp4",
		strings.Repeat("中文电影", 30) + ".mkv",
		strings.Repeat("🎬🍿", 30) + ".mp4",
		strings.Repeat("long.name.", 30) + "video.mp4",
	} {
		t.Run(name, func(t *testing.T) {
			encoded, display, err := BoundEncryptedFilename("test-password", "aesctr", name, "bin", 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) > 100 || len(encoded) > 97 || !strings.HasSuffix(encoded, ".bin") {
				t.Fatalf("encoded length=%d suffix=%q", len(encoded), encoded)
			}
			if !utf8.ValidString(display) || len(display) > 69 {
				t.Fatalf("invalid bounded UTF-8 display: %q", display)
			}
			decoded := DecodeName("test-password", "aesctr", strings.TrimSuffix(encoded, ".bin"))
			if decoded != display || !strings.HasSuffix(display, path.Ext(name)) {
				t.Fatalf("decoded=%q display=%q original=%q", decoded, display, name)
			}
			if len(name) <= 69 && (display != name || encoded != EncodeName("test-password", "aesctr", name)+".bin") {
				t.Fatal("within-budget name changed legacy encoding")
			}
			again, sameDisplay, err := BoundEncryptedFilename("test-password", "aesctr", name, ".bin", 100)
			if err != nil || again != encoded || sameDisplay != display {
				t.Fatal("bounded encoding is not deterministic")
			}
		})
	}
}

func TestBoundEncryptedFilenameDistinctOriginalsAndSuffixes(t *testing.T) {
	prefix := strings.Repeat("相同前缀", 40)
	a, displayA, err := BoundEncryptedFilename("password", "aesctr", prefix+"A.mp4", ".bin", 100)
	if err != nil {
		t.Fatal(err)
	}
	b, displayB, err := BoundEncryptedFilename("password", "aesctr", prefix+"B.mp4", ".bin", 100)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || displayA == displayB {
		t.Fatal("different tails produced the same bounded name")
	}
	for _, suffix := range []string{"", ".mp4", "encrypted", " .bin "} {
		encoded, display, err := BoundEncryptedFilename("password", "aesctr", prefix+".mp4", suffix, 100)
		if err != nil || len(encoded) > 100 {
			t.Fatalf("suffix=%q length=%d err=%v", suffix, len(encoded), err)
		}
		if DecodeName("password", "aesctr", strings.TrimSuffix(encoded, NormalizeEncSuffix(suffix))) != display {
			t.Fatalf("suffix=%q: invalid CRC or round trip", suffix)
		}
	}
}

func TestBoundEncryptedFilenameRejectsUnsafeAndUnrepresentable(t *testing.T) {
	for _, tc := range []struct {
		name, suffix string
		limit        int
	}{
		{"", ".bin", 100},
		{".", ".bin", 100},
		{"..", ".bin", 100},
		{"../video.mp4", ".bin", 100},
		{"dir\\video.mp4", ".bin", 100},
		{"video\x00.mp4", ".bin", 100},
		{"video\n.mp4", ".bin", 100},
		{string([]byte{0xff}), ".bin", 100},
		{"video.mp4", "../bin", 100},
		{"video.mp4", ".二进制", 100},
		{"video.mp4", ".bin\n", 100},
		{"video.mp4", ".bin", 0},
		{"video.mp4", ".bin", -1},
		{"video.mp4", ".bin", 8},
		{"verylongname.mp4", ".bin", 12},
		{"video." + strings.Repeat("x", 70), ".bin", 100},
		{"video.mp4", "." + strings.Repeat("x", 100), 100},
	} {
		encoded, display, err := BoundEncryptedFilename("private-password", "aesctr", tc.name, tc.suffix, tc.limit)
		if err == nil || encoded != "" || display != "" {
			t.Errorf("name=%q suffix=%q limit=%d: got %q %q err=%v", tc.name, tc.suffix, tc.limit, encoded, display, err)
		}
		if err != nil && strings.Contains(err.Error(), "private-password") {
			t.Fatal("error exposed password")
		}
	}
}
