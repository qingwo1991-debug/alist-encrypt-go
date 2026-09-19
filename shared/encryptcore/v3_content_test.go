package encryption

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestV3ContentEncryptDecrypt(t *testing.T) {
	const password = "roundtrip-pw"
	cases := []struct {
		name string
		arg  int64
		data []byte
	}{
		{"empty", 0, nil},
		{"tiny", 1024, []byte("hello v3 content stream")},
		{"chunk-even", 64, bytes.Repeat([]byte{0xab}, 64)},
		{"chunk-odd-tail", 64, bytes.Repeat([]byte{0xcd}, 64+17)},
		{"multi-chunk", 0, bytes.Repeat([]byte{0xef}, 3*4*1024+99)}, // default 16MiB chunk still fine
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := NewV3ContentEncryptor(tc.arg)
			if err != nil {
				t.Fatalf("NewV3ContentEncryptor: %v", err)
			}
			var container bytes.Buffer
			src := bytes.NewReader(tc.data)
			rdr, err := enc.EncryptReader(password, src)
			if err != nil {
				t.Fatalf("EncryptReader: %v", err)
			}
			if _, err := io.Copy(&container, rdr); err != nil {
				t.Fatalf("collect container: %v", err)
			}

			if !HasV3Magic(container.Bytes()) {
				t.Fatal("container does not start with V3 magic")
			}

			// decrypt via io.ReadSeeker (bytes.Reader has ReadAt+Seek)
			br := bytes.NewReader(container.Bytes())
			dec, err := NewV3ReadSeekerDecoder(br, int64(container.Len()), password)
			if err != nil {
				t.Fatalf("NewV3ReadSeekerDecoder: %v", err)
			}
			got, err := io.ReadAll(dec)
			if err != nil {
				t.Fatalf("decrypt read: %v", err)
			}
			if !bytes.Equal(got, tc.data) {
				t.Fatalf("round-trip mismatch: got %d bytes want %d", len(got), len(tc.data))
			}
		})
	}
}

func TestV3ContentWrongPassword(t *testing.T) {
	enc, _ := NewV3ContentEncryptor(1024)
	rdr, _ := enc.EncryptReader("correct", strings.NewReader("protect me"))
	var b bytes.Buffer
	if _, err := io.Copy(&b, rdr); err != nil {
		t.Fatal(err)
	}
	dec, err := NewV3ReadSeekerDecoder(bytes.NewReader(b.Bytes()), int64(b.Len()), "wrong")
	if err != nil {
		t.Fatalf("decode wrong pw should parse, got: %v", err)
	}
	if _, err := io.ReadAll(dec); err == nil {
		t.Fatal("wrong password should fail authentication")
	}
}

func TestV3ContentMagicDetection(t *testing.T) {
	cases := []struct {
		header []byte
		want   bool
	}{
		{[]byte("V3GCM3rest"), true},
		{[]byte("V3GCM3"), true},
		{[]byte("V3G"), false}, // too short
		{[]byte("AECTR2...."), false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := HasV3Magic(tc.header); got != tc.want {
			t.Fatalf("HasV3Magic(%q)=%v want %v", tc.header, got, tc.want)
		}
	}
}
