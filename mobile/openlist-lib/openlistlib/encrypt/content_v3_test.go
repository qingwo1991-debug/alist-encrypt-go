package encrypt

import (
	"bytes"
	"encoding/binary"
	"errors"
	core "github.com/alist-encrypt-go/shared/encryptcore"
	"testing"
)

func TestMobileV3HeaderGeometry(t *testing.T) {
	nonce := bytes.Repeat([]byte{1}, 16)
	for _, plain := range []int64{0, 1, 16, 17} {
		header, err := core.NewV3Header(plain, nonce, 16, 0)
		if err != nil {
			t.Fatal(err)
		}
		size := core.V3CiphertextSize(plain, 16)
		meta, ok, err := ParseContentHeader(EncTypeAESCTR, header, size)
		if !ok || err != nil || !meta.IsV3() || meta.PlainSize != plain || meta.ChunkSize != 16 {
			t.Fatalf("meta=%+v ok=%t err=%v", meta, ok, err)
		}
		if meta.V3CoreMeta().EncType != core.EncType("aesctr") {
			t.Fatal("AES mapping")
		}
		if err = ValidateV3ContentMeta(meta); err != nil {
			t.Fatal(err)
		}
		if plain > 0 {
			if _, _, err = ParseContentHeader(EncTypeAESCTR, header, size+16); err == nil {
				t.Fatal("fixed accepted trailer")
			}
		}
	}
	if ContentHeaderSize() != 32 || V3HeaderSize != 48 {
		t.Fatal("V2 prefix changed")
	}
}

func TestMobileV3MalformedNeverLegacy(t *testing.T) {
	header, _ := core.NewV3Header(17, make([]byte, 16), 16, 0)
	for _, n := range []int{6, 7, 16, 32, 47} {
		_, recognized, err := ParseContentHeader(EncTypeAESCTR, header[:n], 112)
		if !recognized || err == nil {
			t.Fatalf("truncated %d fell back", n)
		}
	}
	for _, tc := range []struct {
		name     string
		mutate   func([]byte)
		resource bool
	}{
		{"version", func(b []byte) { b[6] = 4 }, false},
		{"reserved", func(b []byte) { b[7] = 1 }, false},
		{"reserved_tail", func(b []byte) { b[47] = 1 }, false},
		{"tag", func(b []byte) { binary.BigEndian.PutUint32(b[36:40], 15) }, false},
		{"zero_chunk", func(b []byte) { binary.BigEndian.PutUint32(b[32:36], 0) }, false},
		{"core_chunk_repair", func(b []byte) { binary.BigEndian.PutUint32(b[32:36], 1<<31) }, false},
		{"mobile_chunk_cap", func(b []byte) { binary.BigEndian.PutUint32(b[32:36], MaxMobileV3ChunkSize+1) }, true},
		{"kdf_cap", func(b []byte) { binary.BigEndian.PutUint32(b[40:44], MaxMobileV3KDFIterations+1) }, true},
		{"negative_plain", func(b []byte) { binary.BigEndian.PutUint64(b[24:32], 1<<63) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(header)
			tc.mutate(b)
			_, ok, err := ParseContentHeader(EncTypeAESCTR, b, 112)
			if !ok || err == nil {
				t.Fatal("malformed V3 fell back")
			}
			if errors.Is(err, ErrV3ResourceLimit) != tc.resource {
				t.Fatalf("error class=%v", err)
			}
		})
	}
	meta := ContentMeta{Version: 3, HeaderLen: 48, NonceField: make([]byte, 16), PlainSize: 1 << 62, CiphertextSize: 1 << 62, ChunkSize: 1}
	if ValidateV3ContentMeta(meta) == nil {
		t.Fatal("nonce index overflow accepted")
	}
	meta.PlainSize = 1
	meta.CiphertextSize = 65
	meta.NonceField = nil
	if ValidateV3ContentMeta(meta) == nil {
		t.Fatal("invalid nonce accepted")
	}
}

func TestMobileV3StreamingTrailerGeometry(t *testing.T) {
	header, _ := core.NewV3Header(0, make([]byte, 16), 16, 0)
	for _, plain := range []int64{0, 1, 16, 17} {
		size := core.V3CiphertextSize(plain, 16) + 16
		meta, ok, err := ParseV3ContentHeader(EncTypeAESCTR, header, size)
		if !ok || err != nil {
			t.Fatal(err)
		}
		tail := make([]byte, 16)
		copy(tail, "V3E4")
		binary.BigEndian.PutUint64(tail[8:], uint64(plain))
		completed, err := CompleteV3ContentMeta(meta, tail)
		if err != nil || completed.PlainSize != plain {
			t.Fatalf("meta=%+v err=%v", completed, err)
		}
		for _, kind := range []string{"magic", "reserved", "negative", "wrong_count", "short"} {
			b := bytes.Clone(tail)
			switch kind {
			case "magic":
				b[0] = 'X'
			case "reserved":
				b[4] = 1
			case "negative":
				binary.BigEndian.PutUint64(b[8:], 1<<63)
			case "wrong_count":
				binary.BigEndian.PutUint64(b[8:], uint64(plain+32))
			case "short":
				b = b[:15]
			}
			if _, err = CompleteV3ContentMeta(meta, b); err == nil {
				t.Fatalf("accepted %s", kind)
			}
		}
	}
}

func TestMobileV3DoesNotChangeLegacyHeaderParsing(t *testing.T) {
	for _, algorithm := range []EncryptionType{EncTypeAESCTR, EncTypeRC4, EncTypeChaCha20} {
		header, err := BuildV2Header(algorithm, 123, make([]byte, 16))
		if err != nil {
			t.Fatal(err)
		}
		meta, ok, err := ParseContentHeader(algorithm, header, 155)
		if err != nil || !ok || !meta.IsV2() || meta.PlainSize != 123 {
			t.Fatalf("V2 %s meta=%+v err=%v", algorithm, meta, err)
		}
		meta, ok, err = ParseContentHeader(algorithm, []byte("legacy content"), 123)
		if err != nil || ok || meta.Version != ContentVersionV1 {
			t.Fatal("legacy changed")
		}
		if _, err = BuildV2Header(algorithm, 0, make([]byte, 16)); err == nil {
			t.Fatal("V2 empty behavior changed")
		}
	}
}
