package encryption

import (
	"bytes"
	"io"
	"testing"
)

// buildV3ContainerPlain writes plain into a V3 container and returns the
// container bytes plus a cipher handle over the same key/nonce/chunk size.
func buildV3ContainerPlain(t *testing.T, password string, chunkSize int64, plain []byte) ([]byte, *V3ChunkCipher) {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewV3Writer(&buf, password, chunkSize)
	if err != nil {
		t.Fatalf("NewV3Writer: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	nonce := w.NonceField()
	key := DeriveV3Key(password, nonce, 0)
	cipher, err := NewV3ChunkCipher(key, nonce)
	if err != nil {
		t.Fatalf("NewV3ChunkCipher: %v", err)
	}
	return buf.Bytes(), cipher
}

// samplePlain clamps [start,end) to the plaintext bounds.
func samplePlain(plain []byte, start, end int64) []byte {
	if start < 0 {
		start = 0
	}
	if end > int64(len(plain)) {
		end = int64(len(plain))
	}
	if end <= start {
		return nil
	}
	return plain[start:end]
}

func TestV3StreamReaderWithinAndCrossChunk(t *testing.T) {
	const cs = int64(64)
	data := bytes.Repeat([]byte{0x5a, 0xa5, 0x11}, 96) // 288 bytes -> 5 records
	container, cipher := buildV3ContainerPlain(t, "secret-v3", cs, data)

	// A chunk-window is a contiguous ciphertext span starting at the first
	// byte of record `firstChunk` (the proxy fetches this for plain target
	// [firstChunk*cs, ...)).
	cases := []struct {
		name       string
		firstChunk int64
		srcOffset  int64 // ciphertext offset of the window's first record
		skip       int64
		limit      int64
		want       []byte
	}{
		{"within-chunk", 1, V3HeaderSize + 1*(cs+16), 7, 20, samplePlain(data, cs+7, cs+27)},
		{"cross-chunk", 1, V3HeaderSize + 1*(cs+16), 1, 2*cs + 5, samplePlain(data, cs+1, cs+1+2*cs+5)},
		{"from-very-start", 0, V3HeaderSize, 0, cs + 7, samplePlain(data, 0, cs+7)},
		{"whole-with-to-end", 0, V3HeaderSize, 0, int64(len(data)), samplePlain(data, 0, int64(len(data)))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewV3StreamReader(bytes.NewReader(container[tc.srcOffset:]), cipher, cs, tc.firstChunk, tc.skip, tc.limit)
			if err != nil {
				t.Fatalf("NewV3StreamReader: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("mismatch: got %d bytes, want %d (got head %x, want head %x)",
					len(got), len(tc.want), first8(got), first8(tc.want))
			}
		})
	}
}

func TestV3StreamReaderWrongPasswordFails(t *testing.T) {
	const cs = int64(64)
	data := bytes.Repeat([]byte{0x22}, int(3*cs+5))
	container, _ := buildV3ContainerPlain(t, "pw-a", cs, data)

	badKey := DeriveV3Key("pw-b", make([]byte, 16), 0)
	badCipher, err := NewV3ChunkCipher(badKey, make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewV3StreamReader(bytes.NewReader(container[V3HeaderSize:]), badCipher, cs, 0, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("wrong password must fail stream decryption")
	}
}

func TestV3StreamReaderTruncatedRecordFails(t *testing.T) {
	const cs = int64(64)
	data := bytes.Repeat([]byte{0x42}, int(2*cs+3))
	container, cipher := buildV3ContainerPlain(t, "p-v3", cs, data)

	cut := container[:len(container)-20] // end inside a record
	r, err := NewV3StreamReader(bytes.NewReader(cut[V3HeaderSize:]), cipher, cs, 0, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("truncated stream must fail")
	}
}

func first8(b []byte) []byte {
	if len(b) > 8 {
		b = b[:8]
	}
	return b
}
