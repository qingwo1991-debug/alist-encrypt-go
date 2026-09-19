package encryption

import (
	"bytes"
	"io"
	"testing"
)

func v3StreamTestContainer(t *testing.T, plain []byte, chunkSize int64, password string) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := NewV3Writer(&out, password, chunkSize)
	if err != nil {
		t.Fatalf("NewV3Writer: %v", err)
	}
	if len(plain) > 0 {
		if _, err := w.Write(plain); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.Bytes()
}

func TestV3StreamEmpty(t *testing.T) {
	container := v3StreamTestContainer(t, nil, 1024, "pw-empty")
	// header + trailer only
	if int64(len(container)) != V3HeaderSize+v3TrailerLen {
		t.Fatalf("empty container size %d", len(container))
	}
	plain, err := ReadTrailerV3(bytes.NewReader(container), int64(len(container)))
	if err != nil || plain != 0 {
		t.Fatalf("trailer: %d %v", plain, err)
	}
	c, err := OpenV3Container(bytes.NewReader(container), int64(len(container)), "secret-empty")
	if err != nil {
		t.Fatalf("OpenV3Container: %v", err)
	}
	if c.PlainSize != 0 {
		t.Fatalf("plain size %d", c.PlainSize)
	}
	got, err := io.ReadAll(c.Sequential())
	if err != nil {
		t.Fatalf("sequential read: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(got))
	}
}

func TestV3StreamRoundTrip(t *testing.T) {
	cs := int64(4096)
	sizes := []int{0, 1, int(cs - 1), int(cs), int(cs + 1), int(cs*2 + 17), int(cs*3 + cs/2)}
	for _, sz := range sizes {
		plain := make([]byte, sz)
		for i := range plain {
			plain[i] = byte((i*13 + 3) & 0xff)
		}
		container := v3StreamTestContainer(t, plain, cs, "pw-stream")
		c, err := OpenV3Container(bytes.NewReader(container), int64(len(container)), "pw-stream")
		if err != nil {
			t.Fatalf("size %d open: %v", sz, err)
		}
		seq, err := io.ReadAll(c.Sequential())
		if err != nil {
			t.Fatalf("size %d sequential: %v", sz, err)
		}
		if !bytes.Equal(seq, plain) {
			t.Fatalf("size %d sequential mismatch", sz)
		}
		// random access: read whole range except first/last few bytes via ReadAt
		if sz > 2 {
			mid := make([]byte, sz-2)
			n, err := c.ReadAt(mid, 1)
			if err != nil { // may return n,nil; io.EOF allowed
				if n != len(mid) {
					t.Fatalf("size %d readAt err after %d: %v", sz, n, err)
				}
			}
			if !bytes.Equal(mid, plain[1:1+len(mid)]) {
				t.Fatalf("size %d random-access mismatch", sz)
			}
		}
	}
}

func TestV3StreamReadAtChunkBoundary(t *testing.T) {
	cs := int64(1024)
	plain := make([]byte, cs*3+111)
	for i := range plain {
		plain[i] = byte(i & 0xff)
	}
	container := v3StreamTestContainer(t, plain, cs, "pw")
	c, err := OpenV3Container(bytes.NewReader(container), int64(len(container)), "pw")
	if err != nil {
		t.Fatal(err)
	}
	// a short read that straddles the chunk-1→chunk-2 boundary
	start := int64(cs - 4)
	n := 8
	got := make([]byte, n)
	if _, err := c.ReadAt(got, start); err != nil && err != io.EOF {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, plain[start:start+int64(n)]) {
		t.Fatalf("straddle mismatch: %x vs %x", got, plain[start:start+int64(n)])
	}
	// EOF beyond container
	end := make([]byte, 64)
	if _, err := c.ReadAt(end, int64(len(plain))-2); err == nil {
		t.Fatal("expected error reading past end")
	}
}

func TestV3StreamWrongPassword(t *testing.T) {
	container := v3StreamTestContainer(t, []byte("some data to protect"), 1024, "right-pw")
	c, err := OpenV3Container(bytes.NewReader(container), int64(len(container)), "wrong-pw")
	if err != nil {
		t.Fatalf("open (parameter parse) should succeed: %v", err)
	}
	if _, err := io.ReadAll(c.Sequential()); err == nil {
		t.Fatal("decrypting with a wrong password must fail authentication")
	}
}

func TestV3StreamTamper(t *testing.T) {
	container := v3StreamTestContainer(t, bytes.Repeat([]byte{0x11}, 3000), 1024, "pw")
	// flip one bit in the middle of the second chunk record
	ctr := append([]byte(nil), container...)
	mid := V3HeaderSize + 1024 + 16 + 7
	ctr[mid] ^= 0x01
	c, err := OpenV3Container(bytes.NewReader(ctr), int64(len(ctr)), "pw")
	if err != nil {
		t.Fatalf("open tampered: %v", err)
	}
	if _, err := io.ReadAll(c.Sequential()); err == nil {
		t.Fatal("tampered container decrypted without error")
	}
}

func TestV3StreamHeaderRoundTrip(t *testing.T) {
	container := v3StreamTestContainer(t, []byte("header fields"), 2048, "pw")
	nonce, chunkSize, kdf, ok := ParseV3StreamHeader(container[:V3HeaderSize])
	if !ok || chunkSize != 2048 || kdf != 600000 || len(nonce) != 16 {
		t.Fatalf("parse: ok=%v cs=%d kdf=%d nonce=%d", ok, chunkSize, kdf, len(nonce))
	}
	// V2 magic must not be classified as V3
	hdr := make([]byte, V3HeaderSize)
	copy(hdr, []byte("AECTR2"))
	_, _, _, ok = ParseV3StreamHeader(hdr)
	if ok {
		t.Fatal("v2 magic classified as v3")
	}
}

func TestV3StreamWriterBlankFirst(t *testing.T) {
	// an empty first write must still produce a valid container
	for _, p := range [][]byte{{}, nil} {
		var out bytes.Buffer
		w, err := NewV3Writer(&out, "pw", 128)

		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(p); err != nil {
			t.Fatalf("write empty: %v", err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatalf("write after empty: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close after empty: %v", err)
		}
		c, err := OpenV3Container(bytes.NewReader(out.Bytes()), int64(out.Len()), "pw")
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		got, err := io.ReadAll(c.Sequential())
		if err != nil || !bytes.Equal(got, []byte("x")) {
			t.Fatalf("content mismatch: %q %v", got, err)
		}
	}
}
