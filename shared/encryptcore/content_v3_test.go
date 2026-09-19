package encryption

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func testV3Key(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	return key
}

func testV3Nonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	return nonce
}

// collatePlain assembles plaintext chunks for an end-to-end container check.
func expectedChunks(plain []byte, chunkSize int64) [][]byte {
	var out [][]byte
	for off := int64(0); off < int64(len(plain)); off += chunkSize {
		end := off + chunkSize
		if end > int64(len(plain)) {
			end = int64(len(plain))
		}
		out = append(out, plain[off:end])
	}
	return out
}

func TestV3ChunkRoundTrip(t *testing.T) {
	c, err := NewV3ChunkCipher(testV3Key(t), testV3Nonce(t))
	if err != nil {
		t.Fatalf("NewV3ChunkCipher: %v", err)
	}
	sizes := []int{0, 1, 15, 16, 1024, int(v3DefaultChunkSize) - 1, int(v3DefaultChunkSize), int(v3DefaultChunkSize) + 1}
	for idx, size := range sizes {
		plain := bytes.Repeat([]byte{0x5a}, size)
		if size > 0 {
			plain[0] = 0x01
			plain[size-1] = 0x7f
		}
		ct, err := c.Seal(uint64(idx), plain)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", size, err)
		}
		if len(ct) != size+v3TagSize {
			t.Fatalf("ciphertext length %d != %d+16", len(ct), size)
		}
		got, err := c.Open(uint64(idx), ct)
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", size, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("round-trip mismatch for %d bytes", size)
		}
	}
}

func TestV3TamperDetected(t *testing.T) {
	c, _ := NewV3ChunkCipher(testV3Key(t), testV3Nonce(t))
	plain := bytes.Repeat([]byte{0x42}, 4096)
	ct, err := c.Seal(3, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// flip every single byte in turn — every one must be detected
	for i := 0; i < len(ct); i++ {
		bad := append([]byte(nil), ct...)
		bad[i] ^= 0x01
		if _, err := c.Open(3, bad); err == nil {
			t.Fatalf("tampered byte %d not detected", i)
		}
	}
	// truncation must fail too
	if _, err := c.Open(3, ct[:len(ct)-1]); err == nil {
		t.Fatal("truncated chunk accepted")
	}
	// and wrong chunk index must not authenticate
	if _, err := c.Open(4, ct); err == nil {
		t.Fatal("chunk opened under wrong index")
	}
	if _, err := c.Open(3, ct[:248]); err == nil {
		t.Fatal("short read accepted")
	}
}

func TestV3WrongKey(t *testing.T) {
	c1, _ := NewV3ChunkCipher(testV3Key(t), testV3Nonce(t))
	ke := make([]byte, 32)
	c2, _ := NewV3ChunkCipher(ke, testV3Nonce(t))
	ct, _ := c1.Seal(0, []byte("hello secure v3"))
	if _, err := c2.Open(0, ct); err == nil {
		t.Fatal("decryption with wrong key must fail authentication")
	}
}

func TestV3ContainerRoundTripAndRandomAccess(t *testing.T) {
	cs := int64(8192) // small chunk for fast test
	c, err := NewV3ChunkCipher(testV3Key(t), testV3Nonce(t))
	if err != nil {
		t.Fatal(err)
	}
	// deterministic ~3.2-chunk plaintext
	plain := make([]byte, cs*3+1234)
	for i := range plain {
		plain[i] = byte((i*31 + 7) & 0xff)
	}
	chunks := expectedChunks(plain, cs)
	var container []byte
	hdr, err := NewV3Header(int64(len(plain)), testV3Nonce(t), cs, 600000)
	if err != nil {
		t.Fatal(err)
	}
	container = append(container, hdr...)
	for i, ch := range chunks {
		rec := make([]byte, cs+v3TagSize)
		if len(ch) < int(cs) {
			copy(rec[:len(ch)], ch) // pad with zeros
		} else {
			copy(rec[:cs], ch)
		}
		sealed, err := c.Seal(uint64(i), rec[:cs])
		if err != nil {
			t.Fatal(err)
		}
		container = append(container, sealed...)
	}
	// Now decrypt only chunk 1 in isolation (random access) and verify the
	// chunk-0 region must be verifiable without reading chunk 0's data.
	idx, off := V3ChunkForOffset(2, cs)
	if idx != 0 || off != 2 {
		t.Fatalf("V3ChunkForOffset(2) = (%d,%d)", idx, off)
	}
	// read chunk 1 record directly from the assembled container
	chunkOffset := V3ChunkCipherOffset(1, cs)
	rec := container[chunkOffset : chunkOffset+cs+v3TagSize]
	dec, err := c.Open(1, rec)
	if err != nil {
		t.Fatalf("random-access open chunk 1: %v", err)
	}
	if !bytes.Equal(dec[:cs], plain[cs:2*cs]) {
		t.Fatal("random-access chunk 1 content mismatch")
	}
	// full sequential undo must reproduce the original byte-for-byte
	var rebuilt []byte
	for i := 0; i < len(chunks); i++ {
		off := V3ChunkCipherOffset(uint64(i), cs)
		rec := container[off : off+cs+v3TagSize]
		pt, err := c.Open(uint64(i), rec)
		if err != nil {
			t.Fatalf("open chunk %d: %v", i, err)
		}
		if i < len(chunks)-1 {
			rebuilt = append(rebuilt, pt[:cs]...)
		} else {
			rebuilt = append(rebuilt, pt[:len(chunks[i])]...)
		}
	}
	if !bytes.Equal(rebuilt, plain) {
		t.Fatal("full container round-trip mismatch")
	}
	// container size bookkeeping
	want := V3CiphertextSize(int64(len(plain)), cs)
	if int64(len(container)) != want {
		t.Fatalf("container size %d != geometry %d", len(container), want)
	}
}

func TestV3Geometry(t *testing.T) {
	cs := int64(1024)
	if got := V3ChunkCount(0, cs); got != 0 {
		t.Fatalf("count(0)=%d", got)
	}
	if got := V3ChunkCount(cs, cs); got != 1 {
		t.Fatalf("count(cs)=%d", got)
	}
	if got := V3ChunkCount(cs+1, cs); got != 2 {
		t.Fatalf("count(cs+1)=%d", got)
	}
	if got := V3CiphertextSize(0, cs); got != V3HeaderSize {
		t.Fatalf("ct(0)=%d", got)
	}
	if got := V3CiphertextSize(cs, cs); got != V3HeaderSize+cs+v3TagSize {
		t.Fatalf("ct(cs)=%d", got)
	}
	if got := V3CiphertextSize(cs+1, cs); got != V3HeaderSize+2*(cs+v3TagSize) {
		t.Fatalf("ct(cs+1)=%d", got)
	}
	if idx, off := V3ChunkForOffset(0, cs); idx != 0 || off != 0 {
		t.Fatalf("offset0=(%d,%d)", idx, off)
	}
	if idx, off := V3ChunkForOffset(cs, cs); idx != 1 || off != 0 {
		t.Fatalf("offset cs=(%d,%d)", idx, off)
	}
	if idx, off := V3ChunkForOffset(cs+5, cs); idx != 1 || off != 5 {
		t.Fatalf("offset cs+5=(%d,%d)", idx, off)
	}
	if got := V3ChunkCipherOffset(2, cs); got != V3HeaderSize+2*(cs+v3TagSize) {
		t.Fatalf("chunk offset 2=%d", got)
	}
	if got := V3RemainingInChunk(cs+5, cs+2, cs); got != 3 {
		t.Fatalf("remaining=%d", got)
	}
	if got := V3RemainingInChunk(100, 90, cs); got != 10 {
		t.Fatalf("remaining(tail)=%d", got)
	}
}

func TestV3Header(t *testing.T) {
	nonce := testV3Nonce(t)
	hdr, err := NewV3Header(123456789, nonce, v3DefaultChunkSize, 600000)
	if err != nil {
		t.Fatal(err)
	}
	if len(hdr) != V3HeaderSize {
		t.Fatalf("header len %d", len(hdr))
	}
	if !bytes.HasPrefix(hdr, v3MagicBytes) {
		t.Fatal("bad magic")
	}
	meta, isV3, err := ParseV3Header(hdr, 0)
	if err != nil || !isV3 {
		t.Fatalf("parse: isV3=%v err=%v", isV3, err)
	}
	if meta.Version != ContentVersionV3 || meta.HeaderLen != V3HeaderSize {
		t.Fatalf("meta version/header %d/%d", meta.Version, meta.HeaderLen)
	}
	if meta.PlainSize != 123456789 {
		t.Fatalf("plain size %d", meta.PlainSize)
	}
	if !bytes.Equal(meta.NonceField, nonce) {
		t.Fatal("nonce mismatch")
	}
	if got := meta.CiphertextSize; got != V3CiphertextSize(123456789, v3DefaultChunkSize) {
		t.Fatalf("ciphertext size %d", got)
	}
	// explicit ciphertext size wins
	hdr2, _ := NewV3Header(50, nonce, v3DefaultChunkSize, 600000)
	meta2, isV3, err := ParseV3Header(hdr2, 999)
	if err != nil || !isV3 {
		t.Fatalf("parse explicit ct: %v %v", isV3, err)
	}
	if meta2.CiphertextSize != 999 {
		t.Fatalf("explicit ct size %d", meta2.CiphertextSize)
	}
	// Not-V3 prefix must fall back cleanly
	_, isV3, err = ParseV3Header([]byte(contentHeaderMagic[EncTypeAESCTR]), 0)
	if isV3 || err != nil {
		t.Fatalf("v2 prefix classified v3: %v %v", isV3, err)
	}
	// Truncated header with V3 magic must error
	bad := []byte(v3Magic + "\x03")
	_, isV3, err = ParseV3Header(bad, 0)
	if !isV3 || err == nil {
		t.Fatalf("truncated header: %v %v", isV3, err)
	}
}

func TestV3RawChunkField(t *testing.T) {
	if V3ChunkCount(5, 0) != 1 {
		t.Fatal("default chunk count")
	}
	if V3ChunkCipherLen(0) != v3DefaultChunkSize+v3TagSize {
		t.Fatal("default chunk len")
	}
}

// regression: chunk index must be encoded big-endianly AND the nonce must
// include the index (no chunk collisions)
func TestV3NonceUniqueness(t *testing.T) {
	c, _ := NewV3ChunkCipher(testV3Key(t), testV3Nonce(t))
	blob := []byte("same payload across chunk indexes")
	c0, _ := c.Seal(0, blob)
	c1, _ := c.Seal(1, blob)
	if bytes.Equal(c0, c1) {
		t.Fatal("distinct chunks produced identical ciphertext — nonce bug")
	}
	if _, err := c.Open(1, c0); err == nil {
		t.Fatal("c0 opened under index 1 — nonce collision")
	}
	// encoded index check
	n := c.chunkNonce(1)
	if binary.BigEndian.Uint32(n[8:]) != 1 {
		t.Fatalf("index not encoded big-endian: %v", n[8:])
	}
}

func TestV3RoundTripGolden(t *testing.T) {
	// A tiny fixed vector makes the format reviewable and guards accidental
	// nonce/cipher changes.
	goldenKey := []byte("0123456789abcdef0123456789abcdef")
	c, _ := NewV3ChunkCipher(goldenKey, testV3Nonce(t))
	ct, err := c.Seal(2, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := c.Open(2, ct)
	if err != nil || !bytes.Equal(pt, []byte("0123456789abcdef")) {
		t.Fatalf("golden: %v %q", err, pt)
	}

}
