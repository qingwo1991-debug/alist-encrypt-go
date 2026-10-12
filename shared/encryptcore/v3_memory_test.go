package encryption

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// Keep KDF cost out of allocation/throughput measurements; the production KDF
// cache is covered by its separate, unchanged regression suite.
func v3MemoryCipher(tb testing.TB) *V3ChunkCipher {
	tb.Helper()
	c, err := NewV3ChunkCipher(bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 16))
	if err != nil {
		tb.Fatal(err)
	}
	return c
}
func v3MemoryFixture(tb testing.TB, cs, size int) (*V3Container, []byte, []byte) {
	tb.Helper()
	plain := make([]byte, size)
	for i := range plain {
		// Mix chunk identity and high offset bits so adjacent power-of-two
		// chunks cannot mask a wrong-cache-index or record-reuse bug.
		plain[i] = byte(i*17 + 3 + (i/cs)*71 + (i>>8)*29 + (i>>16)*43)
	}
	var out bytes.Buffer
	cipher := v3MemoryCipher(tb)
	w := &V3Writer{w: &out, chunkSize: int64(cs), nonce: cipher.nonce, cipher: cipher, buf: make([]byte, 0, cs+v3TagSize)}
	if n, err := w.Write(plain); err != nil || n != size {
		tb.Fatalf("Write: %d %v", n, err)
	}
	if err := w.Close(); err != nil {
		tb.Fatal(err)
	}
	data := out.Bytes()
	return &V3Container{R: bytes.NewReader(data), Size: int64(len(data)), ChunkSize: uint64(cs), PlainSize: int64(size), Cipher: cipher, cache: &v3ReadCache{}}, plain, data
}

func TestV3MemoryPaddingAndSmallReaders(t *testing.T) {
	const cs = 257
	c, want, data := v3MemoryFixture(t, cs, cs*3+19)
	// Compare against allocating public Seal: format and zero padding unchanged.
	for idx, start := uint64(0), 0; start < len(want); idx, start = idx+1, start+cs {
		padded := make([]byte, cs)
		copy(padded, want[start:])
		expected, err := c.Cipher.Seal(idx, padded)
		if err != nil {
			t.Fatal(err)
		}
		off := int(V3ChunkCipherOffset(idx, cs))
		if !bytes.Equal(expected, data[off:off+len(expected)]) {
			t.Fatalf("record %d changed format/padding", idx)
		}
	}
	stream, err := NewV3StreamReader(bytes.NewReader(data[V3HeaderSize:len(data)-v3TrailerLen]), c.Cipher, cs, 0, 11, int64(len(want)-11))
	if err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]io.Reader{"seq": c.Sequential(), "stream": stream} {
		expected := want
		if name == "stream" {
			expected = want[11:]
		}
		got := make([]byte, 0, len(expected))
		p := make([]byte, 7)
		for {
			n, err := r.Read(p)
			got = append(got, p[:n]...)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got, expected) {
			t.Fatalf("%s: corrupted reused plaintext", name)
		}
	}
}

type v3MemoryCountingReader struct {
	io.ReaderAt
	calls atomic.Int64
}

func (r *v3MemoryCountingReader) ReadAt(p []byte, off int64) (int, error) {
	r.calls.Add(1)
	return r.ReaderAt.ReadAt(p, off)
}

func TestV3MemoryReadAtCacheAndConcurrency(t *testing.T) {
	c, want, _ := v3MemoryFixture(t, 1024, 3073)
	counted := &v3MemoryCountingReader{ReaderAt: c.R}
	c.R = counted
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(off int) {
			defer wg.Done()
			p := make([]byte, 13)
			n, err := c.ReadAt(p, int64(off))
			if err != nil || n != len(p) || !bytes.Equal(p, want[off:off+len(p)]) {
				t.Errorf("same chunk %d: %d %v", off, n, err)
			}
		}(i * 17)
	}
	wg.Wait()
	if got := counted.calls.Load(); got != 1 {
		t.Fatalf("same chunk fetched %d times", got)
	}
	// A copied view shares the cache pointer rather than copying an active mutex.
	copyView := *c
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			off := (i * 83) % 2800
			p := make([]byte, 273)
			n, err := copyView.ReadAt(p, int64(off))
			if err != nil || n != len(p) || !bytes.Equal(p, want[off:off+len(p)]) {
				t.Errorf("cross chunk %d: %d %v", off, n, err)
			}
		}(i)
	}
	wg.Wait()
	p := make([]byte, 10)
	n, err := c.ReadAt(p, int64(len(want)-3))
	if n != 3 || err != io.EOF || !bytes.Equal(p[:n], want[len(want)-3:]) {
		t.Fatalf("tail: %d %v", n, err)
	}
}

type v3MemoryFaultWriter struct {
	calls, failAt int
	err           error
	short         bool
}

func (w *v3MemoryFaultWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == w.failAt {
		n := len(p)
		if w.short {
			n--
		}
		return n, w.err
	}
	return len(p), nil
}
func TestV3MemoryWriterStickyErrors(t *testing.T) {
	sentinel := errors.New("injected")
	for _, stage := range []int{1, 2, 3, 4} {
		for _, mode := range []string{"short", "error", "short-error"} {
			t.Run(mode+string(rune('0'+stage)), func(t *testing.T) {
				dst := &v3MemoryFaultWriter{failAt: stage, short: mode != "error"}
				expected := sentinel
				if mode == "short" {
					expected = io.ErrShortWrite
				} else {
					dst.err = sentinel
				}
				c := v3MemoryCipher(t)
				w := &V3Writer{w: dst, chunkSize: 8, nonce: c.nonce, cipher: c, buf: make([]byte, 0, 24)}
				n, err := w.Write(make([]byte, 17))
				wantN := 17
				if stage == 1 {
					wantN = 0
				}
				if stage == 2 {
					wantN = 8
				}
				if stage == 3 {
					wantN = 16
				}
				if n != wantN || w.written != int64(wantN) {
					t.Fatalf("accepted %d/%d, want %d", n, w.written, wantN)
				}
				if stage == 4 {
					if err != nil {
						t.Fatal(err)
					}
					err = w.Close()
				}
				if !errors.Is(err, expected) {
					t.Fatalf("error: %v", err)
				}
				calls := dst.calls
				if n, next := w.Write([]byte{1}); n != 0 || next != err {
					t.Fatalf("sticky Write: %d %v", n, next)
				}
				if next := w.Close(); next != err {
					t.Fatalf("sticky Close: %v", next)
				}
				if dst.calls != calls {
					t.Fatal("retried failed output/nonce")
				}
			})
		}
	}
	// Trailer failure is terminal too.
	dst := &v3MemoryFaultWriter{failAt: 1, short: true}
	c := v3MemoryCipher(t)
	w := &V3Writer{w: dst, chunkSize: 8, cipher: c, nonce: c.nonce, started: true}
	err := w.Close()
	if !errors.Is(err, io.ErrShortWrite) || w.Close() != err || dst.calls != 1 {
		t.Fatalf("trailer failure: %v", err)
	}
}

func TestV3MemoryTamperAndNonceLimit(t *testing.T) {
	c, _, data := v3MemoryFixture(t, 64, 130)
	data[V3HeaderSize+3] ^= 1
	p := make([]byte, 10)
	if n, err := c.ReadAt(p, 0); n != 0 || !errors.Is(err, errV3TagMismatch) {
		t.Fatalf("tamper: %d %v", n, err)
	}
	if c.cache.plain != nil {
		t.Fatal("cached failed authentication")
	}
	stream, err := NewV3StreamReader(bytes.NewReader(data[V3HeaderSize:]), c.Cipher, 64, 0, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	_, first := stream.Read(p)
	_, second := stream.Read(p)
	if !errors.Is(first, errV3TagMismatch) || second != first {
		t.Fatalf("stream failure not sticky: %v / %v", first, second)
	}
	if _, err := c.Cipher.Seal(1<<32, p); err == nil {
		t.Fatal("nonce wrap permitted")
	}
}

func TestV3MemoryTruncatedReaders(t *testing.T) {
	c, _, data := v3MemoryFixture(t, 64, 128)
	// A complete first record followed by a truncated second record.
	body := data[V3HeaderSize : V3HeaderSize+64+v3TagSize+17]
	stream, err := NewV3StreamReader(bytes.NewReader(body), c.Cipher, 64, 0, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	seq := &v3SeqReader{r: bytes.NewReader(body), c: c, cs: 64}
	for _, r := range []io.Reader{stream, seq} {
		p := make([]byte, 64)
		if _, err := io.ReadFull(r, p); err != nil {
			t.Fatal(err)
		}
		n, first := r.Read(p)
		if n != 0 || !errors.Is(first, io.ErrUnexpectedEOF) {
			t.Fatalf("truncation: %d %v", n, first)
		}
		if n, second := r.Read(p); n != 0 || second != first {
			t.Fatalf("nonterminal truncation: %d %v", n, second)
		}
	}
}

func TestV3MemoryCachedReadAllocations(t *testing.T) {
	c, _, _ := v3MemoryFixture(t, 4096, 8192)
	var p [32]byte
	if _, err := c.ReadAt(p[:], 7); err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		if n, err := c.ReadAt(p[:], 7); n != len(p) || err != nil {
			panic("cached ReadAt failed")
		}
	})
	if allocs != 0 {
		t.Fatalf("cached small reads allocated %.2f times per call", allocs)
	}
}

func TestV3MemoryRecordBufferReuse(t *testing.T) {
	c, _, data := v3MemoryFixture(t, 64, 256)
	seq := c.Sequential().(*v3SeqReader)
	stream, err := NewV3StreamReader(bytes.NewReader(data[V3HeaderSize:len(data)-v3TrailerLen]), c.Cipher, 64, 0, 0, 256)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 64)
	var seqBase, streamBase *byte
	for i := 0; i < 4; i++ {
		if _, err := seq.Read(p); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(stream, p); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			seqBase, streamBase = &seq.record[0], &stream.record[0]
		}
		if seqBase != &seq.record[0] || streamBase != &stream.record[0] {
			t.Fatal("reader reallocated its record")
		}
		if &seq.buf[0] != seqBase || &stream.rbuf[0] != streamBase {
			t.Fatal("open allocated separate plaintext")
		}
	}
}

func BenchmarkV3MemoryReadAtSmall(b *testing.B) {
	c, _, _ := v3MemoryFixture(b, 1<<20, 2<<20)
	p := make([]byte, 64)
	if _, err := c.ReadAt(p, 0); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(p)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.ReadAt(p, int64((i%1000)*64)); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkV3MemoryStreams(b *testing.B) {
	for _, cs := range []int{64 << 10, 1 << 20, 16 << 20} {
		name := map[int]string{64 << 10: "64KiB", 1 << 20: "1MiB", 16 << 20: "default16MiB"}[cs]
		b.Run(name, func(b *testing.B) {
			c, plain, data := v3MemoryFixture(b, cs, cs*2+7)
			for _, mode := range []string{"writer", "sequential", "stream"} {
				b.Run(mode, func(b *testing.B) {
					p := make([]byte, 32<<10)
					b.ReportAllocs()
					b.SetBytes(int64(len(plain)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if mode == "writer" {
							w := &V3Writer{w: io.Discard, chunkSize: int64(cs), cipher: c.Cipher, nonce: c.Cipher.nonce, buf: make([]byte, 0, cs+v3TagSize)}
							if n, err := w.Write(plain); err != nil || n != len(plain) {
								b.Fatalf("Write accepted %d/%d bytes: %v", n, len(plain), err)
							}
							if err := w.Close(); err != nil {
								b.Fatal(err)
							}
						} else {
							r := c.Sequential()
							if mode == "stream" {
								var err error
								r, err = NewV3StreamReader(bytes.NewReader(data[V3HeaderSize:len(data)-v3TrailerLen]), c.Cipher, int64(cs), 0, 0, int64(len(plain)))
								if err != nil {
									b.Fatal(err)
								}
							}
							total := 0
							for {
								n, err := r.Read(p)
								total += n
								if err == io.EOF {
									break
								}
								if err != nil {
									b.Fatal(err)
								}
								if n == 0 {
									b.Fatal("reader made no progress")
								}
							}
							if total != len(plain) {
								b.Fatalf("Read produced %d/%d bytes", total, len(plain))
							}
						}
					}
				})
			}
		})
	}
}
