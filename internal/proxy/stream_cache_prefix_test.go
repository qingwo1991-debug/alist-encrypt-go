package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func TestDecryptedBlockCacheGetPrefix(t *testing.T) {
	cache := newDecryptedBlockCache(1024, 4)
	cache.putBlock("f", 0, []byte("abcd"))
	cache.putBlock("f", 4, []byte("efgh"))
	cache.putBlock("f", 12, []byte("mnop")) // gap at 8
	if got := cache.getPrefix("f", 1, 100); string(got) != "bcdefgh" {
		t.Fatalf("prefix=%q", got)
	}
	if got := cache.getPrefix("f", 2, 3); string(got) != "cde" {
		t.Fatalf("capped prefix=%q", got)
	}
	if got := cache.getPrefix("f", 8, 4); got != nil {
		t.Fatalf("expected nil at gap, got %q", got)
	}
	cache.putBlock("g", 0, []byte("ab")) // short block ends contiguity
	cache.putBlock("g", 4, []byte("efgh"))
	if got := cache.getPrefix("g", 0, 8); string(got) != "ab" {
		t.Fatalf("short-block prefix=%q", got)
	}
}

func TestReadaheadWindowOpenEndedRange(t *testing.T) {
	const size = int64(256 << 20)
	// Bounded range: prefetch right after its end.
	if start, n, ok := readaheadWindow(size, 0, 1023); !ok || start != 1024 || n != readaheadLookaheadBytes {
		t.Fatalf("bounded: start=%d n=%d ok=%v", start, n, ok)
	}
	// Open-ended ranges ("bytes=N-" or no Range, End = EOF) get no forward
	// window: the live connection streams those bytes itself.
	if _, _, ok := readaheadWindow(size, 1000, size-1); ok {
		t.Fatal("open-ended range must not prefetch its own stream")
	}
	if _, _, ok := readaheadWindow(size, 0, size-1); ok {
		t.Fatal("range-less start must not prefetch its own stream")
	}
	// Bounded range near EOF: window clamps to the remainder.
	if start, n, ok := readaheadWindow(size, size-(5<<20), size-(4<<20)); !ok || start+n != size {
		t.Fatalf("near EOF: start=%d n=%d ok=%v", start, n, ok)
	}
	// Open range inside the lead of EOF: nothing to prefetch.
	if _, _, ok := readaheadWindow(size, size-1024, size-1); ok {
		t.Fatal("tail request scheduled readahead past EOF")
	}
}

type prefixTestRig struct {
	t      *testing.T
	sp     *StreamProxy
	plain  []byte
	c      acceptanceContainer
	mu     sync.Mutex
	ranges []string
	url    string
}

func newPrefixTestRig(t *testing.T, plain []byte, c acceptanceContainer) *prefixTestRig {
	rig := &prefixTestRig{t: t, plain: plain, c: c}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.ranges = append(rig.ranges, r.Header.Get("Range"))
		rig.mu.Unlock()
		http.ServeContent(w, r, "movie.bin", time.Time{}, bytes.NewReader(c.body))
	}))
	t.Cleanup(upstream.Close)
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	rig.sp = NewStreamProxy(cfg)
	rig.sp.blockCache = newDecryptedBlockCache(8<<20, 64<<10)
	rig.sp.client = &Client{Client: upstream.Client()}
	rig.url = upstream.URL
	return rig
}

func (rig *prefixTestRig) take() []string {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	got := rig.ranges
	rig.ranges = nil
	return got
}

func (rig *prefixTestRig) get(rangeHeader string) *httptest.ResponseRecorder {
	rig.t.Helper()
	r := httptest.NewRequest("GET", "/movie", nil)
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	r = r.WithContext(WithContentMeta(r.Context(), rig.c.meta))
	w := httptest.NewRecorder()
	pass := &config.PasswdInfo{Enable: true, EncType: "aesctr", Password: "pw"}
	if res := rig.sp.ProxyDownloadDecryptWithStrategyForStorage(w, r, rig.url, pass, int64(len(rig.plain)), StreamStrategyRange, "rule-path"); res.Err != nil {
		rig.t.Fatalf("%q: err=%v", rangeHeader, res.Err)
	}
	return w
}

func prefixTestPlain() []byte {
	plain := make([]byte, 512<<10)
	for i := range plain {
		plain[i] = byte(i*7 + i/251)
	}
	return plain
}

func TestDecryptedCachePrefixSplicesUpstreamContinuation(t *testing.T) {
	plain := prefixTestPlain()
	for _, container := range acceptanceContainers(t, plain) {
		if container.meta.IsV3() {
			continue // V3 uses its own record cache.
		}
		t.Run(container.name, func(t *testing.T) {
			rig := newPrefixTestRig(t, plain, container)

			// Warm the first 128 KiB (two cache blocks).
			if w := rig.get("bytes=0-131071"); w.Code != 206 || !bytes.Equal(w.Body.Bytes(), plain[:131072]) {
				t.Fatalf("warm status=%d len=%d", w.Code, w.Body.Len())
			}
			rig.take()

			// Open-ended seek inside the cached span: prefix from memory,
			// continuation from upstream at the first missing block.
			w := rig.get("bytes=1000-")
			if w.Code != 206 {
				t.Fatalf("status=%d", w.Code)
			}
			if got, want := w.Header().Get("Content-Range"), fmt.Sprintf("bytes 1000-%d/%d", len(plain)-1, len(plain)); got != want {
				t.Fatalf("Content-Range=%q want %q", got, want)
			}
			if got, want := w.Header().Get("Content-Length"), fmt.Sprint(len(plain)-1000); got != want {
				t.Fatalf("Content-Length=%q want %q", got, want)
			}
			if !bytes.Equal(w.Body.Bytes(), plain[1000:]) {
				t.Fatalf("spliced body mismatch: len=%d", w.Body.Len())
			}
			wantStart := int64(131072)
			if container.meta.IsV2() {
				wantStart += container.meta.HeaderLen
			}
			if got := rig.take(); len(got) != 1 || !strings.HasPrefix(got[0], fmt.Sprintf("bytes=%d-", wantStart)) {
				t.Fatalf("continuation upstream ranges=%v want start %d", got, wantStart)
			}

			// The continuation filled the cache, so a later bounded seek is
			// served entirely from memory.
			if w := rig.get("bytes=300000-400000"); w.Code != 206 || !bytes.Equal(w.Body.Bytes(), plain[300000:400001]) {
				t.Fatalf("full hit status=%d", w.Code)
			}
			if got := rig.take(); len(got) != 0 {
				t.Fatalf("fully cached range fetched upstream: %v", got)
			}
		})
	}
}

func TestDecryptedCachePrefixRangelessStart(t *testing.T) {
	plain := prefixTestPlain()
	container := acceptanceContainers(t, plain)[1] // V2

	// A range-less GET must populate the cache too.
	rig := newPrefixTestRig(t, plain, container)
	if w := rig.get(""); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), plain) {
		t.Fatalf("first GET status=%d len=%d", w.Code, w.Body.Len())
	}
	rig.take()
	if w := rig.get("bytes=4096-8191"); w.Code != 206 || !bytes.Equal(w.Body.Bytes(), plain[4096:8192]) {
		t.Fatalf("cached range status=%d", w.Code)
	}
	if got := rig.take(); len(got) != 0 {
		t.Fatalf("range after range-less GET hit upstream: %v", got)
	}

	// With only a cached prefix, a range-less GET replies 200 with the full
	// length, prefix bytes from memory and the rest from upstream.
	rig = newPrefixTestRig(t, plain, container)
	rig.get("bytes=0-131071")
	rig.take()
	w := rig.get("")
	if w.Code != 200 || w.Header().Get("Content-Range") != "" || w.Header().Get("Content-Length") != fmt.Sprint(len(plain)) {
		t.Fatalf("spliced whole body status=%d headers=%v", w.Code, w.Header())
	}
	if !bytes.Equal(w.Body.Bytes(), plain) {
		t.Fatalf("spliced whole body mismatch: len=%d", w.Body.Len())
	}
	if got := rig.take(); len(got) != 1 || !strings.HasPrefix(got[0], fmt.Sprintf("bytes=%d-", 131072+container.meta.HeaderLen)) {
		t.Fatalf("continuation upstream ranges=%v", got)
	}
}

func TestReadaheadTailWindowOnPlaybackStart(t *testing.T) {
	const size = int64(256 << 20)
	if start, n, ok := readaheadTailWindow(size, 0); !ok || start != size-readaheadTailBytes || n != readaheadTailBytes {
		t.Fatalf("start: tail=%d n=%d ok=%v", start, n, ok)
	}
	if _, _, ok := readaheadTailWindow(size, 4096); ok {
		t.Fatal("seek must not warm the tail")
	}
	if _, _, ok := readaheadTailWindow(30<<20, 0); ok {
		t.Fatal("forward window already covers a small file's tail")
	}
}

func TestMP4MoovAtFront(t *testing.T) {
	box := func(typ string, size int) []byte {
		b := make([]byte, size)
		b[0], b[1], b[2], b[3] = byte(size>>24), byte(size>>16), byte(size>>8), byte(size)
		copy(b[4:8], typ)
		return b
	}
	front := append(append(box("ftyp", 32), box("moov", 64)...), box("free", 8)...)
	if !mp4MoovAtFront(front) {
		t.Fatal("moov before mdat must be detected")
	}
	back := append(box("ftyp", 32), []byte{0, 0, 0, 0, 'm', 'd', 'a', 't'}...)
	if mp4MoovAtFront(back) {
		t.Fatal("mdat first means the index is at the tail")
	}
	if mp4MoovAtFront([]byte("\x1aE\xdf\xa3 matroska")) {
		t.Fatal("non-MP4 must keep tail warm-up")
	}
}

func TestFirstWriteHookFiresOnceAfterSniffBytes(t *testing.T) {
	var got [][]byte
	var dst bytes.Buffer
	h := &firstWriteHook{dst: &dst, fire: func(b []byte) { got = append(got, append([]byte(nil), b...)) }}
	h.Write(make([]byte, 100))
	if len(got) != 0 {
		t.Fatal("fired before sniff bytes collected")
	}
	h.Write(bytes.Repeat([]byte{1}, 1000))
	h.Write([]byte{2})
	if len(got) != 1 || len(got[0]) != firstWriteSniffBytes || dst.Len() != 1101 {
		t.Fatalf("fires=%d written=%d", len(got), dst.Len())
	}
}

func TestContinuationWriterRejectsMismatchedRange(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := &continuationWriter{dst: rec, header: make(http.Header), contStart: 100, end: 199}
	cw.Header().Set("Content-Range", "bytes 0-199/1000")
	cw.WriteHeader(http.StatusPartialContent)
	if n, err := cw.Write([]byte("x")); err == nil || n != 0 || rec.Body.Len() != 0 {
		t.Fatalf("mismatched continuation leaked bytes: n=%d err=%v", n, err)
	}
	ok := &continuationWriter{dst: rec, header: make(http.Header), contStart: 100, end: 199}
	ok.Header().Set("Content-Range", "bytes 100-199/1000")
	ok.WriteHeader(http.StatusPartialContent)
	if _, err := ok.Write([]byte("y")); err != nil || rec.Body.String() != "y" || rec.Header().Get("Content-Range") != "" {
		t.Fatalf("matching continuation: err=%v body=%q hdr=%v", err, rec.Body.String(), rec.Header())
	}
}
