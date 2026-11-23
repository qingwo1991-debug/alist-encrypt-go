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
	// "bytes=1000-" parses to End = EOF; it must still yield a window ahead
	// of the live stream rather than nothing.
	if start, n, ok := readaheadWindow(size, 1000, size-1); !ok || start != 1000+readaheadOpenRangeLeadBytes || n != readaheadLookaheadBytes {
		t.Fatalf("open-ended: start=%d n=%d ok=%v", start, n, ok)
	}
	// Range-less playback start behaves like "bytes=0-".
	if start, _, ok := readaheadWindow(size, 0, size-1); !ok || start != readaheadOpenRangeLeadBytes {
		t.Fatalf("whole body: start=%d ok=%v", start, ok)
	}
	// Open range near EOF: window clamps to the remainder.
	if start, n, ok := readaheadWindow(size, size-(5<<20), size-1); !ok || start+n != size {
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
