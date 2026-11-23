package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestMaybeReadaheadGating(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	sp.blockCache = newDecryptedBlockCache(1024, 256)
	meta := encryption.ContentMeta{Version: 2, PlainSize: 256 << 20, CiphertextSize: 256<<20 + 64, HeaderLen: 32}
	newReq := func() *http.Request { return httptest.NewRequest("GET", "/f", nil) }

	// Small file: no readahead.
	sp.maybeReadahead(newReq(), "http://up/x", nil, 1024, meta, 0, 1023, StreamStrategyRange, "k")
	if sp.readaheadActive.Load() != 0 {
		t.Fatal("small file spawned readahead")
	}

	// Range at EOF: nothing left to prefetch.
	sp.maybeReadahead(newReq(), "http://up/x", nil, 256<<20, meta, (256<<20)-1, (256<<20)-1, StreamStrategyRange, "k")
	if sp.readaheadActive.Load() != 0 {
		t.Fatal("EOF range spawned readahead")
	}

	// Marker context: readahead must not chain.
	req := newReq()
	req = req.WithContext(context.WithValue(req.Context(), streamReadaheadKey{}, true))
	sp.maybeReadahead(req, "http://up/x", nil, 256<<20, meta, 0, 1023, StreamStrategyRange, "k")
	if sp.readaheadActive.Load() != 0 {
		t.Fatal("marked request spawned readahead")
	}
}

func TestReadaheadRegistrySeekCancelsStaleWindows(t *testing.T) {
	var r readaheadRegistry
	canceled := map[string]bool{}
	mk := func(name string) context.CancelFunc { return func() { canceled[name] = true } }
	gen1, _ := r.supersede("f", 0)
	r.register("f", 1<<20, 33<<20, mk("a"))
	r.register("g", 0, 1<<20, mk("other-file"))
	// Next sequential chunk lands inside the window: keep it.
	gen2, n := r.supersede("f", 1<<20)
	if n != 0 || canceled["a"] {
		t.Fatalf("sequential read cancelled its own window: n=%d", n)
	}
	if gen2 == gen1 || r.current("f") != gen2 {
		t.Fatal("generation not bumped")
	}
	// Seek far away: cancel, other files untouched.
	if _, n := r.supersede("f", 500<<20); n != 1 || !canceled["a"] || canceled["other-file"] {
		t.Fatalf("seek: n=%d canceled=%v", n, canceled)
	}
}

func TestFirstWriteHookLogsPlaybackWindowOnce(t *testing.T) {
	var calls int
	h := &firstWriteHook{dst: io.Discard, started: time.Now(), onWindow: func(time.Duration) { calls++ }}
	h.Write(make([]byte, playbackWindowLogBytes-1))
	if calls != 0 {
		t.Fatal("logged before window delivered")
	}
	h.Write([]byte{1, 2})
	h.Write([]byte{3})
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}
