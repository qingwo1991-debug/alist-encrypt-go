package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
