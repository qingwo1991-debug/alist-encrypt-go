package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func TestRedirectDecryptedCacheUsesAdmissionLocator(t *testing.T) {
	plain := bytes.Repeat([]byte("playback-cache"), 1024)
	container := acceptanceContainers(t, plain)[1]
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/cdn" {
			http.Redirect(w, r, "/cdn", http.StatusFound)
			return
		}
		http.ServeContent(w, r, "movie.bin", time.Time{}, bytes.NewReader(container.body))
	}))
	defer upstream.Close()
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	cfg.AlistServer.FollowRedirectForDecrypt = true
	sp := NewStreamProxy(cfg)
	sp.blockCache = newDecryptedBlockCache(1024*1024, 4096)
	client := upstream.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	sp.client = &Client{Client: client}
	read := func(locator string) {
		t.Helper()
		r := httptest.NewRequest("GET", "/movie", nil)
		r.Header.Set("Range", "bytes=0-4095")
		r = r.WithContext(WithContentMeta(r.Context(), container.meta))
		w := httptest.NewRecorder()
		result := sp.ProxyDownloadDecryptWithStrategyForStorage(w, r, upstream.URL+locator, &config.PasswdInfo{Enable: true, EncType: "aesctr", Password: "pw"}, int64(len(plain)), StreamStrategyRange, "same-rule-path")
		if result.Err != nil || w.Code != 206 || !bytes.Equal(w.Body.Bytes(), plain[:4096]) {
			t.Fatalf("status=%d err=%v bytes=%d", w.Code, result.Err, w.Body.Len())
		}
	}
	read("/first")
	cold := hits.Load()
	if cold != 2 {
		t.Fatalf("cold requests=%d", cold)
	}
	read("/first")
	if hits.Load() != cold {
		t.Fatal("warm read fetched redirect again")
	}
	read("/second")
	if hits.Load() != cold+2 {
		t.Fatal("different source locator shared cached bytes")
	}
}

func TestKnownPlaintextEOFNeedsNoUpstream(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), 1024)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(404) }))
	defer upstream.Close()
	for _, container := range acceptanceContainers(t, plain) {
		t.Run(container.name, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			for _, rangeHeader := range []string{"bytes=1024-", "bytes=1024-2048", "bytes=4096-"} {
				r := httptest.NewRequest("GET", "/movie", nil)
				r.Header.Set("Range", rangeHeader)
				r = r.WithContext(WithContentMeta(r.Context(), container.meta))
				w := httptest.NewRecorder()
				result := sp.ProxyDownloadDecryptWithStrategyForStorage(w, r, upstream.URL, &config.PasswdInfo{Enable: true, EncType: "aesctr", Password: "pw"}, 1024, StreamStrategyRange, "path")
				if w.Code != 416 || !result.ResponseStarted || w.Header().Get("Content-Range") != fmt.Sprintf("bytes */%d", len(plain)) {
					t.Fatalf("status=%d outcome=%+v", w.Code, result)
				}
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("EOF fetched upstream %d times", hits.Load())
	}
}
