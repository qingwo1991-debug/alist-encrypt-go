package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
)

func configureProbeTestAlist(t *testing.T, cfg *config.Config, serverURL string) {
	t.Helper()
	parsed, err := url.Parse(serverURL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse test server port: %v", err)
	}
	cfg.AlistServer.ServerHost = parsed.Hostname()
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = parsed.Scheme == "https"
}

func writeConfirmedV1Prefix(w http.ResponseWriter, ciphertextSize int64) {
	w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-31/%d", ciphertextSize))
	w.Header().Set("Content-Length", "32")
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(bytes.Repeat([]byte{0x6c}, int(encryption.ContentHeaderSize())))
}

func testPlaybackProbeRequest(cfg *config.Config, sp *proxy.StreamProxy, target string, requestHeaders http.Header, scenario string) (encryption.ContentMeta, bool) {
	req, _ := http.NewRequest(http.MethodGet, "http://proxy.local/video.mp4", nil)
	for key, values := range requestHeaders {
		req.Header[key] = append([]string(nil), values...)
	}
	return inspectPlaybackContentMeta(decryptPlaybackRequest{
		Request:     req,
		Config:      cfg,
		StreamProxy: sp,
		PasswdInfo: &config.PasswdInfo{
			Password: "test-password",
			EncType:  "aesctr",
			Enable:   true,
		},
		FileItem: FileItem{
			DisplayPath:   "/video.mp4",
			EncryptedPath: "/video.bin",
			TargetURL:     target,
			FileName:      "video.mp4",
		},
		TargetURL:        target,
		Path:             "/video.mp4",
		ConsumerScenario: scenario,
	}, requestHeaders, 4096)
}

func TestPlaybackProbeUsesRequestAuthWithoutLoginAndStopsOnConfirmedV1(t *testing.T) {
	var probeHits atomic.Int32
	var fallbackHits atomic.Int32
	var loginHits atomic.Int32
	server := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/raw/video.bin":
			probeHits.Add(1)
			if got := r.Header.Get("Authorization"); got != "Bearer request-token" {
				t.Errorf("Authorization=%q, want request token", got)
			}
			writeConfirmedV1Prefix(w, 4096)
		case "/dav/video.bin", "/d/video.bin":
			fallbackHits.Add(1)
			http.Error(w, "fallback must not run", http.StatusInternalServerError)
		case "/api/auth/login":
			loginHits.Add(1)
			http.Error(w, "login must not run", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	configureProbeTestAlist(t, cfg, server.URL)
	cfg.AlistServer.ScanUsername = "scanner"
	cfg.AlistServer.ScanPassword = "secret"
	sp := proxy.NewStreamProxy(cfg)
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer request-token")

	meta, ok := testPlaybackProbeRequest(cfg, sp, server.URL+"/raw/video.bin", headers, consumerScenarioWebDAV)
	if !ok || meta.Version != encryption.ContentVersionV1 || meta.PlainSize != 4096 {
		t.Fatalf("meta=%+v ok=%v, want confirmed V1", meta, ok)
	}
	if got := probeHits.Load(); got != 1 {
		t.Fatalf("raw probe hits=%d, want 1", got)
	}
	if got := fallbackHits.Load(); got != 0 {
		t.Fatalf("fallback hits=%d, want 0", got)
	}
	if got := loginHits.Load(); got != 0 {
		t.Fatalf("login hits=%d, want 0", got)
	}
}

func TestPlaybackProbeFetchesJWTOnlyAfterAuthFailureAndCachesIt(t *testing.T) {
	var probeHits atomic.Int32
	var loginHits atomic.Int32
	server := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dav/video.bin":
			probeHits.Add(1)
			if r.Header.Get("Authorization") != "Bearer jwt-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			writeConfirmedV1Prefix(w, 4096)
		case "/api/auth/login":
			loginHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"data":{"token":"Bearer jwt-token"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	configureProbeTestAlist(t, cfg, server.URL)
	cfg.AlistServer.ScanUsername = "scanner-jwt"
	cfg.AlistServer.ScanPassword = "secret-jwt"
	sp := proxy.NewStreamProxy(cfg)
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer stale-request-token")

	for attempt := 0; attempt < 2; attempt++ {
		meta, ok := testPlaybackProbeRequest(cfg, sp, server.URL+"/dav/video.bin", headers, consumerScenarioWebDAV)
		if !ok || meta.Version != encryption.ContentVersionV1 {
			t.Fatalf("attempt %d meta=%+v ok=%v, want confirmed V1", attempt+1, meta, ok)
		}
	}
	// First inspection tries request token, cheap Basic fallback, then JWT. The
	// second promotes the cached JWT immediately after the request token fails.
	if got := probeHits.Load(); got != 5 {
		t.Fatalf("probe hits=%d, want 5", got)
	}
	if got := loginHits.Load(); got != 1 {
		t.Fatalf("login hits=%d, want one cached JWT login", got)
	}
}

func TestPlaybackProbeDoesNotRetryAuthOrLoginOnNotFound(t *testing.T) {
	var probeHits atomic.Int32
	var loginHits atomic.Int32
	server := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/raw/missing.bin":
			probeHits.Add(1)
			http.NotFound(w, r)
		case "/api/auth/login":
			loginHits.Add(1)
			http.Error(w, "login must not run", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	configureProbeTestAlist(t, cfg, server.URL)
	cfg.AlistServer.ScanAuthHeader = "Bearer scan-token"
	cfg.AlistServer.ScanUsername = "scanner-404"
	cfg.AlistServer.ScanPassword = "secret-404"
	sp := proxy.NewStreamProxy(cfg)
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer request-token")

	if _, ok := testPlaybackProbeRequest(cfg, sp, server.URL+"/raw/missing.bin", headers, consumerScenarioHTTP); ok {
		t.Fatal("404 probe must remain unconfirmed")
	}
	if got := probeHits.Load(); got != 1 {
		t.Fatalf("404 probe hits=%d, want 1 despite three configured auth variants", got)
	}
	if got := loginHits.Load(); got != 0 {
		t.Fatalf("login hits=%d, want 0", got)
	}
}

func TestPlaybackProbeDoesNotLoginAfterAuthFailureThenNotFound(t *testing.T) {
	var probeHits atomic.Int32
	var loginHits atomic.Int32
	server := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/raw/missing.bin":
			probeHits.Add(1)
			if r.Header.Get("Authorization") == "Bearer request-token" {
				http.Error(w, "expired request auth", http.StatusUnauthorized)
				return
			}
			http.NotFound(w, r)
		case "/api/auth/login":
			loginHits.Add(1)
			http.Error(w, "login must not run", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.DefaultConfig()
	configureProbeTestAlist(t, cfg, server.URL)
	cfg.AlistServer.ScanUsername = "scanner-auth-404"
	cfg.AlistServer.ScanPassword = "secret-auth-404"
	sp := proxy.NewStreamProxy(cfg)
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer request-token")

	if _, ok := testPlaybackProbeRequest(cfg, sp, server.URL+"/raw/missing.bin", headers, consumerScenarioHTTP); ok {
		t.Fatal("401 then 404 probe must remain unconfirmed")
	}
	if got := probeHits.Load(); got != 2 {
		t.Fatalf("probe hits=%d, want request auth then Basic only", got)
	}
	if got := loginHits.Load(); got != 0 {
		t.Fatalf("login hits=%d, want 0 after non-auth terminal response", got)
	}
}

func resetProbeJWTCacheForTest() {
	probeJWTState.Lock()
	probeJWTState.entries = make(map[[32]byte]probeJWTCacheEntry)
	probeJWTState.Unlock()
}

func TestProbeJWTCacheSingleflightTTLAndCapacity(t *testing.T) {
	resetProbeJWTCacheForTest()
	t.Cleanup(resetProbeJWTCacheForTest)

	var fetches atomic.Int32
	start := make(chan struct{})
	const workers = 32
	results := make(chan string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- probeJWTForCredentials("http://alist.local:5244", "scanner", "singleflight-secret", func(_, _, _ string) string {
				fetches.Add(1)
				time.Sleep(10 * time.Millisecond)
				return "Bearer shared-token"
			})
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for token := range results {
		if token != "Bearer shared-token" {
			t.Fatalf("token=%q, want shared token", token)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("concurrent JWT fetches=%d, want 1", got)
	}

	key := probeJWTCacheKey("http://expired.local:5244", "scanner", "expired-secret")
	probeJWTState.Lock()
	probeJWTState.entries[key] = probeJWTCacheEntry{
		token:     "Bearer expired",
		expiresAt: time.Now().Add(-time.Second),
		lastUsed:  time.Now().Add(-time.Hour),
	}
	probeJWTState.Unlock()
	if got := probeJWTForCredentials("http://expired.local:5244", "scanner", "expired-secret", func(_, _, _ string) string {
		fetches.Add(1)
		return "Bearer refreshed"
	}); got != "Bearer refreshed" {
		t.Fatalf("expired cache returned %q", got)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetches after TTL expiry=%d, want 2", got)
	}

	var failedFetches atomic.Int32
	failedFetcher := func(_, _, _ string) string {
		failedFetches.Add(1)
		return ""
	}
	for i := 0; i < 2; i++ {
		if token := probeJWTForCredentials("http://invalid.local:5244", "scanner", "wrong-secret", failedFetcher); token != "" {
			t.Fatalf("failed login returned token %q", token)
		}
	}
	if got := failedFetches.Load(); got != 1 {
		t.Fatalf("failed login fetches within negative TTL=%d, want 1", got)
	}
	negativeKey := probeJWTCacheKey("http://invalid.local:5244", "scanner", "wrong-secret")
	probeJWTState.Lock()
	negativeEntry := probeJWTState.entries[negativeKey]
	negativeEntry.expiresAt = time.Now().Add(-time.Second)
	probeJWTState.entries[negativeKey] = negativeEntry
	probeJWTState.Unlock()
	_ = probeJWTForCredentials("http://invalid.local:5244", "scanner", "wrong-secret", failedFetcher)
	if got := failedFetches.Load(); got != 2 {
		t.Fatalf("failed login fetches after negative TTL expiry=%d, want 2", got)
	}

	for i := 0; i < probeJWTCacheMax+10; i++ {
		alistURL := fmt.Sprintf("http://alist-%d.local:5244", i)
		if token := probeJWTForCredentials(alistURL, "scanner", "bounded-secret", func(_, _, _ string) string {
			return "Bearer bounded"
		}); token == "" {
			t.Fatalf("empty token for cache entry %d", i)
		}
	}
	probeJWTState.Lock()
	cacheLen := len(probeJWTState.entries)
	probeJWTState.Unlock()
	if cacheLen > probeJWTCacheMax {
		t.Fatalf("JWT cache entries=%d, max=%d", cacheLen, probeJWTCacheMax)
	}
}
