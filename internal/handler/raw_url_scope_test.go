package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func newRawURLScopeTestDAO(t *testing.T) *dao.FileDAO {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	fileDAO := dao.NewFileDAO(store)
	t.Cleanup(func() {
		fileDAO.Stop()
		_ = store.Close()
	})
	return fileDAO
}

func authHeader(value string) http.Header {
	headers := make(http.Header)
	if value != "" {
		headers.Set("Authorization", value)
	}
	return headers
}

func TestFetchRawURLCacheIsolatedByAuthScope(t *testing.T) {
	fileDAO := newRawURLScopeTestDAO(t)
	displayPath := "/encrypt/movie.mp4"
	realPath := "/encrypt/movie.bin"
	scanHeaders := authHeader("Bearer scan-account")
	scanScope := rawURLAuthScope(scanHeaders)

	upstreamCalls := 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		suffix := "anon"
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
			suffix = strings.TrimPrefix(auth, "Bearer ")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"raw_url": "https://cdn.example/" + suffix,
				"size":    4096,
			},
		})
	}))
	defer upstream.Close()

	seedScanCache := func(scope string) {
		t.Helper()
		if err := fileDAO.Set(&dao.FileInfo{
			Path:              displayPath,
			EncryptedPath:     realPath,
			Size:              4096,
			RawURL:            "https://cdn.example/scan-cached",
			RawURLAuthScope:   scope,
			UpstreamFetchedAt: time.Now(),
		}); err != nil {
			t.Fatalf("seed scan cache: %v", err)
		}
	}

	seedScanCache(scanScope)
	result := fetchRawURL(context.Background(), upstream.URL, displayPath, realPath, scanHeaders, fileDAO, 30*time.Minute)
	if result.Source != "cache" || result.RawURL != "https://cdn.example/scan-cached" || upstreamCalls != 0 {
		t.Fatalf("same-scope result=%+v upstreamCalls=%d", result, upstreamCalls)
	}

	seedScanCache(scanScope)
	result = fetchRawURL(context.Background(), upstream.URL, displayPath, realPath, nil, fileDAO, 30*time.Minute)
	if result.Source == "cache" || result.RawURL != "https://cdn.example/anon" || upstreamCalls != 1 {
		t.Fatalf("anonymous result=%+v upstreamCalls=%d", result, upstreamCalls)
	}

	seedScanCache(scanScope)
	userBHeaders := authHeader("Bearer user-b")
	result = fetchRawURL(context.Background(), upstream.URL, displayPath, realPath, userBHeaders, fileDAO, 30*time.Minute)
	if result.Source == "cache" || result.RawURL != "https://cdn.example/user-b" || upstreamCalls != 2 {
		t.Fatalf("user B result=%+v upstreamCalls=%d", result, upstreamCalls)
	}

	// Entries written before scope tracking must not be reused by any caller.
	seedScanCache("")
	result = fetchRawURL(context.Background(), upstream.URL, displayPath, realPath, scanHeaders, fileDAO, 30*time.Minute)
	if result.Source == "cache" || upstreamCalls != 3 {
		t.Fatalf("legacy empty-scope result=%+v upstreamCalls=%d", result, upstreamCalls)
	}
}

func TestUnauthorizedScopeCannotInvalidateAnotherScopesRawURLOrMapping(t *testing.T) {
	fileDAO := newRawURLScopeTestDAO(t)
	displayPath := "/encrypt/movie.mp4"
	realPath := "/encrypt/movie.bin"
	userAHeaders := authHeader("Bearer user-a")
	userAScope := rawURLAuthScope(userAHeaders)
	fileDAO.SetEncPathMapping(displayPath, realPath)
	if err := fileDAO.Set(&dao.FileInfo{
		Path:              displayPath,
		EncryptedPath:     realPath,
		Size:              4096,
		RawURL:            "https://cdn.example/user-a",
		RawURLAuthScope:   userAScope,
		UpstreamFetchedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed user A cache: %v", err)
	}

	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":403}`))
	}))
	defer upstream.Close()

	result := fetchRawURL(
		context.Background(),
		upstream.URL,
		displayPath,
		realPath,
		authHeader("Bearer user-b"),
		fileDAO,
		30*time.Minute,
	)
	if result.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403; result=%+v", result.StatusCode, result)
	}
	cached, ok := fileDAO.Get(displayPath)
	if !ok || cached == nil {
		t.Fatal("user B failure removed user A cache entry")
	}
	if cached.RawURL != "https://cdn.example/user-a" || cached.RawURLAuthScope != userAScope || cached.Size != 4096 {
		t.Fatalf("user A cache was changed by user B failure: %+v", cached)
	}
	if encryptedPath, ok := fileDAO.GetEncPath(displayPath); !ok || encryptedPath != realPath {
		t.Fatalf("encrypted mapping=%q ok=%v, want %q", encryptedPath, ok, realPath)
	}
}
