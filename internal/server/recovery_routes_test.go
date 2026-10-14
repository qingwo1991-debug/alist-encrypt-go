package server

import (
	"github.com/alist-encrypt-go/internal/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/recovery"
	"github.com/gin-gonic/gin"
)

func TestRecoveryMutationRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer upstream.Close()
	cfg := config.DefaultConfig()
	u, _ := url.Parse(upstream.URL)
	port, _ := strconv.Atoi(u.Port())
	cfg.AlistServer.ServerHost, cfg.AlistServer.ServerPort = u.Hostname(), port
	// Even a real loopback upstream must receive no refused operations.
	cfg.DataDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, recovery.SidecarName), []byte(`{"version":999}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.BindRecoveryState(recovery.Load(cfg.DataDir))
	p := handler.NewProxyHandler(cfg, nil, nil, nil, nil, nil)
	defer p.Stop()
	d := handler.NewWebDAVHandler(cfg, proxy.NewStreamProxy(cfg), nil, nil, nil, nil, nil)
	defer d.Stop()
	a := handler.NewAlistHandler(cfg, nil, nil, nil, p, nil, nil)
	defer a.Stop()
	s := &Server{cfg: cfg}
	r := gin.New()
	s.registerRoutes(r, &handler.APIHandler{}, p, a, d, &handler.StatsHandler{})
	for _, limits := range []map[string]int{{"/protected": 100}, nil} {
		cfg.AlistServer.FilenameWriteLimits = limits
		for _, tc := range []struct{ method, path string }{
			{"PUT", "/api/fs/put"}, {"POST", "/api/fs/remove"}, {"POST", "/api/fs/rename"}, {"POST", "/api/fs/move"}, {"POST", "/api/fs/copy"},
			{"PUT", "/dav/raw/short.bin"}, {"DELETE", "/dav/raw/file"}, {"MKCOL", "/dav/outside/new"}, {"MOVE", "/dav/outside/file"}, {"COPY", "/dav/outside/file"}, {"PROPPATCH", "/dav/raw/file"}, {"LOCK", "/dav/raw/file"}, {"UNLOCK", "/dav/raw/file"},
			{"POST", "/api/fs/form"}, {"POST", "/api/fs/batch_rename"}, {"GET", "/api/task/offline_download/add"}, {"POST", "/api/admin/storage/update"}, {"POST", "/api/fs/other"}, {"PATCH", "/unknown"}, {"GET", "/unknown"},
		} {
			req := httptest.NewRequest(tc.method, "http://example.com"+tc.path, strings.NewReader(`{}`))
			req.Header.Set("File-Path", "/raw/short.bin")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != 503 || !strings.Contains(rec.Body.String(), "recovery_reconciliation_required") {
				t.Fatalf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("refused request reached upstream")
	}
	read := httptest.NewRecorder()
	r.ServeHTTP(read, httptest.NewRequest("POST", "http://example.com/api/fs/dirs", strings.NewReader(`{}`)))
	if read.Code != 204 || calls.Load() != 1 {
		t.Fatalf("known read changed: %d calls=%d", read.Code, calls.Load())
	}
	req := httptest.NewRequest("GET", "http://example.com/enc-api/admin/reconciliation-status", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status lacks JWT protection: %d", rec.Code)
	}
	token, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("admin")
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "http://example.com/enc-api/admin/reconciliation-status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"required":true`) {
		t.Fatalf("authenticated status: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), cfg.DataDir) {
		t.Fatal("status leaked path")
	}
}
