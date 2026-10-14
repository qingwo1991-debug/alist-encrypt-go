package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/gin-gonic/gin"
)

func TestProtectedMutationRealRouteFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var calls atomic.Int64
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		seen <- r.URL.Path
		w.WriteHeader(204)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	port, _ := strconv.Atoi(u.Port())
	cfg := config.DefaultConfig()
	cfg.AlistServer.ServerHost, cfg.AlistServer.ServerPort = u.Hostname(), port
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100}
	p := handler.NewProxyHandler(cfg, nil, nil, nil, nil, nil)
	defer p.Stop()
	d := handler.NewWebDAVHandler(cfg, proxy.NewStreamProxy(cfg), nil, nil, nil, nil, nil)
	defer d.Stop()
	s := &Server{cfg: cfg}
	r := gin.New()
	s.registerRoutes(r, &handler.APIHandler{}, p, &handler.AlistHandler{}, d, &handler.StatsHandler{})
	for _, tc := range []struct{ method, path string }{
		{"POST", "/api/fs/form"}, {"POST", "/api/fs/batch_rename"},
		{"POST", "/api/fs/recursive_move"}, {"POST", "/api/fs/other"},
		{"POST", "/api/fs/mkdir"}, {"GET", "/api/fs/rename"},
		{"POST", "/api/fs/put"}, {"PATCH", "/api/fs/get"},
		{"POST", "/api/fs/../fs/form"}, {"MKCOL", "/dav/mount/protected/new"},
		{"PROPPATCH", "/dav/mount/protected/file"},
		{"MOVE", "/dav/mount/protected/file"}, {"COPY", "/dav/mount/protected/file"},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "http://example.com"+tc.path, strings.NewReader(`{"path":"/mount/protected/file"}`))
			req.Header.Set("Destination", "/dav/outside/file")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("route bypass status=%d body=%s", rec.Code, rec.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatal("refused operation reached actual upstream")
			}
		})
	}
	// Double-encoded route characters are literal storage values. They must
	// remain literal at the actual upstream, not become protected fs methods.
	for _, tc := range []struct{ method, encoded, literal string }{
		{"POST", "/api/%2566s/form", "/api/%66s/form"},
		{"MKCOL", "/dav/mount/%2570rotected/a", "/dav/mount/%70rotected/a"},
		{"PROPPATCH", "/dav/mount/protected%3Foutside/../safe", "/dav/mount/protected?outside/../safe"},
		{"MKCOL", "/dav/mount/literal%23tail", "/dav/mount/literal#tail"},
	} {
		t.Run(tc.method+tc.encoded, func(t *testing.T) {
			before := calls.Load()
			req := httptest.NewRequest(tc.method, "http://example.com"+tc.encoded, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != 204 || calls.Load() != before+1 {
				t.Fatalf("literal operation status=%d calls=%d body=%s", rec.Code, calls.Load(), rec.Body.String())
			}
			if got := <-seen; got != tc.literal {
				t.Fatalf("actual upstream path=%q want=%q", got, tc.literal)
			}
		})
	}
}
