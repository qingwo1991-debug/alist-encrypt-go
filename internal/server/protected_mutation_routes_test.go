package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

func TestProtectedMutationRealRouteFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.DefaultConfig()
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/mount/protected": 100}
	p := handler.NewProxyHandler(cfg, nil, nil, nil, nil, nil)
	defer p.Stop()
	d := handler.NewWebDAVHandler(cfg, nil, nil, nil, nil, nil, nil)
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
		})
	}
}
