package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/gin-gonic/gin"
)

// These exercise the production router, not a test-only protected group. In
// particular, neither public fs/other nor the catch-all proxy may expose WoPan
// administrator operations. Every upstream here is a local mock.
func TestWopanManagementRoutesRequireLocalAdministratorSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	port, _ := strconv.Atoi(u.Port())
	cfg := config.DefaultConfig()
	cfg.JWTSecret = "wopan-test-local-manager-secret"
	cfg.AlistServer.ServerHost, cfg.AlistServer.ServerPort = u.Hostname(), port
	p := handler.NewProxyHandler(cfg, nil, nil, nil, nil, nil)
	defer p.Stop()
	d := handler.NewWebDAVHandler(cfg, proxy.NewStreamProxy(cfg), nil, nil, nil, nil, nil)
	defer d.Stop()
	s := &Server{cfg: cfg}
	router := gin.New()
	s.registerRoutes(router, &handler.APIHandler{}, p, &handler.AlistHandler{}, d, &handler.StatsHandler{})
	local, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("deleted-local-admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/enc-api/wopan/storages"},
		{http.MethodGet, "/enc-api/wopan/quota?storage_id=5"},
		{http.MethodPost, "/enc-api/wopan/recycle/prepare"},
		{http.MethodPost, "/enc-api/wopan/recycle/clear"},
	} {
		for _, credential := range []string{"missing", "upstream-basic", "invalid-local", "query-token", "no-current-user"} {
			t.Run(route.path+"/"+credential, func(t *testing.T) {
				path := route.path
				if credential == "query-token" {
					separator := "?"
					if strings.Contains(path, "?") {
						separator = "&"
					}
					path += separator + "token=" + url.QueryEscape(local)
				}
				req := httptest.NewRequest(route.method, "http://manager.invalid"+path, strings.NewReader(`{"storage_id":5,"confirmation_token":"not-a-live-token","confirmation_phrase":"清空个人账号全部回收站"}`))
				req.Header.Set("Content-Type", "application/json")
				switch credential {
				case "upstream-basic":
					req.SetBasicAuth("owner", "not-a-live-password")
				case "invalid-local":
					req.Header.Set("Authorizetoken", "not-a-local-jwt")
				case "no-current-user":
					req.Header.Set("Authorizetoken", local)
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
					t.Fatalf("expected authentication rejection, status=%d body=%s", rec.Code, rec.Body.String())
				}
				if calls.Load() != 0 {
					t.Fatal("rejected management request contacted upstream")
				}
			})
		}
	}
}
