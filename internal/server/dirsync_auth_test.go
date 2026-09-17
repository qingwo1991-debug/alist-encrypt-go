package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

func TestDirSyncRoutesRequireJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "synthetic-test-secret"
	s := &Server{cfg: &config.Config{JWTSecret: secret, JWTExpire: 1}}
	r := gin.New()
	// Register the real route table without creating stores or background work.
	s.registerRoutes(r, &handler.APIHandler{}, &handler.ProxyHandler{}, &handler.AlistHandler{}, &handler.WebDAVHandler{}, &handler.StatsHandler{})
	token, err := auth.NewJWTAuth(secret, time.Hour).GenerateToken("synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path     string
		authorizedStatus int
	}{
		{http.MethodGet, "/api/encrypt/dir-sync/overview", http.StatusOK},
		{http.MethodPost, "/api/encrypt/dir-sync/run", http.StatusBadRequest}, // scan not configured
	} {
		for _, header := range []string{"", "Authorization", "Authorizetoken"} {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			want := http.StatusUnauthorized
			if header != "" {
				value := token
				if header == "Authorization" {
					value = "Bearer " + token
				}
				req.Header.Set(header, value)
				want = tc.authorizedStatus
			}
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)
			if rr.Code != want {
				t.Errorf("%s header %q status=%d want %d", tc.path, header, rr.Code, want)
			}
		}
	}
}
