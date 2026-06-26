//go:build !noembedwebui

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"

	"github.com/gin-gonic/gin"
)

func TestSetupWebUIRoutesEmbeddedBuildRedirectsIndex(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := &Server{}
	r := gin.New()
	s.setupWebUIRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusFound)
	}
	if got := rr.Header().Get("Location"); got != "/public/index.html" {
		t.Fatalf("location=%q, want %q", got, "/public/index.html")
	}
}

func TestGetBuildInfoRouteIsPublic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.JWTSecret = "test-secret"

	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })

	req := httptest.NewRequest(http.MethodGet, "/enc-api/getBuildInfo", nil)
	rr := httptest.NewRecorder()
	s.engine.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
}
