package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/gin-gonic/gin"
)

func TestCORSMiddlewareAllowsWebDAVOptionsToReachHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware())
	r.OPTIONS("/dav/*path", func(c *gin.Context) {
		c.Header("DAV", "1, 2")
		c.Header("Allow", "OPTIONS, PROPFIND")
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodOptions, "/dav/library", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNoContent)
	}
	if got := rr.Header().Get("DAV"); got != "1, 2" {
		t.Fatalf("DAV header=%q", got)
	}
	if got := rr.Header().Get("Allow"); got != "OPTIONS, PROPFIND" {
		t.Fatalf("Allow header=%q", got)
	}
}

func TestCORSMiddlewareStillHandlesNonWebDAVOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware())
	r.OPTIONS("/api/ping", func(c *gin.Context) {
		t.Fatal("handler should not be reached for non-WebDAV OPTIONS")
	})

	req := httptest.NewRequest(http.MethodOptions, "/api/ping", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusOK)
	}
}

func TestCORSMiddlewareDoesNotReflectCrossOriginEncAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware())
	r.OPTIONS("/enc-api/getStats", func(c *gin.Context) {
		t.Fatal("handler should not be reached for preflight")
	})

	req := httptest.NewRequest(http.MethodOptions, "http://proxy.local/enc-api/getStats", nil)
	req.Header.Set("Origin", "https://evil.example")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusOK)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin=%q, want empty", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("Access-Control-Allow-Credentials=%q, want empty", got)
	}
}

func TestCORSMiddlewareAllowsSameOriginEncAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(CORSMiddleware())
	r.OPTIONS("/enc-api/getStats", func(c *gin.Context) {
		t.Fatal("handler should not be reached for preflight")
	})

	req := httptest.NewRequest(http.MethodOptions, "http://proxy.local/enc-api/getStats", nil)
	req.Header.Set("Origin", "https://proxy.local")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://proxy.local" {
		t.Fatalf("Access-Control-Allow-Origin=%q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("Access-Control-Allow-Credentials=%q", got)
	}
}

func TestAuthMiddlewareStoresTokenWithoutMutatingRequestHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "test-secret"
	token, err := auth.NewJWTAuth(secret, time.Hour).GenerateToken("admin")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	r := gin.New()
	r.Use(AuthMiddleware(secret, 48))
	r.GET("/enc-api/getStats", func(c *gin.Context) {
		if got := c.Request.Header.Get("X-User-Token"); got != "" {
			t.Fatalf("X-User-Token header=%q, want empty", got)
		}
		if got, ok := c.Get("user_token"); !ok || got != token {
			t.Fatalf("context token=%v ok=%v", got, ok)
		}
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/enc-api/getStats", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNoContent)
	}
}
