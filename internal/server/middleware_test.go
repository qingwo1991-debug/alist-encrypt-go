package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
