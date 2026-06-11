package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestHandleProxyLimitsTextRewriteBody(t *testing.T) {
	oldLimit := maxProxyResponseBody
	maxProxyResponseBody = 32
	t.Cleanup(func() {
		maxProxyResponseBody = oldLimit
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(strings.Repeat("x", 64)))
	}))
	t.Cleanup(upstream.Close)

	parsed, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse upstream port: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.AlistServer.HTTPS = parsed.Scheme == "https"
	cfg.AlistServer.ServerHost = parsed.Hostname()
	cfg.AlistServer.ServerPort = port

	handler := newTestProxyHandler(t, cfg)
	req := httptest.NewRequest(http.MethodGet, "/index.html", nil)
	rec := httptest.NewRecorder()

	handler.HandleProxy(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusBadGateway)
	}
}
