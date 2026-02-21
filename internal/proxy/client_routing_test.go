package proxy

import (
	"net/http"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestProxyFuncRulesMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Proxy.Mode = "rules"
	cfg.Proxy.URL = "http://127.0.0.1:7890"
	cfg.Proxy.NoProxy = []string{"example.com"}
	cfg.Proxy.Rules = []config.ProxyRule{
		{
			ID:        "google",
			MatchType: "domain_suffix",
			Pattern:   "googleapis.com",
			Action:    "proxy",
			Enabled:   true,
			Priority:  1,
		},
	}
	cfg.Proxy.MaxIdleConns = 100
	cfg.Proxy.MaxIdleConnsPerHost = 100
	cfg.Proxy.MaxConnsPerHost = 100
	cfg.Proxy.IdleConnTimeout = 90
	cfg.Proxy.DialTimeoutSeconds = 30
	cfg.Proxy.TLSHandshakeSeconds = 10
	cfg.Proxy.ResponseHeaderSecs = 15

	fn := proxyFunc(cfg)
	req, _ := http.NewRequest(http.MethodGet, "https://www.googleapis.com/drive/v3/files", nil)
	route, err := fn(req)
	if err != nil {
		t.Fatalf("proxyFunc returned error: %v", err)
	}
	if route == nil || route.Host != "127.0.0.1:7890" {
		t.Fatalf("expected proxy route, got %#v", route)
	}

	noProxyReq, _ := http.NewRequest(http.MethodGet, "https://cdn.example.com/file", nil)
	route, err = fn(noProxyReq)
	if err != nil {
		t.Fatalf("proxyFunc no-proxy returned error: %v", err)
	}
	if route != nil {
		t.Fatalf("expected direct route for no_proxy host, got %#v", route)
	}

	internalReq, _ := http.NewRequest(http.MethodGet, "http://openalist:5244/api/fs/list", nil)
	route, err = fn(internalReq)
	if err != nil {
		t.Fatalf("proxyFunc internal returned error: %v", err)
	}
	if route != nil {
		t.Fatalf("expected direct route for internal host, got %#v", route)
	}
}

func TestProxyFuncFixedMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Proxy.Mode = "fixed"
	cfg.Proxy.URL = "http://127.0.0.1:7890"
	cfg.Proxy.NoProxy = []string{"192.168.0.0/16"}
	cfg.Proxy.MaxIdleConns = 100
	cfg.Proxy.MaxIdleConnsPerHost = 100
	cfg.Proxy.MaxConnsPerHost = 100
	cfg.Proxy.IdleConnTimeout = 90
	cfg.Proxy.DialTimeoutSeconds = 30
	cfg.Proxy.TLSHandshakeSeconds = 10
	cfg.Proxy.ResponseHeaderSecs = 15

	fn := proxyFunc(cfg)
	proxyReq, _ := http.NewRequest(http.MethodGet, "https://drive.google.com/file", nil)
	route, err := fn(proxyReq)
	if err != nil {
		t.Fatalf("proxyFunc fixed returned error: %v", err)
	}
	if route == nil || route.Host != "127.0.0.1:7890" {
		t.Fatalf("expected proxy route, got %#v", route)
	}

	directReq, _ := http.NewRequest(http.MethodGet, "http://192.168.1.20:8080/test", nil)
	route, err = fn(directReq)
	if err != nil {
		t.Fatalf("proxyFunc fixed cidr returned error: %v", err)
	}
	if route != nil {
		t.Fatalf("expected direct route for private cidr, got %#v", route)
	}
}
