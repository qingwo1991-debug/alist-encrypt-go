package encrypt

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func h2cPoolConfig(t *testing.T, rawURL string) *ProxyConfig {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.EnableH2C = true
	cfg.AlistHost = u.Hostname()
	cfg.AlistPort = port
	cfg.EnableDualNetwork = false
	return cfg
}

func TestRoutePoolH2CBackendOnlyAndMediaHTTP1(t *testing.T) {
	srv := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", strconv.Itoa(r.ProtoMajor))
		_, _ = io.WriteString(w, "ok")
	}), &http2.Server{}))
	defer srv.Close()
	cfg := h2cPoolConfig(t, srv.URL)
	pool := newRouteTransportPool(cfg, nil, nil, true)
	defer pool.RetireRouteTransports()
	pool.resolver = func(*http.Request) (*url.URL, error) { return nil, nil }
	for _, tc := range []struct {
		profile string
		want    string
	}{{"control", "2"}, {"probe", "2"}, {"media", "1"}} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := pool.roundTrip(req, tc.profile)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if got := resp.Header.Get("X-Proto"); got != tc.want {
			t.Fatalf("%s proto=%s want=%s", tc.profile, got, tc.want)
		}
	}
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Proto", strconv.Itoa(r.ProtoMajor)) }))
	defer foreign.Close()
	req, _ := http.NewRequest(http.MethodGet, foreign.URL, nil)
	resp, err := pool.roundTrip(req, "control")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Proto") != "1" {
		t.Fatal("foreign target incorrectly enabled H2C")
	}
}

func TestRoutePoolH2CProxyCannotBypass(t *testing.T) {
	var originCalls atomic.Int32
	origin := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originCalls.Add(1) }), &http2.Server{}))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proxy", "yes")
		w.Header().Set("X-Proto", strconv.Itoa(r.ProtoMajor))
	}))
	defer proxy.Close()
	cfg := h2cPoolConfig(t, origin.URL)
	pool := newRouteTransportPool(cfg, nil, nil, true)
	defer pool.RetireRouteTransports()
	proxyURL, _ := url.Parse(proxy.URL)
	pool.resolver = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	// Use a non-control host with a private test resolver so the explicit proxy
	// policy remains selected; origin host must match the configured backend.
	cfgHost := "backend.example"
	pool.config.AlistHost = cfgHost
	target := strings.Replace(origin.URL, "127.0.0.1", cfgHost, 1)
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	decision := providerRouteDecision{proxy: proxyURL}
	if pool.useH2C(req, "control", decision) {
		t.Fatal("proxied backend eligible for H2C")
	}
	// Mark it non-control for policy evaluation: the response must come from the
	// proxy without the direct origin being contacted.
	pool.config.AlistHost = "other.example"
	pool.config.EnableLocalBypass = false
	resp, err := pool.roundTrip(req, "control")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Proxy") != "yes" || resp.Header.Get("X-Proto") != "1" || originCalls.Load() != 0 {
		t.Fatal("H2C bypassed explicit proxy decision")
	}
}

func TestRoutePoolH2CFallbackOnlyBodylessGet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Proto", strconv.Itoa(r.ProtoMajor)) }))
	defer srv.Close()
	cfg := h2cPoolConfig(t, srv.URL)
	pool := newRouteTransportPool(cfg, nil, nil, true)
	defer pool.RetireRouteTransports()
	pool.resolver = func(*http.Request) (*url.URL, error) { return nil, nil }
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	resp, err := pool.roundTrip(req, "control")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("X-Proto") != "1" {
		t.Fatal("missing HTTP/1 fallback")
	}
	var h1Calls atomic.Int32
	entry := &routeTransportEntry{transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		h1Calls.Add(1)
		return nil, io.ErrUnexpectedEOF
	}}, h2c: &http2.Transport{AllowHTTP: true, DialTLSContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) { return nil, io.ErrUnexpectedEOF }}}
	defer entry.closeIdleConnections()
	post, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	if _, err := entry.roundTrip(post); err == nil {
		t.Fatal("POST failure missing")
	}
	if h1Calls.Load() != 0 {
		t.Fatal("POST was replayed via HTTP/1")
	}
}

func TestRoutePoolH2CNativeDNSBindSameSnapshot(t *testing.T) {
	srv := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proto", strconv.Itoa(r.ProtoMajor))
		_, _ = io.WriteString(w, "ok")
	}), &http2.Server{}))
	defer srv.Close()
	old := SnapshotNativeRoutes()
	defer func() { nativeRoutes.Lock(); nativeRoutes.snapshot = old; nativeRoutes.Unlock() }()
	bridge := &fakeNativeBridge{payload: `{"status":"ok","addresses":["127.0.0.1"]}`}
	nativeRoutes.Lock()
	nativeRoutes.snapshot = NativeRouteSnapshot{Bridge: bridge, DefaultToken: "h2c-default", Generation: old.Generation + 1}
	nativeRoutes.Unlock()
	target := strings.Replace(srv.URL, "127.0.0.1", "h2c.example", 1)
	cfg := h2cPoolConfig(t, target)
	pool := newRouteTransportPool(cfg, nil, nil, true)
	defer pool.RetireRouteTransports()
	pool.resolver = func(*http.Request) (*url.URL, error) { return nil, nil }
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	resp, err := pool.roundTrip(req, "control")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.Header.Get("X-Proto") != "2" {
		t.Fatal("native H2C not restored")
	}
	bridge.mu.Lock()
	tokens := append([]string(nil), bridge.tokens...)
	bridge.mu.Unlock()
	if len(tokens) != 2 || tokens[0] != "h2c-default" || tokens[1] != "h2c-default" {
		t.Fatalf("native DNS/bind snapshot mismatch: %v", tokens)
	}
}
