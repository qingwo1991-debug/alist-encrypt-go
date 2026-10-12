package encrypt

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestRoutePoolSameOriginProviderProxyIsolation(t *testing.T) {
	var originCalls, proxyCalls atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originCalls.Add(1); _, _ = io.WriteString(w, "origin") }))
	defer origin.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1); _, _ = io.WriteString(w, "proxy") }))
	defer proxy.Close()
	proxyURL, _ := url.Parse(proxy.URL)
	cfg := DefaultConfig()
	// This fixture intentionally tests proxy routing to a loopback origin;
	// disable the production local-host exemption rather than weaken isolation.
	cfg.EnableLocalBypass = false
	pool := newRouteTransportPool(cfg, &http.Transport{}, &http.Transport{})
	defer pool.RetireRouteTransports()
	pool.resolver = func(r *http.Request) (*url.URL, error) {
		if r.Header.Get("X-Encrypt-Provider") == "B" {
			return proxyURL, nil
		}
		return nil, nil
	}
	client := http.Client{Transport: &routePoolRoundTripper{pool: pool, profile: "media"}}
	for _, provider := range []string{"A", "B", "A", "B"} {
		req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
		req.Header.Set("X-Encrypt-Provider", provider)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		want := "origin"
		if provider == "B" {
			want = "proxy"
		}
		if string(data) != want {
			t.Fatalf("provider %s got %q", provider, data)
		}
	}
	if originCalls.Load() != 2 || proxyCalls.Load() != 2 {
		t.Fatalf("origin=%d proxy=%d", originCalls.Load(), proxyCalls.Load())
	}
	pool.mu.Lock()
	count := len(pool.entries)
	pool.mu.Unlock()
	if count != 2 {
		t.Fatalf("pool entries %d", count)
	}
}

func TestRoutePoolActiveBodyCapacityAndRetirement(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		_, _ = io.WriteString(w, "hello")
	}))
	defer origin.Close()
	pool := newRouteTransportPool(DefaultConfig(), &http.Transport{}, &http.Transport{})
	pool.limit = 1
	req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	first, err := pool.roundTrip(req, "media")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.roundTrip(req, "control"); !errors.Is(err, ErrRoutePoolBusy) {
		t.Fatalf("active pool admitted: %v", err)
	}
	pool.RetireRouteTransports()
	data, err := io.ReadAll(first.Body)
	first.Body.Close()
	first.Body.Close()
	if err != nil || string(data) != "hello" {
		t.Fatalf("retirement killed active body %q %v", data, err)
	}
	pool.mu.Lock()
	count := len(pool.entries)
	pool.mu.Unlock()
	if count != 0 {
		t.Fatalf("retired entry leaked: %d", count)
	}
}

func TestRoutePoolIdleLRUCapacity(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	pool := newRouteTransportPool(DefaultConfig(), &http.Transport{}, &http.Transport{})
	pool.limit = 2
	defer pool.RetireRouteTransports()
	for _, profile := range []string{"control", "probe", "media", "control"} {
		req, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
		resp, err := pool.roundTrip(req, profile)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		pool.mu.Lock()
		count := len(pool.entries)
		pool.mu.Unlock()
		if count > 2 {
			t.Fatalf("capacity %d", count)
		}
	}
}
