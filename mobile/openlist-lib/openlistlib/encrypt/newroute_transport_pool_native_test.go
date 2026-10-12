package encrypt

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestNativeRoutePoolProviderTokensAndGeneration(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer origin.Close()
	old := SnapshotNativeRoutes()
	defer func() { nativeRoutes.Lock(); nativeRoutes.snapshot = old; nativeRoutes.Unlock() }()
	bridge := &fakeNativeBridge{payload: `{"status":"ok","addresses":["127.0.0.1"]}`}
	cfg := DefaultConfig()
	cfg.EnableDualNetwork = true
	cfg.EnableLocalBypass = false
	cfg.ProviderRoutingRules = []ProviderRoutingRule{{Enabled: true, MatchType: routingMatchProvider, MatchValue: "A", Action: routingActionDirect}, {Enabled: true, MatchType: routingMatchProvider, MatchValue: "B", Action: routingActionProxy}}
	nativeRoutes.Lock()
	nativeRoutes.snapshot = NativeRouteSnapshot{Bridge: bridge, DefaultToken: "vpn-1", PhysicalToken: "wifi-1", Generation: old.Generation + 1}
	nativeRoutes.Unlock()
	pool := newRouteTransportPool(cfg, &http.Transport{}, &http.Transport{})
	defer pool.RetireRouteTransports()
	pool.resolver = func(*http.Request) (*url.URL, error) { return nil, nil }
	target := strings.Replace(origin.URL, "127.0.0.1", "route.example", 1)
	for _, provider := range []string{"A", "B", "A"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("X-Encrypt-Provider", provider)
		resp, err := pool.roundTrip(req, "media")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	bridge.mu.Lock()
	tokens := append([]string(nil), bridge.tokens...)
	bridge.mu.Unlock()
	if len(tokens) != 4 || tokens[0] != "wifi-1" || tokens[1] != "wifi-1" || tokens[2] != "vpn-1" || tokens[3] != "vpn-1" {
		t.Fatalf("DNS/bind token mismatch %v", tokens)
	}
	nativeRoutes.Lock()
	nativeRoutes.snapshot.Generation++
	nativeRoutes.snapshot.PhysicalToken = "wifi-2"
	nativeRoutes.Unlock()
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Encrypt-Provider", "A")
	resp, err := pool.roundTrip(req, "media")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	bridge.mu.Lock()
	tokens = append([]string(nil), bridge.tokens...)
	bridge.mu.Unlock()
	if len(tokens) != 6 || tokens[4] != "wifi-2" || tokens[5] != "wifi-2" {
		t.Fatalf("generation reused old connection %v", tokens)
	}
	pool.mu.Lock()
	count := len(pool.entries)
	pool.mu.Unlock()
	if count != 1 {
		t.Fatalf("old idle generation retained %d", count)
	}
	// Simulate replacing the native runtime without changing a published
	// topology generation: bridge identity must still prohibit connection reuse.
	replacement := &fakeNativeBridge{payload: `{"status":"ok","addresses":["127.0.0.1"]}`}
	nativeRoutes.Lock()
	nativeRoutes.snapshot.Bridge = replacement
	nativeRoutes.snapshot.BridgeEpoch++
	nativeRoutes.Unlock()
	req, _ = http.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("X-Encrypt-Provider", "A")
	resp, err = pool.roundTrip(req, "media")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	replacement.mu.Lock()
	calls := append([]string(nil), replacement.events...)
	replacement.mu.Unlock()
	if len(calls) != 2 || calls[0] != "dns" || calls[1] != "bind" {
		t.Fatalf("replacement reused old bridge connection: %v", calls)
	}
	pool.mu.Lock()
	count = len(pool.entries)
	pool.mu.Unlock()
	if count != 1 {
		t.Fatalf("old idle bridge retained %d", count)
	}
}

func TestNativePhysicalMissingDoesNotFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EnableDualNetwork = true
	cfg.EnableLocalBypass = false
	cfg.RoutingUnmatchedDefault = routingActionDirect
	req, _ := http.NewRequest(http.MethodGet, "http://route.example/", nil)
	_, err := EvaluateProviderPolicy(cfg, req, NativeRouteSnapshot{Bridge: &fakeNativeBridge{}}, func(*http.Request) (*url.URL, error) { return nil, nil })
	if !errors.Is(err, ErrNativeRouteUnavailable) {
		t.Fatalf("missing physical silently fell back: %v", err)
	}
}
