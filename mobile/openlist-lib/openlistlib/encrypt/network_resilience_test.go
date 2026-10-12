package encrypt

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestDualNetworkRuntimeToggleAndBindingFallback(t *testing.T) {
	SetEncryptDualNetworkMarks(0, 0, false)
	defer SetEncryptDualNetworkMarks(0, 0, false)
	original := setDualNetworkSocketMark
	defer func() { setDualNetworkSocketMark = original }()
	calls := 0
	setDualNetworkSocketMark = func(int, uint32) error { calls++; return syscall.EPERM }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Constructed while disabled: it must still observe later enabled state.
	dial := newDualNetworkDialer(&net.Dialer{Timeout: time.Second})
	host, _, _ := net.SplitHostPort(listener.Addr().String())
	putHint := func(mark uint32) { hostMarkHint.mu.Lock(); hostMarkHint.hints[host] = mark; hostMarkHint.mu.Unlock() }
	connect := func() {
		t.Helper()
		conn, err := dial(context.Background(), "tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	putHint(123)
	connect()
	if calls != 0 {
		t.Fatal("disabled path applied SO_MARK")
	}
	SetEncryptDualNetworkMarks(123, 456, true)
	putHint(123)
	connect()
	connect()
	if calls != 1 {
		t.Fatalf("failed mark should be suppressed after one fallback: %d", calls)
	}
	var status map[string]interface{}
	if err := json.Unmarshal([]byte(GetEncryptDualNetworkStatusJson()), &status); err != nil {
		t.Fatal(err)
	}
	if status["binding_status"] != "default-route-fallback" || status["last_bind_error"] == nil {
		t.Fatalf("fallback not observable: %v", status)
	}
	SetEncryptDualNetworkMarks(321, 654, true)
	if hostMarkFromAddr(listener.Addr().String()) != 0 {
		t.Fatal("old host mark survived topology change")
	}
	putHint(123) // Even a stale racing hint cannot bind a departed mark.
	connect()
	if calls != 1 {
		t.Fatal("departed mark reused")
	}
	SetEncryptDualNetworkMarks(0, 0, false)
	connect()
}

func TestNetworkNotificationRetiresIdlePool(t *testing.T) {
	var connections atomic.Int32
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	upstream.Start()
	defer upstream.Close()
	transport := &http.Transport{}
	trackNetworkTransport(transport, true)
	defer trackNetworkTransport(transport, false)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	fetch := func() {
		t.Helper()
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	fetch()
	fetch()
	if connections.Load() != 1 {
		t.Fatal("test did not reuse idle connection")
	}
	SetEncryptDualNetworkMarks(0, 0, false) // Android same-type topology change.
	fetch()
	if connections.Load() != 2 {
		t.Fatal("old idle pool survived connectivity notification")
	}
}

func TestNetworkChangeClearsRoutingEvidence(t *testing.T) {
	previous := GetNetworkState()
	defer SetNetworkState(string(previous))
	SetNetworkState("wifi")
	globalDualNetworkLatency.recordPassive("example", "cdn.example", time.Millisecond)
	directProbeCache.Store("cdn.example", &directProbeState{reachable: true, at: time.Now()})
	hostMarkHint.mu.Lock()
	hostMarkHint.hints["cdn.example"] = 42
	hostMarkHint.mu.Unlock()
	SetNetworkState("cellular")
	if hostMarkFromAddr("cdn.example:443") != 0 || directProbeCacheCount() != 0 {
		t.Fatal("stale route evidence")
	}
	globalDualNetworkLatency.mu.Lock()
	count := len(globalDualNetworkLatency.entries)
	globalDualNetworkLatency.mu.Unlock()
	if count != 0 {
		t.Fatal("stale latency")
	}
}

func TestResolverDualNetworkConfigGateAndDefaultBypass(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")
	t.Setenv("NO_PROXY", "")
	SetEncryptDualNetworkMarks(123, 456, true)
	defer SetEncryptDualNetworkMarks(0, 0, false)
	cfg := &ProxyConfig{AlistHost: "127.0.0.1", EnableLocalBypass: true, RoutingMode: routingModeByProvider, RoutingUnmatchedDefault: routingActionDirect}
	resolver := newProxyResolverWithProbe(cfg, func(string) bool { t.Fatal("unexpected active probe"); return false })
	for _, target := range []string{"http://127.0.0.1:5244/api/fs/list", "http://192.168.1.10/file", "https://cdn.example/file"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		proxy, err := resolver(req)
		if proxy != nil || err != nil {
			t.Fatalf("default bypass %s: %v %v", target, proxy, err)
		}
		if hostMarkFromAddr(req.URL.Hostname()+":443") != 0 {
			t.Fatal("disabled config installed mark")
		}
	}
	cfg.EnableDualNetwork = true
	resolver = newProxyResolverWithProbe(cfg, nil)
	req, _ := http.NewRequest(http.MethodGet, "https://cdn.example/file", nil)
	_, _ = resolver(req) // Empty provider means no active probe.
	if hostMarkFromAddr("cdn.example:443") != 123 {
		t.Fatal("enabled config did not install routing hint")
	}
	cfg.EnableDualNetwork = false
	invalidateNetworkRouting()
	resolver = newProxyResolverWithProbe(cfg, nil)
	_, _ = resolver(req)
	if hostMarkFromAddr("cdn.example:443") != 0 {
		t.Fatal("disabled config retained routing hint")
	}
}

func TestDualNetworkUnsupportedStatus(t *testing.T) {
	SetEncryptDualNetworkMarks(0, 0, false)
	var status map[string]interface{}
	if err := json.Unmarshal([]byte(GetEncryptDualNetworkStatusJson()), &status); err != nil {
		t.Fatal(err)
	}
	if status["binding_status"] != "unsupported" || status["enabled"] != false {
		t.Fatalf("unsupported capability hidden: %v", status)
	}
}

func TestStreamTransportUpdateRetainsBudgetAndDialConfig(t *testing.T) {
	p := &ProxyServer{transport: &http.Transport{}, streamTransport: &http.Transport{}}
	defer func() { trackNetworkTransport(p.transport, false); trackNetworkTransport(p.streamTransport, false) }()
	for _, secs := range []int{5, 60, 600} {
		p.UpdateConfig(&ProxyConfig{UpstreamTimeoutSeconds: secs})
		if p.streamTransport.ResponseHeaderTimeout != streamHeaderBudget(p.config) || p.streamTransport.ResponseHeaderTimeout > 7*time.Second {
			t.Fatal("stream header cap lost on reload")
		}
		if p.streamTransport.DialContext == nil || p.transport.DialContext == nil {
			t.Fatal("dial callback not refreshed")
		}
		if p.streamClient.Timeout != 0 {
			t.Fatal("video body has wall-clock timeout")
		}
	}
}
