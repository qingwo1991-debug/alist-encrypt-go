package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

func TestCircuitBreakerOriginKey(t *testing.T) {
	tests := []struct {
		raw  string
		want string
		ok   bool
	}{
		{raw: "HTTP://CDN.Example:80/video?id=1", want: "http://cdn.example", ok: true},
		{raw: "https://cdn.example:443/next", want: "https://cdn.example", ok: true},
		{raw: "https://cdn.example:8443/next", want: "https://cdn.example:8443", ok: true},
		{raw: "http://[2001:db8::1]:80/video", want: "http://[2001:db8::1]", ok: true},
		{raw: "/relative/video", ok: false},
		{raw: "://bad", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, ok := circuitBreakerOriginKey(tt.raw)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("circuitBreakerOriginKey(%q) = %q, %v; want %q, %v", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestCircuitBreakerRegistryUsesFallbackForControlPlaneAndInvalidURL(t *testing.T) {
	fallback := backoff.NewGate(1, time.Hour)
	registry := newCircuitBreakerRegistry(fallback, "http://alist.internal:5244", 1, time.Hour)

	for _, target := range []string{
		"http://ALIST.internal:5244/api/fs/get",
		"/relative/path",
		"://bad",
	} {
		if got := registry.gateFor(target); got != fallback {
			t.Fatalf("gateFor(%q) did not use fallback", target)
		}
	}
	if got := registry.gateFor("https://cdn.example/video"); got == fallback {
		t.Fatal("data-plane origin unexpectedly used the control-plane fallback")
	}
}

func TestCircuitBreakerRegistryIsolatesFailedCDNFromNextVideo(t *testing.T) {
	registry := newCircuitBreakerRegistry(backoff.NewGate(1, time.Hour), "http://alist.internal:5244", 1, time.Hour)
	failedCDN := registry.gateFor("https://bad-cdn.example/video-one")
	failedCDN.RecordFailure()

	if failedCDN.Allow() {
		t.Fatal("failed CDN circuit remained closed")
	}
	if registry.gateFor("https://bad-cdn.example/video-two") != failedCDN {
		t.Fatal("paths on the same origin did not share a circuit")
	}
	if !registry.gateFor("https://healthy-cdn.example/next-video").Allow() {
		t.Fatal("failed CDN blocked a healthy next-video origin")
	}
	if !registry.gateFor("http://bad-cdn.example/video-one").Allow() {
		t.Fatal("HTTPS failure leaked into the HTTP origin")
	}
}

func TestCircuitBreakerRegistryEvictsLRUAndExpiresIdleEntries(t *testing.T) {
	fallback := backoff.NewGate(1, time.Hour)
	registry := newCircuitBreakerRegistry(fallback, "", 1, time.Hour)
	registry.maxEntries = 2
	registry.ttl = time.Minute
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }

	registry.gateFor("https://a.example/video")
	now = now.Add(time.Second)
	registry.gateFor("https://b.example/video")
	now = now.Add(time.Second)
	registry.gateFor("https://a.example/seek")
	now = now.Add(time.Second)
	registry.gateFor("https://c.example/video")

	registry.mu.Lock()
	_, hasA := registry.entries["https://a.example"]
	_, hasB := registry.entries["https://b.example"]
	_, hasC := registry.entries["https://c.example"]
	entryCount := len(registry.entries)
	registry.mu.Unlock()
	if !hasA || hasB || !hasC || entryCount != 2 {
		t.Fatalf("LRU entries: a=%v b=%v c=%v count=%d", hasA, hasB, hasC, entryCount)
	}

	now = now.Add(time.Minute)
	registry.gateFor("https://d.example/video")
	registry.mu.Lock()
	_, hasD := registry.entries["https://d.example"]
	entryCount = len(registry.entries)
	registry.mu.Unlock()
	if !hasD || entryCount != 1 {
		t.Fatalf("expired entries were not pruned: d=%v count=%d", hasD, entryCount)
	}
}

func TestCircuitBreakerRegistryConcurrentAccessStaysBounded(t *testing.T) {
	registry := newCircuitBreakerRegistry(backoff.NewGate(3, time.Minute), "", 3, time.Minute)
	registry.maxEntries = 32
	registry.ttl = time.Hour

	const workers = 512
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			gate := registry.gateFor(fmt.Sprintf("https://cdn-%d.example/video", i))
			gate.RecordSuccess()
		}(i)
	}
	close(start)
	wg.Wait()

	registry.mu.Lock()
	entryCount := len(registry.entries)
	registry.mu.Unlock()
	if entryCount > registry.maxEntries {
		t.Fatalf("registry count=%d exceeds max=%d", entryCount, registry.maxEntries)
	}

	want := registry.gateFor("https://shared.example/video")
	wg.Add(workers)
	var mismatches atomic.Int32
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if got := registry.gateFor("https://shared.example/seek"); got != want {
				mismatches.Add(1)
			}
		}()
	}
	wg.Wait()
	if mismatches.Load() != 0 {
		t.Fatalf("same-origin concurrent lookups returned %d different gates", mismatches.Load())
	}
}

func TestProxyRequestCircuitBreakerIsolatesOrigins(t *testing.T) {
	var badCalls atomic.Int32
	var healthyCalls atomic.Int32
	sp := newProxyForRoundTripper(proxyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		status := http.StatusOK
		body := "ok"
		switch req.URL.Hostname() {
		case "bad-cdn.example":
			badCalls.Add(1)
			status = http.StatusServiceUnavailable
			body = "unavailable"
		case "healthy-cdn.example":
			healthyCalls.Add(1)
		default:
			return nil, errors.New("unexpected origin")
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}))
	sp.retrier.MaxRetries = 0
	sp.cbGate = backoff.NewGate(1, time.Hour)
	sp.cbGates = newCircuitBreakerRegistry(sp.cbGate, "http://alist.internal:5244", 1, time.Hour)

	request := func(target string) error {
		r := httptest.NewRequest(http.MethodPut, "http://proxy.local/file", nil)
		return sp.ProxyRequest(httptest.NewRecorder(), r, target)
	}
	if err := request("https://bad-cdn.example/video-one"); err != nil {
		t.Fatalf("first bad-origin response should be forwarded: %v", err)
	}
	if err := request("https://bad-cdn.example/video-two"); err == nil {
		t.Fatal("open bad-origin circuit did not reject the next request")
	}
	if err := request("https://healthy-cdn.example/next-video"); err != nil {
		t.Fatalf("healthy next-video origin was blocked: %v", err)
	}
	if badCalls.Load() != 1 || healthyCalls.Load() != 1 {
		t.Fatalf("upstream calls bad=%d healthy=%d, want 1 each", badCalls.Load(), healthyCalls.Load())
	}
}

func TestRedirectCircuitBreakerRecordsActualDataPlaneOrigin(t *testing.T) {
	sp := NewStreamProxy(config.DefaultConfig())
	sp.cbGate = backoff.NewGate(1, time.Hour)
	sp.cbGates = newCircuitBreakerRegistry(sp.cbGate, "http://alist.internal:5244", 1, time.Hour)
	var calls atomic.Int32
	sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("unavailable")),
			Request:    req,
		}, nil
	})

	upstreamURL, err := url.Parse("http://alist.internal:5244/d/video")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	initialResp := &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{"https://bad-cdn.example/video"}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    &http.Request{URL: upstreamURL},
	}
	request := httptest.NewRequest(http.MethodGet, "http://proxy.local/d/video", nil)
	result := sp.followRedirectDecrypt(
		httptest.NewRecorder(),
		request,
		initialResp,
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		64,
		encryption.LegacyContentMeta(encryption.EncTypeAESCTR, 64),
		"",
		StreamStrategyFull,
		upstreamURL.String(),
		"/encrypt",
	)
	if result.Err == nil || result.FailureReason != "upstream_5xx" {
		t.Fatalf("redirect outcome=%+v, want upstream_5xx", result)
	}
	if !sp.cbGate.Allow() {
		t.Fatal("data-plane failure opened the Alist control-plane circuit")
	}
	if sp.circuitBreakerFor("https://bad-cdn.example/next").Allow() {
		t.Fatal("data-plane failure did not open the CDN circuit")
	}
	if !sp.circuitBreakerFor("https://healthy-cdn.example/next").Allow() {
		t.Fatal("failed redirected CDN blocked a healthy next-video origin")
	}
	if calls.Load() != 1 {
		t.Fatalf("redirect upstream calls=%d, want 1", calls.Load())
	}
}
