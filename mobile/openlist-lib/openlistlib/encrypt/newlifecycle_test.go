package encrypt

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

func lifecycleTestServer(t *testing.T) *ProxyServer { return lifecycleTestServerPort(t, 0) }
func lifecycleTestServerPort(t *testing.T, port int) *ProxyServer {
	t.Helper()
	cfg := DefaultConfig()
	cfg.ConfigPath = t.TempDir() + "/config.json"
	cfg.ProviderCatalogEnabled = false
	cfg.ProviderCatalogBootstrapOnStart = false
	cfg.ProxyPort = port
	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Stop() })
	return p
}
func lifecycleWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("owned operation did not finish")
	}
}
func TestProxyLifecycleNeverStartedStopJoinsWorkers(t *testing.T) {
	p := lifecycleTestServer(t)
	joined := make(chan struct{})
	if !p.goBackground(func(ctx context.Context) { <-ctx.Done(); close(joined) }) {
		t.Fatal("admission unexpectedly closed")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, joined)
	if p.goBackground(func(context.Context) { t.Error("post-stop work executed") }) {
		t.Fatal("post-stop admission")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err == nil {
		t.Fatal("terminal instance restarted")
	}
}
func TestProxyLifecycleListenFailureCleanup(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	p := lifecycleTestServerPort(t, occupied.Addr().(*net.TCPAddr).Port)
	if err := p.Start(); err == nil {
		t.Fatal("expected occupied port error")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if !p.lifetimeClosed() {
		t.Fatal("failure cleanup retained admission")
	}
}
func TestProxyLifecycleStopCancelsActualBackgroundHTTP(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-stop:
		}
	}))
	defer func() { close(stop); srv.CloseClientConnections(); srv.Close() }()
	p := lifecycleTestServer(t)
	finished := make(chan struct{})
	p.goBackground(func(ctx context.Context) {
		defer close(finished)
		req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	})
	lifecycleWait(t, entered)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, canceled)
	lifecycleWait(t, finished)
}
func TestProxyLifecycleHandlerDrainPrecedesClose(t *testing.T) {
	p := lifecycleTestServer(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	sqlResult := make(chan error, 1)
	if p.localStore == nil {
		t.Fatal("SQLite store missing")
	}
	handler := p.guardHandlers(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(entered)
		<-release
		sqlResult <- p.localStore.db.Ping()
		close(finished)
	}))
	go handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	lifecycleWait(t, entered)
	stopped := make(chan struct{})
	go func() { _ = p.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop abandoned an admitted handler")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	lifecycleWait(t, finished)
	if err := <-sqlResult; err != nil {
		t.Fatalf("DB closed before admitted handler finished: %v", err)
	}
	lifecycleWait(t, stopped)
	if err := p.localStore.db.Ping(); err == nil {
		t.Fatal("DB still open after Stop")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal(w.Code)
	}
}
func TestProxyLifecycleActualCatalogCancellation(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	stop := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		once.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-stop:
		}
	}))
	defer func() { close(stop); srv.CloseClientConnections(); srv.Close() }()
	cfg := DefaultConfig()
	cfg.ConfigPath = t.TempDir() + "/config.json"
	cfg.ProviderCatalogBootstrapOnStart = false
	cfg.ProviderCatalogEnabled = true
	u, _ := url.Parse(srv.URL)
	cfg.AlistHost = u.Hostname()
	cfg.AlistPort, _ = strconv.Atoi(u.Port())
	p, err := NewProxyServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	p.refreshProviderCatalogAsync(nil, true)
	lifecycleWait(t, entered)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, canceled)
	p.routingMu.RLock()
	refreshing := p.catalogRefreshing
	p.routingMu.RUnlock()
	if refreshing {
		t.Fatal("catalog task not actually drained")
	}
}
func TestProxyLifecycleActualRangeCancellation(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-r.Context().Done():
			close(canceled)
		case <-stop:
		}
	}))
	defer func() { close(stop); srv.CloseClientConnections(); srv.Close() }()
	p := lifecycleTestServer(t)
	finished := make(chan struct{})
	p.goBackground(func(context.Context) { defer close(finished); _, _ = p.probeRangeCapability(srv.URL) })
	lifecycleWait(t, entered)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, canceled)
	lifecycleWait(t, finished)
}
func TestProxyLifecycleAdmissionStopFence(t *testing.T) {
	p := lifecycleTestServer(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				p.goBackground(func(ctx context.Context) { <-ctx.Done() })
			}
		}()
	}
	done := make(chan struct{})
	go func() { _ = p.Stop(); close(done) }()
	wg.Wait()
	lifecycleWait(t, done)
	if p.goBackground(func(context.Context) {}) {
		t.Fatal("sealed admission reopened")
	}
}
