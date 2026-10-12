package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestResilienceProactiveSlowHTTPRefreshNeverBlocks(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	server := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	cfg := config.DefaultConfig()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg.AlistServer.ServerHost = u.Hostname()
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = false
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	files := dao.NewFileDAO(store)
	if err := files.Set(&dao.FileInfo{Path: "/movie.mp4", RawURL: signedURL(time.Now().Add(-58*time.Minute), 3600), RawURLAuthScope: "anon", UpstreamFetchedAt: time.Now(), Size: 100}); err != nil {
		t.Fatal(err)
	}
	h := &ProxyHandler{cfg: cfg, fileDAO: files}
	defer h.Stop()
	returned := make(chan struct{})
	go func() {
		h.maybeProactivelyRefreshRawURL(httptest.NewRequest(http.MethodGet, "/d/movie.mp4", nil), "/movie.mp4", "/movie.mp4")
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("proactive refresh blocked playback")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh never started")
	}
	h.Stop()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel HTTP refresh")
	}
}

func TestResilienceRawRefreshNonblockingBoundedStop(t *testing.T) {
	h := &ProxyHandler{}
	entered := make(chan struct{}, maxProactiveRawRefreshWorkers)
	var canceled atomic.Int32
	refresh := func(ctx context.Context) { entered <- struct{}{}; <-ctx.Done(); canceled.Add(1) }
	start := time.Now()
	if !h.enqueueRawURLRefresh("same", refresh) {
		t.Fatal("not admitted")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("slow refresh blocked caller")
	}
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.enqueueRawURLRefresh("same", refresh) {
				t.Error("duplicate admitted")
			}
		}()
	}
	wg.Wait()
	for i := 1; i < maxProactiveRawRefreshWorkers; i++ {
		if !h.enqueueRawURLRefresh(fmt.Sprint(i), refresh) {
			t.Fatal("capacity missing")
		}
		<-entered
	}
	for i := 0; i < 1000; i++ {
		if h.enqueueRawURLRefresh(fmt.Sprint("overflow", i), refresh) {
			t.Fatal("capacity exceeded")
		}
	}
	done := make(chan struct{})
	go func() { h.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop did not cancel/reap refresh")
	}
	if canceled.Load() != maxProactiveRawRefreshWorkers || h.rawRefreshActive != 0 || len(h.lastRawURLRefreshes) != 0 {
		t.Fatalf("not reclaimed canceled=%d active=%d keys=%d", canceled.Load(), h.rawRefreshActive, len(h.lastRawURLRefreshes))
	}
	if h.enqueueRawURLRefresh("after", refresh) {
		t.Fatal("admitted after Stop")
	}
}

func TestResilienceRawRefreshCooldownCapacity(t *testing.T) {
	h := &ProxyHandler{lastRawURLRefreshes: make(map[string]time.Time)}
	defer h.Stop()
	for i := 0; i < maxProactiveRawRefreshKeys; i++ {
		h.lastRawURLRefreshes[fmt.Sprint(i)] = time.Now()
	}
	if h.enqueueRawURLRefresh("overflow", func(context.Context) {}) {
		t.Fatal("cooldown map unbounded")
	}
	h.lastRawURLRefreshes["0"] = time.Now().Add(-proactiveRawRefreshCooldown)
	if !h.enqueueRawURLRefresh("new", func(context.Context) {}) {
		t.Fatal("expired cooldown not reclaimed")
	}
}

func TestResilienceProbeWinnerCancelsLoser(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	result, candidate := probeCandidateCandidatesContext(context.Background(), nil, []string{"primary", "slow", "winner"}, testProbeAuthVariants(), func(ctx context.Context, c string, _ http.Header) proxy.ContentInspectionResult {
		switch c {
		case "primary":
			return proxy.ContentInspectionResult{}
		case "slow":
			close(started)
			<-ctx.Done()
			close(canceled)
			return proxy.ContentInspectionResult{}
		default:
			<-started
			return proxy.ContentInspectionResult{Confirmed: true}
		}
	})
	if !result.Confirmed || candidate != "winner" {
		t.Fatalf("winner=%s result=%+v", candidate, result)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("loser was not canceled")
	}
}

func TestResilienceProbeTotalBudgetIncludesPrimary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var calls atomic.Int32
	start := time.Now()
	result, _ := probeCandidateCandidatesContext(ctx, nil, []string{"primary", "fallback"}, testProbeAuthVariants(), func(ctx context.Context, _ string, _ http.Header) proxy.ContentInspectionResult {
		calls.Add(1)
		<-ctx.Done()
		return proxy.ContentInspectionResult{}
	})
	if result.Confirmed || calls.Load() != 1 || time.Since(start) > time.Second {
		t.Fatalf("budget failed calls=%d", calls.Load())
	}
}

type liveResilienceStreamer struct {
	startedPlaybackStreamer
	first, finish chan struct{}
	prework       time.Duration
}

func (s *liveResilienceStreamer) AcquireStream() (func(), bool) {
	time.Sleep(s.prework)
	return func() {}, true
}
func (s *liveResilienceStreamer) ProxyDownloadDecryptWithStrategyForStorage(w http.ResponseWriter, r *http.Request, _ string, _ *config.PasswdInfo, _ int64, _ proxy.StreamStrategy, _ string) *proxy.StreamOutcome {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("a"))
	close(s.first)
	<-s.finish
	_, _ = w.Write([]byte("b"))
	return &proxy.StreamOutcome{StatusCode: 200, ResponseStarted: true, BytesWritten: 2, ExpectedBytes: 2, HeaderLatency: time.Millisecond}
}
func TestResilienceNextEpisodeBeforeEOFAndFirstBytePrework(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	files := dao.NewFileDAO(store)
	if err := files.Set(&dao.FileInfo{Path: "/drama/第02集.mp4", EncryptedPath: "/encrypted/2", Size: 100}); err != nil {
		t.Fatal(err)
	}
	ps := &ProbeScheduler{cfg: cfg, fileDAO: files, enabled: true, queue: make(chan probeItem, 16), seen: make(map[string]time.Time), providerSem: make(map[string]chan struct{})}
	sp := &liveResilienceStreamer{first: make(chan struct{}), finish: make(chan struct{}), prework: 30 * time.Millisecond}
	stats := &startedPlaybackRecorder{}
	done := make(chan struct{})
	var count, nanos uint64
	go func() {
		defer close(done)
		executeDecryptPlayback(decryptPlaybackRequest{ResponseWriter: httptest.NewRecorder(), Request: httptest.NewRequest(http.MethodGet, "/d/drama/第01集.mp4", nil), Config: cfg, Probe: ps, FileDAO: files, StreamProxy: sp, PasswdInfo: &config.PasswdInfo{}, FileItem: FileItem{DisplayPath: "/drama/第01集.mp4", EncryptedPath: "/encrypted/1"}, InitialSize: 2, StatsRecorder: stats, FirstBodyByteCount: &count, FirstBodyByteNanos: &nanos})
	}()
	<-sp.first
	select {
	case item := <-ps.queue:
		if item.file.DisplayPath != "/drama/第02集.mp4" {
			t.Fatalf("wrong warm item %s", item.file.DisplayPath)
		}
	default:
		t.Error("next episode not queued before EOF")
	}
	close(sp.finish)
	<-done
	if count != 1 || time.Duration(nanos) < sp.prework {
		t.Fatalf("firstbyte count=%d elapsed=%s", count, time.Duration(nanos))
	}
	if len(stats.events) != 1 || stats.events[0].FirstByteLatencyMs < 30 || stats.events[0].HeaderLatencyMs != 1 {
		t.Fatalf("timing=%+v", stats.events)
	}
}

type failingResilienceWriter struct{ *httptest.ResponseRecorder }

func (w failingResilienceWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("disconnect") }
func TestResilienceFirstByteDoesNotInventSuccess(t *testing.T) {
	for _, tc := range []struct {
		name, method string
		status       int
		cancel, fail bool
	}{{"head", http.MethodHead, 200, false, false}, {"error", http.MethodGet, 502, false, false}, {"cancel", http.MethodGet, 200, true, false}, {"writefail", http.MethodGet, 200, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			r := withPlaybackRequestStart(httptest.NewRequest(tc.method, "/", nil))
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			if tc.cancel {
				cancel()
			}
			var called int
			var underlying http.ResponseWriter = httptest.NewRecorder()
			if tc.fail {
				underlying = failingResilienceWriter{httptest.NewRecorder()}
			}
			w := &playbackFirstByteWriter{ResponseWriter: underlying, request: r, onFirstByte: func(time.Duration) { called++ }}
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte("data"))
			if called != 0 {
				t.Fatal("fake firstbyte")
			}
			if w.Unwrap() != underlying {
				t.Fatal("Unwrap lost")
			}
			w.Flush()
		})
	}
}
