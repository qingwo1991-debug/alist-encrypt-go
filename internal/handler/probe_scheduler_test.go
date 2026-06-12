package handler

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestProbeSchedulerWarmStateLifecycleAndRecordBackfill(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.UpstreamStalenessMinutes = 1
	ps := &ProbeScheduler{cfg: cfg}

	file := FileItem{
		DisplayPath:   "/movie.mp4",
		EncryptedPath: "/enc/movie.mp4",
		TargetURL:     "https://example.com/raw",
		FileName:      "movie.mp4",
	}

	ps.recordTerminal(file, probeSourceFirstFrame, probeStatusSuccess, 4096, probeExecutionResult{
		resolvedSize: 4096,
		sizeSource:   string(SourceHEAD),
		usedAuthMode: "request",
	})
	ps.RecordConsumerHit(file, consumerScenarioHTTP)
	ps.RecordConsumerHit(file, consumerScenarioHTTP)

	stats := ps.Stats()
	if got := stats["consumer_hit_total"]; got != uint64(1) {
		t.Fatalf("consumer_hit_total=%v, want 1", got)
	}

	records, ok := stats["recent_records"].([]ProbeRecord)
	if !ok || len(records) == 0 {
		t.Fatalf("recent_records=%T len=%d", stats["recent_records"], len(records))
	}
	record := records[0]
	if record.WarmState != warmStateReady {
		t.Fatalf("warm_state=%q, want %q", record.WarmState, warmStateReady)
	}
	if record.ConsumerHitCount != 1 {
		t.Fatalf("consumer_hit_count=%d, want 1", record.ConsumerHitCount)
	}
	if record.Priority != "high" {
		t.Fatalf("priority=%q, want high", record.Priority)
	}
	if record.SizeSource != string(SourceHEAD) {
		t.Fatalf("size_source=%q", record.SizeSource)
	}
	if record.UsedAuthMode != "request" {
		t.Fatalf("used_auth_mode=%q", record.UsedAuthMode)
	}

	ps.recordMu.Lock()
	warm := ps.successfulWarm[file.DisplayPath]
	warm.FinishedAt = time.Now().Add(-2 * time.Minute)
	ps.successfulWarm[file.DisplayPath] = warm
	ps.applyWarmStateToRecordsLocked(file.DisplayPath, warm, time.Now())
	ps.recordMu.Unlock()

	stats = ps.Stats()
	warmStateCounts, ok := stats["warm_state_counts"].(map[string]uint64)
	if !ok {
		t.Fatalf("warm_state_counts=%T", stats["warm_state_counts"])
	}
	if warmStateCounts[warmStateStale] != 1 {
		t.Fatalf("stale count=%d, want 1", warmStateCounts[warmStateStale])
	}

	ps.InvalidateWarm(file.DisplayPath, "upstream_4xx")
	stats = ps.Stats()
	warmStateCounts = stats["warm_state_counts"].(map[string]uint64)
	if warmStateCounts[warmStateInvalid] != 1 {
		t.Fatalf("invalid count=%d, want 1", warmStateCounts[warmStateInvalid])
	}

	records = stats["recent_records"].([]ProbeRecord)
	if !records[0].Invalidated {
		t.Fatal("expected record invalidated flag to be true")
	}
	if records[0].WarmState != warmStateInvalid {
		t.Fatalf("warm_state=%q, want %q", records[0].WarmState, warmStateInvalid)
	}

	invalidations, ok := stats["recent_invalidations"].([]ProbeInvalidation)
	if !ok || len(invalidations) != 1 {
		t.Fatalf("recent_invalidations=%T len=%d", stats["recent_invalidations"], len(invalidations))
	}
	if invalidations[0].Reason != "upstream_4xx" {
		t.Fatalf("reason=%q", invalidations[0].Reason)
	}
}

func TestInvalidateWarmDoesNotCreateSyntheticWarmState(t *testing.T) {
	ps := &ProbeScheduler{cfg: config.DefaultConfig()}

	ps.InvalidateWarm("/never-warmed.mp4", "upstream_4xx")

	stats := ps.Stats()
	warmStateCounts, ok := stats["warm_state_counts"].(map[string]uint64)
	if !ok {
		t.Fatalf("warm_state_counts=%T", stats["warm_state_counts"])
	}
	if warmStateCounts[warmStateInvalid] != 0 {
		t.Fatalf("invalid count=%d, want 0", warmStateCounts[warmStateInvalid])
	}
	currentWarmStates, ok := stats["current_warm_states"].([]ProbeWarmSnapshot)
	if !ok {
		t.Fatalf("current_warm_states=%T", stats["current_warm_states"])
	}
	if len(currentWarmStates) != 0 {
		t.Fatalf("current_warm_states len=%d, want 0", len(currentWarmStates))
	}
	invalidations, ok := stats["recent_invalidations"].([]ProbeInvalidation)
	if !ok || len(invalidations) != 1 {
		t.Fatalf("recent_invalidations=%T len=%d", stats["recent_invalidations"], len(invalidations))
	}
}

func TestSnapshotWarmStatesUsesCachedDisplayName(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fileDAO := dao.NewFileDAO(store)
	_ = fileDAO.Set(&dao.FileInfo{
		Path:  "/移动云盘156/encrypt/demo.mp4",
		Name:  "demo.mp4",
		Size:  123,
		IsDir: false,
	})

	ps := &ProbeScheduler{
		cfg:     config.DefaultConfig(),
		fileDAO: fileDAO,
		successfulWarm: map[string]probeWarmState{
			"/移动云盘156/encrypt/demo.mp4": {
				Source:     probeSourcePropfind,
				FinishedAt: time.Now(),
				State:      warmStateReady,
			},
		},
	}

	states := ps.snapshotWarmStates()
	if len(states) != 1 {
		t.Fatalf("states len=%d, want 1", len(states))
	}
	if states[0].FileName != "demo.mp4" {
		t.Fatalf("file_name=%q, want %q", states[0].FileName, "demo.mp4")
	}
}

func TestFetchRawURLUsesAuthHeaders(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)

	var gotAuth string
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if gotAuth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":401}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"https://cdn.example/file","size":4096}}`))
	}))
	defer srv.Close()

	authHeaders := make(http.Header)
	authHeaders.Set("Authorization", "Bearer test-token")
	result := fetchRawURL(context.Background(), srv.URL, "/movie.mp4", "/enc/movie.bin", authHeaders, fileDAO, 30*time.Minute)
	if result.RawURL != "https://cdn.example/file" {
		t.Fatalf("raw_url=%q", result.RawURL)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("authorization=%q", gotAuth)
	}
}

func TestFetchRawURLFallsBackToFsLinkWhenFsGetReturnsEmpty(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)

	var fsGetCalls, fsLinkCalls int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			fsGetCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"","size":0}}`))
		case "/api/fs/link":
			fsLinkCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"https://cdn.example/from-link","size":8192}}`))
		default:
			t.Fatalf("unexpected path=%q", r.URL.Path)
		}
	}))
	defer srv.Close()

	result := fetchRawURL(context.Background(), srv.URL, "/movie.mp4", "/enc/movie.bin", nil, fileDAO, 30*time.Minute)
	if result.RawURL != "https://cdn.example/from-link" {
		t.Fatalf("raw_url=%q", result.RawURL)
	}
	if result.Source != "fs_link" {
		t.Fatalf("source=%q, want fs_link", result.Source)
	}
	if fsGetCalls != 1 || fsLinkCalls != 1 {
		t.Fatalf("fsGetCalls=%d fsLinkCalls=%d, want 1/1", fsGetCalls, fsLinkCalls)
	}

	info, ok := fileDAO.Get("/movie.mp4")
	if !ok || info == nil {
		t.Fatal("expected cache entry for display path")
	}
	if info.RawURL != "https://cdn.example/from-link" || info.Size != 8192 {
		t.Fatalf("cached raw_url=%q size=%d", info.RawURL, info.Size)
	}
}

func TestFetchRawURLFallsBackToFinalRedirectWhenAPIsReturnEmpty(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)

	signedAt := time.Now().UTC().Format("20060102T150405Z")
	finalRawURL := ""
	var fsGetCalls, fsLinkCalls, dCalls, cdnHeadCalls int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			fsGetCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"","size":0}}`))
		case "/api/fs/link":
			fsLinkCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"","size":0}}`))
		case "/d/enc/movie.bin":
			dCalls++
			http.Redirect(w, r, finalRawURL, http.StatusFound)
		case "/cdn/movie.bin":
			cdnHeadCalls++
			w.Header().Set("Content-Length", "8192")
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%q", r.URL.Path)
		}
	}))
	defer srv.Close()
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	parsed.Host = strings.Replace(parsed.Host, "127.0.0.1", "localhost", 1)
	finalRawURL = parsed.String() + "/cdn/movie.bin?X-Amz-Date=" + signedAt + "&X-Amz-Expires=900"

	result := fetchRawURL(context.Background(), srv.URL, "/movie.mp4", "/enc/movie.bin", nil, fileDAO, 30*time.Minute)
	if result.RawURL != finalRawURL {
		t.Fatalf("raw_url=%q, want %q", result.RawURL, finalRawURL)
	}
	if result.Source != "redirect_d" {
		t.Fatalf("source=%q, want redirect_d", result.Source)
	}
	if result.Size != 8192 {
		t.Fatalf("size=%d, want 8192", result.Size)
	}
	if fsGetCalls != 1 || fsLinkCalls != 1 || dCalls != 1 || cdnHeadCalls != 1 {
		t.Fatalf("calls fs/get=%d fs/link=%d /d=%d cdn=%d", fsGetCalls, fsLinkCalls, dCalls, cdnHeadCalls)
	}

	info, ok := fileDAO.Get("/movie.mp4")
	if !ok || info == nil {
		t.Fatal("expected cache entry for display path")
	}
	if info.RawURL != finalRawURL || info.Size != 8192 {
		t.Fatalf("cached raw_url=%q size=%d", info.RawURL, info.Size)
	}
}

func TestProbeSchedulerRunItemUsesEffectiveAuthForRawURLAndRangeProbe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.ScanAuthHeader = "Bearer scan-token"

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	fileDAO.SetFileSize("/movie.mp4", 4096, time.Hour)

	var (
		mu             sync.Mutex
		rawURLAuth     string
		rangeProbeAuth string
	)

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Header.Get("Range") == "bytes=0-0" {
			rangeProbeAuth = r.Header.Get("Authorization")
		}
		mu.Unlock()
		w.Header().Set("Content-Range", "bytes 0-0/4096")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	sp := proxy.NewStreamProxy(cfg)
	ps := &ProbeScheduler{
		cfg:           cfg,
		fileDAO:       fileDAO,
		stream:        sp,
		resolver:      NewFileSizeResolver(cfg, fileDAO, nil, 1, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		providerLimit: 1,
		providerSem:   make(map[string]chan struct{}),
	}
	ps.rawURLFetcher = func(displayPath, realPath string, authHeaders http.Header) string {
		mu.Lock()
		rawURLAuth = authHeaders.Get("Authorization")
		mu.Unlock()
		return "https://cdn.example/file"
	}

	ps.runItem(probeItem{
		file: FileItem{
			DisplayPath:      "/movie.mp4",
			EncryptedPath:    "/enc/movie.bin",
			TargetURL:        srv.URL,
			FileName:         "movie.mp4",
			CompatStorageKey: "/encrypt",
		},
		authHeaders: make(http.Header),
		source:      probeSourceStartupScan,
		queuedAt:    time.Now(),
	})

	mu.Lock()
	defer mu.Unlock()
	if rawURLAuth != "Bearer scan-token" {
		t.Fatalf("rawURL auth=%q", rawURLAuth)
	}
	if rangeProbeAuth != "Bearer scan-token" {
		t.Fatalf("range probe auth=%q", rangeProbeAuth)
	}
}
