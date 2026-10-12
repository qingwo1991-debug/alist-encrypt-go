package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func interestTestScheduler(t *testing.T, capacity int) *ProbeScheduler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ps := &ProbeScheduler{enabled: true, queue: make(chan probeItem, capacity), ctx: ctx, cancel: cancel, workers: 1, providerLimit: 1, providerSem: make(map[string]chan struct{})}
	t.Cleanup(ps.Stop)
	return ps
}
func interestTestFile(path string) FileItem {
	return FileItem{DisplayPath: path, TargetURL: "http://provider.test/d" + path, FileName: path}
}
func interestAdvance(t *testing.T, ps *ProbeScheduler, session string, generation uint64, target string) {
	t.Helper()
	if _, err := ps.AdvancePlaybackInterest("verified", "session"+session, "provider", generation, target); err != nil {
		t.Fatal(err)
	}
}
func interestEnqueue(t *testing.T, ps *ProbeScheduler, session string, generation uint64, path string, kind WarmKind) {
	t.Helper()
	if err := ps.EnqueuePlaybackInterest("verified", "session"+session, "provider", generation, interestTestFile(path), nil, 0, kind); err != nil {
		t.Fatal(err)
	}
}
func TestPlaybackInterestGenerationValidationAndIsolation(t *testing.T) {
	ps := interestTestScheduler(t, 8)
	interestAdvance(t, ps, "one", 1, "/A")
	if advanced, err := ps.AdvancePlaybackInterest("verified", "sessionone", "provider", 1, "/A"); err != nil || advanced {
		t.Fatalf("retry %v %v", advanced, err)
	}
	if _, err := ps.AdvancePlaybackInterest("verified", "sessionone", "provider", 1, "/B"); !errors.Is(err, ErrPlaybackInterestInvalid) {
		t.Fatal(err)
	}
	interestAdvance(t, ps, "one", 2, "/B")
	if _, err := ps.AdvancePlaybackInterest("verified", "sessionone", "provider", 1, "/A"); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal(err)
	}
	if err := ps.EnqueuePlaybackInterest("other", "sessionone", "provider", 2, interestTestFile("/B"), nil, 0, WarmForeground); !errors.Is(err, ErrPlaybackInterestStale) {
		t.Fatal(err)
	}
	if err := ps.EnqueuePlaybackInterest("verified", "sessionone", "provider", 2, interestTestFile("/other"), nil, 0, WarmForeground); !errors.Is(err, ErrPlaybackInterestInvalid) {
		t.Fatal(err)
	}
}
func TestPlaybackInterestRapidQueuedABCAndPromotion(t *testing.T) {
	ps := interestTestScheduler(t, 8)
	interestAdvance(t, ps, "one", 1, "/A")
	interestEnqueue(t, ps, "one", 1, "/old-spec", WarmSpeculative)
	old := ps.interestTasks[playbackInterestTaskKey("verified", "provider", interestTestFile("/old-spec"), nil)]
	interestAdvance(t, ps, "one", 2, "/B")
	interestEnqueue(t, ps, "one", 2, "/B-spec", WarmSpeculative)
	interestAdvance(t, ps, "one", 3, "/C")
	interestEnqueue(t, ps, "one", 3, "/later-spec", WarmSpeculative)
	interestEnqueue(t, ps, "one", 3, "/C", WarmSpeculative)
	interestEnqueue(t, ps, "one", 3, "/C", WarmForeground)
	if old.ctx.Err() == nil {
		t.Fatal("old speculative context remains active")
	}
	item, sem, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/C" {
		t.Fatalf("final target priority: %+v", item)
	}
	ps.finishPlaybackInterest(item.interest)
	ps.releaseProviderSlot(sem)
	if len(ps.interestTasks) != 1 {
		t.Fatalf("withdrawn tasks not drained: %d", len(ps.interestTasks))
	}
}
func TestPlaybackInterestMultipleSessionsAndForegroundWithdrawal(t *testing.T) {
	ps := interestTestScheduler(t, 8)
	interestAdvance(t, ps, "one", 1, "/A")
	interestAdvance(t, ps, "two", 1, "/A")
	interestEnqueue(t, ps, "one", 1, "/shared", WarmSpeculative)
	interestEnqueue(t, ps, "two", 1, "/shared", WarmSpeculative)
	task := ps.interestTasks[playbackInterestTaskKey("verified", "provider", interestTestFile("/shared"), nil)]
	if len(ps.queue) != 1 || len(task.refs) != 2 {
		t.Fatal("same-scope duplicate was not coalesced")
	}
	interestAdvance(t, ps, "one", 2, "/B")
	if task.ctx.Err() != nil {
		t.Fatal("other session interest incorrectly canceled")
	}
	interestAdvance(t, ps, "two", 2, "/C")
	if task.ctx.Err() == nil {
		t.Fatal("last speculative reference was not canceled")
	}
	interestEnqueue(t, ps, "one", 2, "/B", WarmForeground)
	fg := ps.interestTasks[playbackInterestTaskKey("verified", "provider", interestTestFile("/B"), nil)]
	interestAdvance(t, ps, "one", 3, "/D")
	if fg.ctx.Err() == nil {
		t.Fatal("withdrawn priority metadata warm task still active")
	}
	// Live HTTP and legacy directory probes are not linked to any interest context.
	if ps.probeContext().Err() != nil {
		t.Fatal("withdrawal canceled service or unrelated requests")
	}
}
func TestPlaybackInterestForegroundReferenceDemotesOnWithdrawal(t *testing.T) {
	ps := interestTestScheduler(t, 8)
	interestAdvance(t, ps, "one", 1, "/shared")
	interestAdvance(t, ps, "two", 1, "/A")
	interestEnqueue(t, ps, "one", 1, "/shared", WarmForeground)
	interestEnqueue(t, ps, "two", 1, "/shared", WarmSpeculative)
	task := ps.interestTasks[playbackInterestTaskKey("verified", "provider", interestTestFile("/shared"), nil)]
	interestAdvance(t, ps, "one", 2, "/C")
	if task.ctx.Err() != nil || task.foreground {
		t.Fatal("remaining speculative reference incorrectly canceled or promoted")
	}
	interestEnqueue(t, ps, "one", 2, "/C", WarmForeground)
	item, sem, _ := ps.nextReadyItem()
	if item.file.DisplayPath != "/C" {
		t.Fatal("withdrawn foreground still outranks current target")
	}
	ps.finishPlaybackInterest(item.interest)
	ps.releaseProviderSlot(sem)
}
func TestPlaybackInterestCapacityTTLAndStop(t *testing.T) {
	ps := interestTestScheduler(t, 64)
	for i := 0; i < playbackInterestSessions; i++ {
		interestAdvance(t, ps, fmt.Sprint(i), 1, "/A")
	}
	if _, err := ps.AdvancePlaybackInterest("verified", "overflow", "provider", 1, "/A"); !errors.Is(err, ErrPlaybackInterestCapacity) {
		t.Fatal(err)
	}
	ps.queueMu.Lock()
	ps.interests[playbackSessionKey{"verified", "session0", "provider"}].touched = time.Now().Add(-playbackInterestTTL)
	ps.queueMu.Unlock()
	if _, err := ps.AdvancePlaybackInterest("verified", "overflow", "provider", 1, "/A"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < playbackInterestPerSession; i++ {
		interestEnqueue(t, ps, "1", 1, fmt.Sprintf("/spec%d", i), WarmSpeculative)
	}
	if err := ps.EnqueuePlaybackInterest("verified", "session1", "provider", 1, interestTestFile("/overflow"), nil, 0, WarmSpeculative); !errors.Is(err, ErrPlaybackInterestCapacity) {
		t.Fatal(err)
	}
	ps.Stop()
	if len(ps.interestTasks) != 0 || len(ps.interests) != 0 || len(ps.queue) != 0 {
		t.Fatal("stop retained session or task ownership")
	}
	if _, err := ps.AdvancePlaybackInterest("verified", "x", "provider", 1, "/A"); !errors.Is(err, ErrPlaybackInterestStopped) {
		t.Fatal(err)
	}
}
func TestPlaybackInterestConfiguredLoginIsActuallyCanceled(t *testing.T) {
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	cfg := config.LoadFromBaseDir(t.TempDir())
	alist := cfg.AlistServerSnapshot()
	alist.ServerHost = u.Hostname()
	alist.ServerPort = port
	alist.ScanUsername = "scan-user"
	alist.ScanPassword = "scan-password"
	if err := cfg.UpdateAlistServer(alist); err != nil {
		t.Fatal(err)
	}
	ps := interestTestScheduler(t, 8)
	ps.cfg = cfg
	ctx, cancel := context.WithCancel(ps.probeContext())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := ps.ensurePlaybackInterestAuth(ctx, nil); done <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("provider login did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("login wrapper returned without canceling actual transfer")
	}
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("real login request did not observe cancellation")
	}
}
func TestPlaybackInterestActiveCancellationJoinsRealTransfer(t *testing.T) {
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer srv.Close()
	ps := interestTestScheduler(t, 8)
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ps.fileDAO = dao.NewFileDAO(store)
	ps.resolver = NewFileSizeResolver(cfg, ps.fileDAO, nil, 1, MinMetaSize(cfg), RedirectMaxHops(cfg))
	interestAdvance(t, ps, "one", 1, "/A")
	file := interestTestFile("/active")
	file.TargetURL = srv.URL + "/active"
	if err := ps.EnqueuePlaybackInterest("verified", "sessionone", "provider", 1, file, nil, 0, WarmSpeculative); err != nil {
		t.Fatal(err)
	}
	item, sem, ok := ps.nextReadyItem()
	if !ok {
		t.Fatal("no task")
	}
	done := make(chan struct{})
	ps.workerWG.Add(1)
	go func() { defer ps.workerWG.Done(); defer close(done); ps.runClaimedItem(item, sem) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("actual request not started")
	}
	interestAdvance(t, ps, "one", 2, "/C")
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("HTTP request not canceled")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("worker failed to drain")
	}
	if len(sem) != 0 {
		t.Fatal("provider slot retained after actual return")
	}
	ps.Stop()
	if len(ps.interestTasks) != 0 {
		t.Fatal("stop failed to join active ownership")
	}
}
