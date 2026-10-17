package handler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

// NewProbeScheduler starts dispatch before the server attaches its tracker.
// Repeated publication overlaps the real workers' empty-queue state reads; the
// race matrix verifies both initial nil publication and subsequent replacements.
func TestProbeSchedulerTrackerPublicationAfterWorkersStart(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableBackgroundProbe = true
	cfg.AlistServer.ProbeConcurrency = 4
	ps := NewProbeScheduler(cfg, nil, nil, nil, nil)
	defer ps.Stop()
	first := NewForegroundTracker(func() bool { return true })
	second := NewForegroundTracker(func() bool { return false })
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ps.SetForegroundTracker(first)
				ps.SetForegroundTracker(second)
				ps.SetForegroundTracker(nil)
			}
		}()
	}
	wg.Wait()
	ps.SetForegroundTracker(first)
	if ps.foreground.Load() != first {
		t.Fatal("published tracker not visible")
	}
}

func TestForegroundTrackerNestedAndIdempotentRelease(t *testing.T) {
	f := NewForegroundTracker(func() bool { return true })
	first, second := f.Begin(), f.Begin()
	first()
	first()
	if busy, _ := f.state(); !busy {
		t.Fatal("nested foreground released early")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.WaitBackground(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel = %v", err)
	}
	second()
	if err := f.WaitBackground(context.Background()); err != nil {
		t.Fatal(err)
	}
	if busy, _ := f.state(); busy {
		t.Fatal("foreground leaked")
	}
}

func TestForegroundTrackerProfileChangeReleasesActiveWait(t *testing.T) {
	var enabled atomic.Bool
	enabled.Store(true)
	var observeWait atomic.Bool
	observed := make(chan struct{})
	var once sync.Once
	f := NewForegroundTracker(func() bool {
		value := enabled.Load()
		if observeWait.Load() {
			once.Do(func() { close(observed) })
		}
		return value
	})
	finish := f.Begin()
	defer finish()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	observeWait.Store(true)
	go func() { result <- f.WaitBackground(ctx) }()
	select {
	case <-observed:
	case <-ctx.Done():
		t.Fatal("waiter did not start")
	}
	// Do not finish the stream: the profile change itself must release admission.
	enabled.Store(false)
	if err := <-result; err != nil {
		t.Fatalf("disabled profile retained background waiter: %v", err)
	}
}

func TestForegroundTrackerStandardIsNoop(t *testing.T) {
	f := NewForegroundTracker(func() bool { return false })
	defer f.Begin()()
	if busy, _ := f.state(); busy {
		t.Fatal("standard paused background")
	}
	if err := f.WaitBackground(context.Background()); err != nil {
		t.Fatal(err)
	}
	var absent *ForegroundTracker
	absent.Begin()()
	if err := absent.WaitBackground(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestForegroundGatePausesDispatchButNotExplicitForeground(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	// Queue before switching to trusted mode, as with an in-process profile change.
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "scan.mp4"), nil, 4096, probeSourceStartupScan)
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "foreground.mp4"), nil, 4096, probeSourceFirstFrame)
	f := NewForegroundTracker(func() bool { return true })
	ps.SetForegroundTracker(f)
	done := f.Begin()
	item, sem, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/foreground.mp4" {
		t.Fatalf("foreground blocked: %+v", item)
	}
	ps.releaseProviderSlot(sem)
	ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
	// No additional bulk work should even reserve queue/cooldown state.
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "bulk.mp4"), nil, 4096, probeSourceFSList)
	if got := ps.Stats()["queue_len"]; got != 1 {
		t.Fatalf("bulk admitted: queue=%v", got)
	}
	done()
	item, sem, ok = ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/scan.mp4" {
		t.Fatal("background failed to resume")
	}
	ps.releaseProviderSlot(sem)
	ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
}

func TestSnapshotRefreshCoalescesBeforeSpawningAndStopJoins(t *testing.T) {
	webdav, store, _ := newWebDAVSnapshotTestHandler(t)
	f := NewForegroundTracker(func() bool { return true })
	finish := f.Begin()
	defer finish()
	h := &AlistHandler{
		cfg: webdav.cfg, dirSyncStore: store, foreground: f,
		dirSyncRefreshSem: make(chan struct{}, 8),
	}
	defer h.Stop()
	for i := 0; i < 100; i++ {
		h.refreshDirSnapshotAsync("/directory", nil, nil, "scope", dirSyncModeReq)
	}
	h.dirSyncMu.Lock()
	pending, slots := len(h.dirSyncRefreshPending), len(h.dirSyncRefreshSem)
	h.dirSyncMu.Unlock()
	if pending != 1 || slots != 1 {
		t.Fatalf("duplicate refresh admission: pending=%d slots=%d", pending, slots)
	}
	// Stop must cancel the actual blocked worker and wait for its deferred release.
	h.Stop()
	h.refreshDirSnapshotAsync("/directory", nil, nil, "scope", dirSyncModeReq)
	h.dirSyncMu.Lock()
	pending, slots = len(h.dirSyncRefreshPending), len(h.dirSyncRefreshSem)
	h.dirSyncMu.Unlock()
	if pending != 0 || slots != 0 {
		t.Fatalf("refresh leaked or restarted after stop: pending=%d slots=%d", pending, slots)
	}
}

func TestTrustedSchedulerReservesProviderSlotForForeground(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	ps.providerLimit = 2
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "background.mp4"), nil, 4096, probeSourceStartupScan)
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "foreground.mp4"), nil, 4096, probeSourceFirstFrame)
	ps.SetForegroundTracker(NewForegroundTracker(func() bool { return true }))
	sem := ps.getProviderSem("ready.example")
	sem <- struct{}{} // An already-running background request keeps its actual slot.
	item, claimed, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/foreground.mp4" {
		t.Fatalf("reserved slot was not available to foreground: %+v", item)
	}
	ps.releaseProviderSlot(claimed)
	ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
	ps.releaseProviderSlot(sem)
}

func TestProbeDelayDoesNotClaimProviderOrBlockReadyItem(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	delayed := fairDispatchFile("ready.example", "delayed.mp4")
	ready := fairDispatchFile("ready.example", "ready.mp4")
	ps.queue <- probeItem{file: delayed, notBefore: time.Now().Add(time.Hour)}
	ps.queue <- probeItem{file: ready}
	item, sem, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != ready.DisplayPath {
		t.Fatalf("delayed item blocked ready provider: %+v", item)
	}
	if len(sem) != 1 {
		t.Fatal("provider admission not bounded")
	}
	ps.releaseProviderSlot(sem)
	if len(sem) != 0 {
		t.Fatal("provider slot leaked")
	}
}
