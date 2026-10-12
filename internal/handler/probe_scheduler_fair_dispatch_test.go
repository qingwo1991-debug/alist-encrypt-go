package handler

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func fairDispatchScheduler(t *testing.T, capacity int) *ProbeScheduler {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	ps := &ProbeScheduler{enabled: true, ctx: ctx, cancel: cancel, queue: make(chan probeItem, capacity), providerLimit: 1, providerSem: make(map[string]chan struct{}), cooldown: time.Hour, fileDAO: dao.NewFileDAO(store)}
	ps.resolver = NewFileSizeResolver(nil, ps.fileDAO, nil, 4, 0, 1)
	t.Cleanup(ps.Stop)
	return ps
}

func fairDispatchFile(provider, name string) FileItem {
	return FileItem{DisplayPath: "/" + name, FileName: name, TargetURL: "https://" + provider + "/" + name, PropfindSize: 4096}
}

func awaitDispatchEvent(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("event = %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

// Four consecutive probes for a blocked provider must not occupy four workers.
// Channel handshakes, not sleeps/polling, control both completion and shutdown.
func TestProbeFairDispatchBlockedProviderDoesNotOccupyWorkers(t *testing.T) {
	ps := fairDispatchScheduler(t, 8)
	entered := make(chan string, 8)
	release := make(chan struct{})
	ps.rawURLFetcher = func(displayPath, _ string, _ http.Header) string {
		entered <- displayPath
		if displayPath != "/other.mp4" {
			select {
			case <-release:
			case <-ps.done():
			}
		}
		return "https://cdn.example/warm"
	}
	for i := 0; i < 4; i++ {
		file := fairDispatchFile("blocked.example", fmt.Sprintf("blocked%d.mp4", i))
		ps.fileDAO.SetFileSize(file.DisplayPath, 4096, time.Hour)
		ps.EnqueueWithSource(file, nil, 4096, probeSourceStartupScan)
	}
	ps.fileDAO.SetFileSize("/other.mp4", 4096, time.Hour)
	for i := 0; i < 4; i++ {
		ps.workerWG.Add(1)
		go func() { defer ps.workerWG.Done(); ps.worker() }()
	}
	awaitDispatchEvent(t, entered, "/blocked0.mp4")
	ps.EnqueueWithSource(fairDispatchFile("other.example", "other.mp4"), nil, 4096, probeSourceFirstFrame)
	awaitDispatchEvent(t, entered, "/other.mp4")
	if got := atomic.LoadUint64(&ps.droppedTotal); got != 0 {
		t.Fatalf("dropped = %d", got)
	}
	close(release)
	for i := 1; i < 4; i++ {
		awaitDispatchEvent(t, entered, fmt.Sprintf("/blocked%d.mp4", i))
	}
	ps.Stop()
	ps.seenMu.Lock()
	defer ps.seenMu.Unlock()
	if len(ps.pending) != 0 {
		t.Fatalf("shutdown left %d reservations", len(ps.pending))
	}
	if got := atomic.LoadUint64(&ps.enqueuedTotal); got != 5 {
		t.Fatalf("enqueued = %d", got)
	}
}

func TestProbeFairDispatchBoundedPriorityAndReservations(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	blocked := ps.getProviderSem("blocked.example")
	blocked <- struct{}{}
	for i := 0; i < 2; i++ {
		ps.EnqueueWithSource(fairDispatchFile("blocked.example", fmt.Sprintf("blocked%d.mp4", i)), nil, 4096, probeSourceStartupScan)
	}
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "scan.mp4"), nil, 4096, probeSourceStartupScan)
	ps.EnqueueWithSource(fairDispatchFile("ready.example", "foreground.mp4"), nil, 4096, probeSourceFirstFrame)
	item, sem, ok := ps.nextReadyItem()
	if !ok || item.file.DisplayPath != "/foreground.mp4" {
		t.Fatalf("claimed %+v, ok=%v", item, ok)
	}
	if got := ps.Stats()["queue_len"]; got != 3 {
		t.Fatalf("queue_len = %v", got)
	}
	// The released queue capacity is exactly one even though the channel drained.
	admitted := fairDispatchFile("blocked.example", "admitted.mp4")
	rejected := fairDispatchFile("blocked.example", "rejected.mp4")
	ps.EnqueueWithSource(admitted, nil, 4096, probeSourceStartupScan)
	ps.EnqueueWithSource(rejected, nil, 4096, probeSourceStartupScan)
	if got := ps.Stats()["queue_len"]; got != 4 {
		t.Fatalf("queue_len = %v", got)
	}
	if ps.isCoolingDown(probeCooldownKey(rejected)) {
		t.Fatal("rejected admission retained cooldown")
	}
	ps.seenMu.Lock()
	_, pending := ps.pending[probeCooldownKey(admitted)]
	ps.seenMu.Unlock()
	if !pending {
		t.Fatal("accepted deferred probe lost reservation")
	}
	ps.releaseProviderSlot(sem)
	ps.releaseProbeReservation(probeCooldownKey(item.file), time.Time{}, false)
	ps.Stop()
	ps.seenMu.Lock()
	defer ps.seenMu.Unlock()
	if len(ps.pending) != 0 {
		t.Fatalf("shutdown left %d reservations", len(ps.pending))
	}
	if len(ps.waiting) != 0 || len(ps.queue) != 0 {
		t.Fatal("shutdown retained queued items")
	}
}

func TestProbeFairDispatchIdleShutdown(t *testing.T) {
	ps := fairDispatchScheduler(t, 4)
	sem := ps.getProviderSem("blocked.example")
	sem <- struct{}{}
	ps.EnqueueWithSource(fairDispatchFile("blocked.example", "blocked.mp4"), nil, 4096, probeSourceStartupScan)
	stopped := make(chan struct{})
	ps.workerWG.Add(1)
	go func() { defer ps.workerWG.Done(); ps.worker(); close(stopped) }()
	ps.Stop()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("idle worker did not stop")
	}
}
