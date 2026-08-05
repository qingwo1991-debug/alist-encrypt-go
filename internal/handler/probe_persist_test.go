package handler

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
)

func newTestStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return store
}

func TestProbeCountersPersistRoundTrip(t *testing.T) {
	store := newTestStore(t)
	pp := newProbePersister(store)
	if pp == nil {
		t.Fatal("persister nil")
	}

	in := &ProbeCounters{
		FilesSucceededTotal: 42,
		FilesFailedTotal:    3,
		ConsumerHitTotal:    7,
		FilesRangeProbed:    11,
	}
	pp.saveCounters(in)

	got := pp.loadCounters()
	if got == nil {
		t.Fatal("loadCounters returned nil after save")
	}
	if got.FilesSucceededTotal != 42 || got.FilesFailedTotal != 3 ||
		got.ConsumerHitTotal != 7 || got.FilesRangeProbed != 11 {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestProbeWarmStatePersistRoundTrip(t *testing.T) {
	store := newTestStore(t)
	pp := newProbePersister(store)

	now := time.Now()
	in := map[string]probeWarmState{
		"/videos/a.mp4": {
			Source:            "scan",
			FinishedAt:        now.Add(-time.Minute),
			ConsumerHitCount:  3,
			LastConsumerHitAt: now,
			State:             warmStateReady,
		},
		"/videos/b.mp4": {
			Source:     "playback",
			FinishedAt: now.Add(-time.Hour),
			State:      warmStateStale,
		},
	}
	pp.saveWarmState(in)

	got := pp.loadWarmState()
	if got == nil {
		t.Fatal("loadWarmState returned nil after save")
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(got))
	}
	if got["/videos/a.mp4"].ConsumerHitCount != 3 {
		t.Errorf("ConsumerHitCount = %d, want 3", got["/videos/a.mp4"].ConsumerHitCount)
	}
	if got["/videos/b.mp4"].State != warmStateStale {
		t.Errorf("b.mp4 state = %q, want %q", got["/videos/b.mp4"].State, warmStateStale)
	}
}

func TestProbePersisterNilSafe(t *testing.T) {
	var pp *probePersister
	// 这些都不该 panic。
	pp.loadCounters()
	pp.saveCounters(nil)
	pp.loadWarmState()
	pp.saveWarmState(nil)
}

func TestProbeSchedulerPersistedCountersLoaded(t *testing.T) {
	store := newTestStore(t)
	pp := newProbePersister(store)
	pp.saveCounters(&ProbeCounters{FilesSucceededTotal: 99, ConsumerHitTotal: 5})

	ps := NewProbeScheduler(nil, nil, nil, nil, store)
	if ps == nil {
		t.Fatal("scheduler nil")
	}
	defer ps.Stop()

	if got := atomic.LoadUint64(&ps.filesSucceededTotal); got != 99 {
		t.Errorf("filesSucceededTotal = %d, want 99", got)
	}
	if got := atomic.LoadUint64(&ps.consumerHitTotal); got != 5 {
		t.Errorf("consumerHitTotal = %d, want 5", got)
	}
}
