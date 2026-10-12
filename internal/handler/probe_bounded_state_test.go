package handler

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeSeenTTLAndCapacity(t *testing.T) {
	now := time.Now()
	ps := &ProbeScheduler{cooldown: time.Hour, seen: make(map[string]time.Time), pending: make(map[string]struct{})}
	ps.seen["expired"] = now.Add(-2 * time.Hour)
	ps.seen["pending"] = now.Add(-2 * time.Hour)
	ps.pending["pending"] = struct{}{}
	ps.pruneSeenLocked(now)
	if _, ok := ps.seen["expired"]; ok {
		t.Fatal("expired cooldown retained")
	}
	if _, ok := ps.seen["pending"]; !ok {
		t.Fatal("pending reservation removed")
	}
	for i := len(ps.seen); i < probeSeenCapacity; i++ {
		ps.seen[fmt.Sprint(i)] = now
	}
	if _, status := ps.reserveProbe("overflow", false); status != probeStatusDroppedState {
		t.Fatalf("capacity status = %q", status)
	}
	if len(ps.seen) != probeSeenCapacity {
		t.Fatal("capacity exceeded")
	}
}

func TestProbeWarmActiveBoundsPreserveTotals(t *testing.T) {
	ps := NewProbeScheduler(nil, nil, nil, nil, nil)
	now := time.Now()
	atomic.StoreUint64(&ps.filesSucceededTotal, 123456)
	atomic.StoreUint64(&ps.consumerHitTotal, 654321)
	ps.recordMu.Lock()
	for i := 0; i < probeWarmCapacity+2; i++ {
		ps.successfulWarm[fmt.Sprint(i)] = probeWarmState{FinishedAt: now.Add(time.Duration(i) * time.Nanosecond), ConsumerHitCount: 1}
	}
	ps.successfulWarm["expired"] = probeWarmState{FinishedAt: now.Add(-probeWarmRetention)}
	ps.pruneWarmLocked(now)
	if len(ps.successfulWarm) != probeWarmCapacity {
		t.Fatalf("warm size = %d", len(ps.successfulWarm))
	}
	if _, ok := ps.successfulWarm["0"]; ok {
		t.Fatal("oldest warm retained")
	}
	ps.recordMu.Unlock()
	stats := ps.Stats()
	if stats["files_succeeded_total"] != uint64(123456) || stats["consumer_hit_total"] != uint64(654321) {
		t.Fatal("pruning changed cumulative counters")
	}
	if stats["unique_warmed_files"] != uint64(probeWarmCapacity) || stats["warm_state_scope"] != "bounded_active" {
		t.Fatal("active scope missing")
	}
	// Consumer activity extends retention, but does not refresh readiness.
	ps.recordMu.Lock()
	ps.successfulWarm["recently-consumed"] = probeWarmState{FinishedAt: now.Add(-2 * probeWarmRetention), LastConsumerHitAt: now}
	ps.recordMu.Unlock()
	snapshot := ps.copyWarmStates()
	if _, ok := snapshot["recently-consumed"]; !ok {
		t.Fatal("consumer activity ignored")
	}
	snapshot["recently-consumed"] = probeWarmState{}
	if ps.successfulWarm["recently-consumed"].LastConsumerHitAt.IsZero() {
		t.Fatal("snapshot aliases map")
	}
}

func TestProbeWarmDirtyPersistence(t *testing.T) {
	store := newTestStore(t)
	ps := NewProbeScheduler(nil, nil, nil, nil, store)
	ps.recordTerminal(FileItem{DisplayPath: "/a"}, probeSourceFSList, probeStatusSuccess, 1, probeExecutionResult{})
	ps.persistWarmStateSnapshot()
	if ps.warmRevision != ps.warmPersistedRevision {
		t.Fatal("successful save stays dirty")
	}
	// Replace on disk without changing in-memory state: clean flush must not write.
	sentinel := map[string]probeWarmState{"sentinel": {FinishedAt: time.Now()}}
	if !ps.persister.saveWarmState(sentinel) {
		t.Fatal("save sentinel")
	}
	ps.persistWarmStateSnapshot()
	if _, ok := ps.persister.loadWarmState()["sentinel"]; !ok {
		t.Fatal("clean snapshot rewritten")
	}
	ps.InvalidateWarm("/a", "test")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ps.persistWarmStateSnapshot()
	if ps.warmRevision == ps.warmPersistedRevision {
		t.Fatal("failed write cleared dirty")
	}
}

func TestProbeConcurrentSnapshotsAndMutation(t *testing.T) {
	ps := NewProbeScheduler(nil, nil, nil, nil, nil)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			file := FileItem{DisplayPath: fmt.Sprintf("/file-%d", id)}
			for i := 0; i < 100; i++ {
				ps.recordTerminal(file, probeSourceFSList, probeStatusSuccess, 1, probeExecutionResult{})
				ps.RecordConsumerHit(file, consumerScenarioHTTP)
				ps.Stats()
				ps.InvalidateWarm(file.DisplayPath, "test")
			}
		}(worker)
	}
	wg.Wait()
	if len(ps.copyWarmStates()) != 4 {
		t.Fatal("lost concurrent warm state")
	}
}

func BenchmarkProbeStatsWarmActive(b *testing.B) {
	ps := NewProbeScheduler(nil, nil, nil, nil, nil)
	now := time.Now()
	for i := 0; i < 1000; i++ {
		ps.successfulWarm[fmt.Sprint(i)] = probeWarmState{FinishedAt: now}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ps.Stats()
	}
}

func BenchmarkProbeCleanWarmPersistence(b *testing.B) {
	ps := NewProbeScheduler(nil, nil, nil, nil, nil)
	ps.persister = &probePersister{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ps.persistWarmStateSnapshot()
	}
}
