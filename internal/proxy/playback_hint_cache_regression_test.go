package proxy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestPlaybackHintsHardCapacityAndOldestEviction(t *testing.T) {
	sp := &StreamProxy{playbackHints: make(map[string]recentPlaybackHint)}
	now := time.Now()
	for i := 0; i < maxRecentPlaybackHints; i++ {
		sp.playbackHints[fmt.Sprint(i)] = recentPlaybackHint{Strategy: StreamStrategyRange, UpdatedAt: now}
	}
	sp.playbackHints["0"] = recentPlaybackHint{Strategy: StreamStrategyRange, UpdatedAt: now.Add(-time.Minute)}
	sp.RecordPlaybackHint("new", "storage", StreamStrategyRange)
	if len(sp.playbackHints) != maxRecentPlaybackHints {
		t.Fatalf("entries = %d, want %d", len(sp.playbackHints), maxRecentPlaybackHints)
	}
	if _, ok := sp.playbackHints["0"]; ok {
		t.Fatal("oldest hint was not evicted")
	}
	for i := 0; i < maxRecentPlaybackHints+10; i++ {
		sp.RecordPlaybackHint(fmt.Sprint(i), "storage", StreamStrategyRange)
		if len(sp.playbackHints) > maxRecentPlaybackHints {
			t.Fatal("hard capacity exceeded")
		}
	}
}

func TestPlaybackHintsSweepExpiredOnWrite(t *testing.T) {
	sp := &StreamProxy{playbackHints: map[string]recentPlaybackHint{
		"expired": {Strategy: StreamStrategyRange, UpdatedAt: time.Now().Add(-recentPlaybackHintTTL - time.Second)},
		"fresh":   {Strategy: StreamStrategyRange, UpdatedAt: time.Now()},
	}}
	sp.RecordPlaybackHint("new", "storage", StreamStrategyRange)
	if _, ok := sp.playbackHints["expired"]; ok {
		t.Fatal("unread expired hint survived write cleanup")
	}
	if _, ok := sp.playbackHints["fresh"]; !ok {
		t.Fatal("cleanup removed fresh hint")
	}
}

func TestPlaybackHintsExpiredReadCleansUp(t *testing.T) {
	sp := &StreamProxy{playbackHints: make(map[string]recentPlaybackHint)}
	key := sp.hintKeyFor("file", "storage")
	sp.playbackHints[key] = recentPlaybackHint{Strategy: StreamStrategyRange, UpdatedAt: time.Now().Add(-recentPlaybackHintTTL - time.Second)}
	if _, ok := sp.recentPlaybackStrategy("file", "storage", requestRangeProfile{}); ok {
		t.Fatal("expired hint was returned")
	}
	if _, ok := sp.playbackHints[key]; ok {
		t.Fatal("expired read did not remove hint")
	}
}

func TestPlaybackHintsExpiredReaderPreservesConcurrentRefresh(t *testing.T) {
	sp := &StreamProxy{playbackHints: make(map[string]recentPlaybackHint)}
	key := sp.hintKeyFor("file", "storage")
	observed := recentPlaybackHint{Strategy: StreamStrategyRange, UpdatedAt: time.Now().Add(-recentPlaybackHintTTL - time.Second)}
	sp.playbackHints[key] = observed

	// Model the exact lock-upgrade interleaving: the reader has observed an
	// expired value, then a writer refreshes it before deletion obtains Lock.
	sp.playbackHintsMu.Lock()
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		sp.removeExpiredPlaybackHint(key, observed)
		close(done)
	}()
	<-started
	refreshed := recentPlaybackHint{Strategy: StreamStrategyChunked, UpdatedAt: time.Now()}
	sp.playbackHints[key] = refreshed
	sp.playbackHintsMu.Unlock()
	<-done
	if got := sp.playbackHints[key]; got != refreshed {
		t.Fatalf("expired reader removed concurrent refresh: got %+v", got)
	}
}

func TestPlaybackHintsConcurrentRecordAndRead(t *testing.T) {
	sp := &StreamProxy{}
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 256; i++ {
				key := fmt.Sprintf("%d/%d", worker, i)
				sp.RecordPlaybackHint(key, "storage", StreamStrategyRange)
				sp.recentPlaybackStrategy(key, "storage", requestRangeProfile{})
			}
		}(worker)
	}
	wg.Wait()
	if len(sp.playbackHints) > maxRecentPlaybackHints {
		t.Fatalf("concurrent writes exceeded capacity: %d", len(sp.playbackHints))
	}
}

func BenchmarkPlaybackHintsRead(b *testing.B) {
	sp := &StreamProxy{}
	sp.RecordPlaybackHint("file", "storage", StreamStrategyRange)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sp.recentPlaybackStrategy("file", "storage", requestRangeProfile{})
		}
	})
}

func BenchmarkPlaybackHintsRecordAtCapacity(b *testing.B) {
	sp := &StreamProxy{}
	for i := 0; i < maxRecentPlaybackHints; i++ {
		sp.RecordPlaybackHint(fmt.Sprint(i), "storage", StreamStrategyRange)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sp.RecordPlaybackHint(fmt.Sprint(i), "storage", StreamStrategyRange)
	}
}
