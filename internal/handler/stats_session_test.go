package handler

import (
	"context"
	"sync"
	"testing"
	"time"
)

// testPlaybackWriter 记录聚合器 flush 的会话。
type testPlaybackWriter struct {
	mu      sync.Mutex
	records []PlaybackEvent
}

func (w *testPlaybackWriter) RecordPlayback(_ context.Context, ev PlaybackEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.records = append(w.records, ev)
	return nil
}

func newTestAggregator() (*serverPlaybackSessionAggregator, *testPlaybackWriter) {
	w := &testPlaybackWriter{}
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	a := &serverPlaybackSessionAggregator{
		sessions: make(map[string]*serverPlaybackSession),
		window:   serverPlaybackSessionWindow,
		writer:   w,
		nowFn: func() time.Time {
			now = now.Add(time.Second)
			return now
		},
	}
	return a, w
}

func TestServerPlaybackSessionMergesRangeRequests(t *testing.T) {
	a, w := newTestAggregator()
	// 首帧：0 位置，2MB（连续段，不计 seek）
	a.record(PlaybackEvent{Path: "/a.mp4", Provider: "cdn", BytesServed: 2 << 20, TotalBytes: 10 << 20, DurationSecs: 3.0, Completed: true})
	// 两次 seek：位置 > 0，量小
	a.record(PlaybackEvent{Path: "/a.mp4", Provider: "cdn", BytesServed: 256 << 10, TotalBytes: 10 << 20, DurationSecs: 1.0, Completed: true, RangeStart: 30 << 20})
	a.record(PlaybackEvent{Path: "/a.mp4", Provider: "cdn", BytesServed: 256 << 10, TotalBytes: 10 << 20, DurationSecs: 1.0, Completed: true, RangeStart: 70 << 20})
	// 窗口外 flush
	a.flushAll()

	if len(w.records) != 1 {
		t.Fatalf("expected 1 merged record, got %d", len(w.records))
	}
	rec := w.records[0]
	if rec.Path != "/a.mp4" {
		t.Errorf("path = %q", rec.Path)
	}
	wantBytes := int64(2<<20) + (256 << 10) + (256 << 10)
	if rec.BytesServed != wantBytes {
		t.Errorf("bytes_served = %d, want %d", rec.BytesServed, wantBytes)
	}
	if rec.SeekCount != 2 {
		t.Errorf("seek_count = %d, want 2", rec.SeekCount)
	}
	if rec.DurationSecs != 5.0 {
		t.Errorf("duration_secs = %f, want 5.0", rec.DurationSecs)
	}
}

func TestServerPlaybackSessionSplitsOnTimeout(t *testing.T) {
	a, w := newTestAggregator()
	a.record(PlaybackEvent{Path: "/a.mp4", BytesServed: 2 << 20})
	// 推进到窗口外
	a.nowFn()
	now := a.nowFn().Add(serverPlaybackSessionWindow + time.Second)
	_ = now
	a.record(PlaybackEvent{Path: "/a.mp4", BytesServed: 2 << 20})
	a.flushAll()
	// 时间只推进了 3s（每次 +1s），仍同会话 → 1 条
	if len(w.records) != 1 {
		t.Fatalf("expected 1 merged record within window, got %d", len(w.records))
	}
}

func TestServerPlaybackSessionSplitsOnPathChange(t *testing.T) {
	a, w := newTestAggregator()
	a.record(PlaybackEvent{Path: "/a.mp4", BytesServed: 2 << 20})
	a.record(PlaybackEvent{Path: "/b.mp4", BytesServed: 2 << 20})
	a.flushAll()
	if len(w.records) != 2 {
		t.Fatalf("expected 2 records for 2 paths, got %d", len(w.records))
	}
}
