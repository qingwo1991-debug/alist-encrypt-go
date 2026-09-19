package handler

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
)

// newAsyncStatsStore returns a StatsStore plus its backing store so tests can
// inspect write-transaction accounting.
func newAsyncStatsStore(t *testing.T) (*StatsStore, *storage.Store) {
	t.Helper()
	st, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ss := NewStatsStore(st)
	t.Cleanup(ss.Stop)
	return ss, st
}

// TestStatsQueuedEventsFlushAsOneWriteTransaction proves the batched-writer
// contract: a burst of playback events goes through a single BoltDB write
// transaction. Before the async rewrite every event was its own transaction.
func TestStatsQueuedEventsFlushAsOneWriteTransaction(t *testing.T) {
	ss, st := newAsyncStatsStore(t)
	const n = 500
	start := st.WriteTxnCount()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("f%04d.mp4", i)
		if err := ss.RecordPlayback(context.Background(), PlaybackEvent{
			Path: "/movies/" + name, BytesServed: 100, PlayedAt: time.Now(),
		}); err != nil {
			t.Fatalf("RecordPlayback: %v", err)
		}
	}
	if err := ss.flushPending(); err != nil {
		t.Fatalf("flushPending: %v", err)
	}
	delta := st.WriteTxnCount() - start
	if delta != 1 {
		t.Fatalf("%d queued events flushed in %d write transactions, want 1", n, delta)
	}

	plays, err := ss.ListPlayback(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListPlayback: %v", err)
	}
	if len(plays) != n {
		t.Fatalf("ListPlayback returned %d events, want %d", len(plays), n)
	}
}

// TestStatsStoreRestartSurvivesDrainedQueue 停服会冲刷排队事件；即使新建一个
// StatsStore（内存索引清空）也能从持久化 last_play 索引点查回上次播放时间。
func TestStatsStoreRestartSurvivesDrainedQueue(t *testing.T) {
	ss, st := newAsyncStatsStore(t)

	playedAt := time.Now().Add(-time.Hour)
	if err := ss.RecordPlayback(context.Background(), PlaybackEvent{Path: "/a/b.mp4", PlayedAt: playedAt}); err != nil {
		t.Fatalf("RecordPlayback: %v", err)
	}
	if err := ss.RecordPlayback(context.Background(), PlaybackEvent{Path: "/a/b.mp4", PlayedAt: playedAt.Add(time.Minute)}); err != nil {
		t.Fatalf("RecordPlayback: %v", err)
	}
	ss.Stop() // 冲刷 + 停 writer；stone Cleanup 幂等

	// 重启视角：同一 bolt 文件上新建 StatsStore（内存索引空），应能点查索引取回最新。
	ss2 := NewStatsStore(st)
	defer ss2.Stop()
	plays, err := ss2.ListPlayback(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListPlayback after restart: %v", err)
	}
	if len(plays) != 2 {
		t.Fatalf("expected 2 playback events after restart, got %d", len(plays))
	}

	lastPlay, ok := ss2.lastPlayForPath("/a/b.mp4")
	if !ok {
		t.Fatal("last_play index missing after restart")
	}
	if want := playedAt.Add(time.Minute); !lastPlay.Equal(want) {
		t.Fatalf("last_play after restart = %v, want %v", lastPlay, want)
	}
}

// TestStatsDeletionKeepsIndexAndSinceLastPlay 删除入队仍正确反查最近播放。
func TestStatsDeletionUsesIndexForSinceLastPlay(t *testing.T) {
	ss, _ := newAsyncStatsStore(t)
	playedAt := time.Now().Add(-90 * time.Minute)
	if err := ss.RecordPlayback(context.Background(), PlaybackEvent{Path: "/x/y.mp4", PlayedAt: playedAt}); err != nil {
		t.Fatalf("RecordPlayback: %v", err)
	}
	if err := ss.RecordDeletion(context.Background(), "/x/y.mp4"); err != nil {
		t.Fatalf("RecordDeletion: %v", err)
	}
	dels, err := ss.ListDeletions(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListDeletions: %v", err)
	}
	if len(dels) != 1 {
		t.Fatalf("expected 1 deletion, got %d", len(dels))
	}
	if wantSecs := 90.0 * 60; dels[0].SinceLastPlaySecs < wantSecs-10 || dels[0].SinceLastPlaySecs > wantSecs+10 {
		t.Fatalf("SinceLastPlaySecs = %f, want ~%f", dels[0].SinceLastPlaySecs, wantSecs)
	}
}

// TestStatsClearAlsoClearsIndex 清空统计时同步清除 last_play 索引。
func TestStatsClearAlsoClearsIndex(t *testing.T) {
	ss := newTestStatsStore(t)
	_ = ss.RecordPlayback(context.Background(), PlaybackEvent{Path: "/z.mp4", PlayedAt: time.Now()})
	if err := ss.ClearPlaybackStats(); err != nil {
		t.Fatalf("ClearPlaybackStats: %v", err)
	}
	if _, ok := ss.lastPlayForPath("/z.mp4"); ok {
		t.Fatal("last_play index survived ClearPlaybackStats")
	}
	if plays, _ := ss.ListPlayback(context.Background(), 0); len(plays) != 0 {
		t.Fatalf("expected 0 playbacks after clear, got %d", len(plays))
	}
}
