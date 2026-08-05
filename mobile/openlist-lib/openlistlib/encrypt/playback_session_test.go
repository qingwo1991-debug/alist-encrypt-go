package encrypt

import (
	"testing"
	"time"
)

// testSessionStore 是 localStore 的轻量替身：只记录 flush 的结果。
type testSessionStore struct {
	records []PlaybackStatsRecord
}

func (s *testSessionStore) AppendPlayback(rec PlaybackStatsRecord) error {
	s.records = append(s.records, rec)
	return nil
}

func newTestSessionTracker() (*playbackSessionTracker, *testSessionStore) {
	st := &testSessionStore{}
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	t := &playbackSessionTracker{
		sessions: make(map[string]*playbackSession),
		window:   playbackSessionWindow,
		store:    st,
		nowFn: func() time.Time {
			now = now.Add(time.Second)
			return now
		},
	}
	return t, st
}

func TestPlaybackSessionMergesSeekRequests(t *testing.T) {
	tr, st := newTestSessionTracker()
	// 首帧：0 位置，2MB（连续播放段，不计 seek）
	tr.record("/movies/a.mp4", "cdn", "video/mp4", 2<<20, 10<<20, 3.0, true, 0)
	// 两次 seek：位置 > 0，量小（定位型预取）
	tr.record("/movies/a.mp4", "cdn", "video/mp4", 256<<10, 10<<20, 1.0, true, 30<<20)
	tr.record("/movies/a.mp4", "cdn", "video/mp4", 256<<10, 10<<20, 1.0, true, 70<<20)
	// 时间推进到窗口外，flush 落库
	tr.flushStale(tr.nowFn().Add(playbackSessionWindow + time.Second))

	if len(st.records) != 1 {
		t.Fatalf("expected 1 merged record, got %d", len(st.records))
	}
	rec := st.records[0]
	if rec.Path != "/movies/a.mp4" {
		t.Errorf("path = %q", rec.Path)
	}
	if rec.BytesServed != (2<<20)+(256<<10)+(256<<10) {
		t.Errorf("bytes_served = %d", rec.BytesServed)
	}
	if rec.SeekCount != 2 {
		t.Errorf("seek_count = %d, want 2", rec.SeekCount)
	}
	if rec.DurationSecs != 5.0 {
		t.Errorf("duration_secs = %f, want 5.0", rec.DurationSecs)
	}
}

func TestPlaybackSessionSplitsOnPathChange(t *testing.T) {
	tr, st := newTestSessionTracker()
	tr.record("/movies/a.mp4", "cdn", "video/mp4", 2<<20, 10<<20, 3.0, true, 0)
	tr.record("/movies/b.mp4", "cdn", "video/mp4", 2<<20, 10<<20, 3.0, true, 0)
	tr.flushStale(tr.nowFn().Add(playbackSessionWindow + time.Second))
	if len(st.records) != 2 {
		t.Fatalf("expected 2 records for 2 paths, got %d", len(st.records))
	}
}

func TestPlaybackSessionSplitsOnTimeout(t *testing.T) {
	tr, st := newTestSessionTracker()
	tr.record("/movies/a.mp4", "cdn", "video/mp4", 2<<20, 10<<20, 3.0, true, 0)
	// 模拟暂停后继续：超过窗口
	tr.nowFn()
	tr.nowFn()
	tr.nowFn() // +3s
	tr.record("/movies/a.mp4", "cdn", "video/mp4", 2<<20, 10<<20, 3.0, true, 0)
	tr.flushStale(tr.nowFn().Add(playbackSessionWindow + time.Second))
	// 每次 +1s，第二次 record 距第一次 4s < 30s，仍是同会话。
	if len(st.records) != 1 {
		t.Fatalf("expected 1 merged record within window, got %d", len(st.records))
	}
}

func TestPlaybackSessionCompletedSingleRequest(t *testing.T) {
	tr, st := newTestSessionTracker()
	// 首播即完整：单请求 completed=true。不立即落库，等待窗口 flush。
	tr.record("/movies/c.mp4", "cdn", "video/mp4", 5<<20, 5<<20, 4.0, true, 0)
	if len(st.records) != 0 {
		t.Fatalf("expected no record before flush, got %d", len(st.records))
	}
	tr.flushStale(tr.nowFn().Add(playbackSessionWindow + time.Second))
	if len(st.records) != 1 {
		t.Fatalf("expected 1 record after flush, got %d", len(st.records))
	}
	if st.records[0].Completed != true {
		t.Errorf("completed = %v", st.records[0].Completed)
	}
}

func TestSeekLikeRequestHeuristic(t *testing.T) {
	cases := []struct {
		start, bytes int64
		want         bool
	}{
		{0, 2 << 20, false},
		{30 << 20, 256 << 10, true},
		{30 << 20, 5 << 20, false}, // 大段连续播放（位置>0 但体量大）
	}
	for _, c := range cases {
		if got := isSeekLikeRequest(c.start, c.bytes); got != c.want {
			t.Errorf("isSeekLikeRequest(%d,%d) = %v, want %v", c.start, c.bytes, got, c.want)
		}
	}
}
