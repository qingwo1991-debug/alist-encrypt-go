package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
)

// 用临时 BoltDB 构造 StatsStore。
func newTestStatsStore(t *testing.T) *StatsStore {
	t.Helper()
	dir := t.TempDir()
	st, err := storage.NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return NewStatsStore(st)
}

func TestStatsStoreRecordAndListPlayback(t *testing.T) {
	ss := newTestStatsStore(t)
	ctx := context.Background()

	if err := ss.RecordPlayback(ctx, PlaybackEvent{
		Path: "/movies/knmb-042.mp4", Provider: "unicom", BytesServed: 1000, PlayedAt: time.Now(),
	}); err != nil {
		t.Fatalf("RecordPlayback: %v", err)
	}
	plays, err := ss.ListPlayback(ctx, 0)
	if err != nil {
		t.Fatalf("ListPlayback: %v", err)
	}
	if len(plays) != 1 {
		t.Fatalf("expected 1 playback, got %d", len(plays))
	}
	if plays[0].Path != "/movies/knmb-042.mp4" || plays[0].Provider != "unicom" {
		t.Fatalf("unexpected playback record: %+v", plays[0])
	}
}

func TestStatsStoreDeletionComputesSinceLastPlay(t *testing.T) {
	ss := newTestStatsStore(t)
	ctx := context.Background()
	playedAt := time.Now().Add(-2 * time.Hour)

	if err := ss.RecordPlayback(ctx, PlaybackEvent{Path: "/a/b.mp4", PlayedAt: playedAt}); err != nil {
		t.Fatalf("RecordPlayback: %v", err)
	}
	if err := ss.RecordDeletion(ctx, "/a/b.mp4"); err != nil {
		t.Fatalf("RecordDeletion: %v", err)
	}
	dels, err := ss.ListDeletions(ctx, 0)
	if err != nil {
		t.Fatalf("ListDeletions: %v", err)
	}
	if len(dels) != 1 {
		t.Fatalf("expected 1 deletion, got %d", len(dels))
	}
	if dels[0].Path != "/a/b.mp4" {
		t.Fatalf("unexpected deletion path: %s", dels[0].Path)
	}
	if dels[0].SinceLastPlaySecs < 0 {
		t.Fatalf("expected positive since-last-play, got %f", dels[0].SinceLastPlaySecs)
	}
	if want := 2 * 3600; dels[0].SinceLastPlaySecs < float64(want)-10 || dels[0].SinceLastPlaySecs > float64(want)+10 {
		t.Fatalf("expected since-last-play ~%d s, got %f", want, dels[0].SinceLastPlaySecs)
	}
}

func TestStatsExportPasswordProtection(t *testing.T) {
	ss := newTestStatsStore(t)
	_ = ss.RecordPlayback(context.Background(), PlaybackEvent{Path: "/x.mp4", PlayedAt: time.Now()})

	cfg := &config.Config{}
	// 需在 DefaultConfig 基础上设 StatsPassword（用 DefaultConfig 更稳）
	cfg = config.DefaultConfig()
	cfg.StatsPassword = "secret123"

	h := NewStatsExportHandler(cfg, ss)

	// 无密码 → 401
	req := httptest.NewRequest(http.MethodGet, "/api/encrypt/exportStats", nil)
	rr := httptest.NewRecorder()
	h.ExportStats(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without password, got %d", rr.Code)
	}

	// 错误密码 → 401
	req = httptest.NewRequest(http.MethodGet, "/api/encrypt/exportStats?password=wrong", nil)
	rr = httptest.NewRecorder()
	h.ExportStats(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong password, got %d", rr.Code)
	}

	// 正确密码 → 200 + playbacks
	req = httptest.NewRequest(http.MethodGet, "/api/encrypt/exportStats?password=secret123", nil)
	rr = httptest.NewRecorder()
	h.ExportStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct password, got %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); !containsJSON(body, `"playbacks"`) || !containsJSON(body, `"/x.mp4"`) {
		t.Fatalf("expected playbacks in body, got %s", body)
	}

	// 未配置密码 → 404（功能关闭）
	cfg2 := config.DefaultConfig()
	h2 := NewStatsExportHandler(cfg2, ss)
	req = httptest.NewRequest(http.MethodGet, "/api/encrypt/exportStats", nil)
	rr = httptest.NewRecorder()
	h2.ExportStats(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when stats disabled, got %d", rr.Code)
	}
}

func containsJSON(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
