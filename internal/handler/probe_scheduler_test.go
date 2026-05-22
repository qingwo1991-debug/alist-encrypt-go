package handler

import (
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func TestProbeSchedulerWarmStateLifecycleAndRecordBackfill(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.UpstreamStalenessMinutes = 1
	ps := &ProbeScheduler{cfg: cfg}

	file := FileItem{
		DisplayPath:   "/movie.mp4",
		EncryptedPath: "/enc/movie.mp4",
		TargetURL:     "https://example.com/raw",
		FileName:      "movie.mp4",
	}

	ps.recordTerminal(file, probeSourceFirstFrame, probeStatusSuccess, 4096, probeExecutionResult{
		resolvedSize: 4096,
		sizeSource:   string(SourceHEAD),
		usedAuthMode: "request",
	})
	ps.RecordConsumerHit(file, consumerScenarioHTTP)
	ps.RecordConsumerHit(file, consumerScenarioHTTP)

	stats := ps.Stats()
	if got := stats["consumer_hit_total"]; got != uint64(1) {
		t.Fatalf("consumer_hit_total=%v, want 1", got)
	}

	records, ok := stats["recent_records"].([]ProbeRecord)
	if !ok || len(records) == 0 {
		t.Fatalf("recent_records=%T len=%d", stats["recent_records"], len(records))
	}
	record := records[0]
	if record.WarmState != warmStateReady {
		t.Fatalf("warm_state=%q, want %q", record.WarmState, warmStateReady)
	}
	if record.ConsumerHitCount != 1 {
		t.Fatalf("consumer_hit_count=%d, want 1", record.ConsumerHitCount)
	}
	if record.Priority != "high" {
		t.Fatalf("priority=%q, want high", record.Priority)
	}
	if record.SizeSource != string(SourceHEAD) {
		t.Fatalf("size_source=%q", record.SizeSource)
	}
	if record.UsedAuthMode != "request" {
		t.Fatalf("used_auth_mode=%q", record.UsedAuthMode)
	}

	ps.recordMu.Lock()
	warm := ps.successfulWarm[file.DisplayPath]
	warm.FinishedAt = time.Now().Add(-2 * time.Minute)
	ps.successfulWarm[file.DisplayPath] = warm
	ps.applyWarmStateToRecordsLocked(file.DisplayPath, warm, time.Now())
	ps.recordMu.Unlock()

	stats = ps.Stats()
	warmStateCounts, ok := stats["warm_state_counts"].(map[string]uint64)
	if !ok {
		t.Fatalf("warm_state_counts=%T", stats["warm_state_counts"])
	}
	if warmStateCounts[warmStateStale] != 1 {
		t.Fatalf("stale count=%d, want 1", warmStateCounts[warmStateStale])
	}

	ps.InvalidateWarm(file.DisplayPath, "upstream_4xx")
	stats = ps.Stats()
	warmStateCounts = stats["warm_state_counts"].(map[string]uint64)
	if warmStateCounts[warmStateInvalid] != 1 {
		t.Fatalf("invalid count=%d, want 1", warmStateCounts[warmStateInvalid])
	}

	records = stats["recent_records"].([]ProbeRecord)
	if !records[0].Invalidated {
		t.Fatal("expected record invalidated flag to be true")
	}
	if records[0].WarmState != warmStateInvalid {
		t.Fatalf("warm_state=%q, want %q", records[0].WarmState, warmStateInvalid)
	}

	invalidations, ok := stats["recent_invalidations"].([]ProbeInvalidation)
	if !ok || len(invalidations) != 1 {
		t.Fatalf("recent_invalidations=%T len=%d", stats["recent_invalidations"], len(invalidations))
	}
	if invalidations[0].Reason != "upstream_4xx" {
		t.Fatalf("reason=%q", invalidations[0].Reason)
	}
}
