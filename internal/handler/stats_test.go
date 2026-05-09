package handler

import "testing"

func TestGetStreamStats(t *testing.T) {
	stats := map[string]interface{}{
		"stream": map[string]interface{}{
			"final_passthrough_count": uint64(3),
			"size_conflict_count":     2,
			"strategy_fallback_count": float64(5),
		},
	}

	got := getStreamStats(stats)
	if got["final_passthrough_count"] != 3 {
		t.Fatalf("final_passthrough_count=%d, want 3", got["final_passthrough_count"])
	}
	if got["size_conflict_count"] != 2 {
		t.Fatalf("size_conflict_count=%d, want 2", got["size_conflict_count"])
	}
	if got["strategy_fallback_count"] != 5 {
		t.Fatalf("strategy_fallback_count=%d, want 5", got["strategy_fallback_count"])
	}
}

func TestGetStreamStatsMissingStream(t *testing.T) {
	got := getStreamStats(map[string]interface{}{})
	if got["final_passthrough_count"] != 0 || got["size_conflict_count"] != 0 || got["strategy_fallback_count"] != 0 {
		t.Fatalf("unexpected non-zero stats: %#v", got)
	}
}

func TestGetSelectorStats(t *testing.T) {
	want := map[string]interface{}{
		"reason_counts":     map[string]uint64{"timeout": 3},
		"provider_strategy": map[string]string{"a.example.com": "full"},
		"recent_events":     []interface{}{},
	}
	stats := map[string]interface{}{
		"strategy_selector": want,
	}
	got := getSelectorStats(stats)
	if got["reason_counts"] == nil {
		t.Fatalf("missing reason_counts: %#v", got)
	}
	if got["provider_strategy"] == nil {
		t.Fatalf("missing provider_strategy: %#v", got)
	}
}
