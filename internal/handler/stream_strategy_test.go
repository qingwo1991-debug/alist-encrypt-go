package handler

import (
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

func TestIsNonStrategyFailureTimeout(t *testing.T) {
	if !isNonStrategyFailure("timeout") {
		t.Fatalf("expected timeout to be non-strategy failure")
	}
	if isNonStrategyFailure("html_response") {
		t.Fatalf("expected html_response to be strategy failure")
	}
}

func TestStrategySelectorStatsIncludesObservability(t *testing.T) {
	cfg := config.DefaultConfig()
	selector, err := NewStrategySelector(cfg, NewMemoryStrategyStore())
	if err != nil {
		t.Fatalf("failed to create selector: %v", err)
	}

	provider := "demo.example.com::/a/b.mp4"
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")

	stats := selector.Stats()
	reasons, ok := stats["reason_counts"].(map[string]uint64)
	if !ok {
		t.Fatalf("reason_counts type mismatch: %#v", stats["reason_counts"])
	}
	if reasons["range_unsupported"] == 0 {
		t.Fatalf("reason_counts missing range_unsupported: %#v", reasons)
	}

	providerStrategy, ok := stats["provider_strategy"].(map[string]string)
	if !ok {
		t.Fatalf("provider_strategy type mismatch: %#v", stats["provider_strategy"])
	}
	if _, ok := providerStrategy["demo.example.com"]; !ok {
		t.Fatalf("provider strategy missing provider host key: %#v", providerStrategy)
	}
}
