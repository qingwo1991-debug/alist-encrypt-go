package encrypt

import (
	"testing"
	"time"
)

func TestProbeStrategyThresholdAndFailureReset(t *testing.T) {
	ClearAllProbeStrategies()
	defer ClearAllProbeStrategies()

	p := &ProxyServer{config: &ProxyConfig{
		ProbeStrategyTTLMinutes:       30,
		ProbeStrategyStableThreshold:  2,
		ProbeStrategyFailureThreshold: 2,
	}}
	key := "enc/*"

	p.updateProbeStrategy(key, ProbeMethodRange)
	st := p.getProbeStrategy(key)
	if st == nil {
		t.Fatalf("expected strategy to exist after first success")
	}
	st.mutex.Lock()
	if st.SuccessCount != 1 {
		t.Fatalf("expected success count 1, got %d", st.SuccessCount)
	}
	st.mutex.Unlock()

	p.updateProbeStrategy(key, ProbeMethodRange)
	st = p.getProbeStrategy(key)
	if st == nil {
		t.Fatalf("expected strategy to exist after second success")
	}
	st.mutex.Lock()
	if st.SuccessCount != 2 {
		t.Fatalf("expected success count 2, got %d", st.SuccessCount)
	}
	st.mutex.Unlock()

	p.markProbeStrategyFailure(key, ProbeMethodRange)
	if p.getProbeStrategy(key) == nil {
		t.Fatalf("strategy should still exist after first failure")
	}

	p.markProbeStrategyFailure(key, ProbeMethodRange)
	if p.getProbeStrategy(key) != nil {
		t.Fatalf("strategy should be cleared after reaching failure threshold")
	}
}

func TestProbeStrategyTTLExpiration(t *testing.T) {
	ClearAllProbeStrategies()
	defer ClearAllProbeStrategies()

	p := &ProxyServer{config: &ProxyConfig{
		ProbeStrategyTTLMinutes:       1,
		ProbeStrategyStableThreshold:  2,
		ProbeStrategyFailureThreshold: 2,
	}}
	key := "movie_encrypt/*"

	p.updateProbeStrategy(key, ProbeMethodHead)
	st := p.getProbeStrategy(key)
	if st == nil {
		t.Fatalf("expected strategy to exist")
	}
	st.mutex.Lock()
	st.UpdatedAt = time.Now().Add(-2 * time.Minute)
	st.mutex.Unlock()

	if got := p.getProbeStrategy(key); got != nil {
		t.Fatalf("expected expired strategy to be removed")
	}
}

func TestApplyLearningDefaults(t *testing.T) {
	cfg := &ProxyConfig{}
	applyLearningDefaults(cfg)
	if cfg.ProbeStrategyTTLMinutes != defaultProbeStrategyTTLMinutes {
		t.Fatalf("unexpected probe strategy ttl default: %d", cfg.ProbeStrategyTTLMinutes)
	}
	if cfg.ProbeStrategyStableThreshold != int(defaultProbeStrategyStableThreshold) {
		t.Fatalf("unexpected stable threshold default: %d", cfg.ProbeStrategyStableThreshold)
	}
	if cfg.ProbeStrategyFailureThreshold != int(defaultProbeStrategyFailureThreshold) {
		t.Fatalf("unexpected failure threshold default: %d", cfg.ProbeStrategyFailureThreshold)
	}
	if cfg.SizeMapTTL != defaultSizeMapTTLMinutes {
		t.Fatalf("unexpected size map ttl default: %d", cfg.SizeMapTTL)
	}
	if cfg.RangeCompatTTL != defaultRangeCompatTTLMinutes {
		t.Fatalf("unexpected range compat ttl default: %d", cfg.RangeCompatTTL)
	}
	if cfg.LocalSizeRetentionDays != defaultLocalSizeRetentionDays {
		t.Fatalf("unexpected local size retention default: %d", cfg.LocalSizeRetentionDays)
	}
	if cfg.LocalStrategyRetentionDays != defaultLocalStrategyRetentionDays {
		t.Fatalf("unexpected local strategy retention default: %d", cfg.LocalStrategyRetentionDays)
	}
}
