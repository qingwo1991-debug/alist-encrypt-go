package config

import "testing"

func TestApplyEnvOverridesDBDisableCleanup(t *testing.T) {
	t.Setenv("DB_DISABLE_CLEANUP", "true")
	t.Setenv("PLAY_FIRST_FALLBACK", "false")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Database == nil || !cfg.Database.DisableCleanup {
		t.Fatalf("expected Database.DisableCleanup=true from env override")
	}
	if cfg.AlistServer.PlayFirstFallback {
		t.Fatalf("expected PlayFirstFallback=false from env override")
	}
}

func TestApplyEnvOverridesRangeLearning(t *testing.T) {
	t.Setenv("RANGE_FAIL_TO_DOWNGRADE", "4")
	t.Setenv("RANGE_SUCCESS_TO_RECOVER", "6")
	t.Setenv("RANGE_REPROBE_MINUTES", "45")
	t.Setenv("RANGE_PROBE_TIMEOUT_SECONDS", "12")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()
	cfg.normalizeAlistServerTuning()

	if cfg.AlistServer.RangeFailToDowngrade != 4 {
		t.Fatalf("RangeFailToDowngrade=%d, want 4", cfg.AlistServer.RangeFailToDowngrade)
	}
	if cfg.AlistServer.RangeSuccessToRecover != 6 {
		t.Fatalf("RangeSuccessToRecover=%d, want 6", cfg.AlistServer.RangeSuccessToRecover)
	}
	if cfg.AlistServer.RangeReprobeMinutes != 45 {
		t.Fatalf("RangeReprobeMinutes=%d, want 45", cfg.AlistServer.RangeReprobeMinutes)
	}
	if cfg.AlistServer.RangeProbeTimeoutSeconds != 12 {
		t.Fatalf("RangeProbeTimeoutSeconds=%d, want 12", cfg.AlistServer.RangeProbeTimeoutSeconds)
	}
}
