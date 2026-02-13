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
