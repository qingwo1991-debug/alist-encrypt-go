package config

import "testing"

func TestApplyEnvOverridesDBDisableCleanup(t *testing.T) {
	t.Setenv("DB_DISABLE_CLEANUP", "true")
	t.Setenv("PLAY_FIRST_FALLBACK", "true")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	if cfg.Database == nil || !cfg.Database.DisableCleanup {
		t.Fatalf("expected Database.DisableCleanup=true from env override")
	}
	if !cfg.AlistServer.PlayFirstFallback {
		t.Fatalf("expected PlayFirstFallback=true from env override (overriding default false)")
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

func TestApplyEnvOverridesV2KeyCacheTTL(t *testing.T) {
	t.Setenv("V2_KEY_CACHE_TTL_MINUTES", "2880")

	cfg := DefaultConfig()
	cfg.applyEnvOverrides()
	cfg.normalizeAlistServerTuning()

	if cfg.AlistServer.V2KeyCacheTTLMinutes != 2880 {
		t.Fatalf("V2KeyCacheTTLMinutes=%d, want 2880", cfg.AlistServer.V2KeyCacheTTLMinutes)
	}
}

func TestApplyEnvOverridesSecrets(t *testing.T) {
	t.Setenv("JWT_SECRET", "env-jwt-secret")
	t.Setenv("STATS_PASSWORD", "env-stats-pass")
	t.Setenv("SCAN_USERNAME", "env-scan-user")
	t.Setenv("SCAN_PASSWORD", "env-scan-pass")
	t.Setenv("SCAN_AUTH_HEADER", "env-scan-header")

	cfg := DefaultConfig()
	cfg.JWTSecret = "file-jwt"
	cfg.StatsPassword = "file-stats"
	cfg.AlistServer.ScanUsername = "file-user"
	cfg.AlistServer.ScanPassword = "file-pass"
	cfg.AlistServer.ScanAuthHeader = "file-header"
	cfg.applyEnvOverrides()

	if cfg.JWTSecret != "env-jwt-secret" {
		t.Fatalf("JWTSecret=%q, want env value", cfg.JWTSecret)
	}
	if cfg.StatsPassword != "env-stats-pass" {
		t.Fatalf("StatsPassword=%q, want env value", cfg.StatsPassword)
	}
	if cfg.AlistServer.ScanUsername != "env-scan-user" ||
		cfg.AlistServer.ScanPassword != "env-scan-pass" ||
		cfg.AlistServer.ScanAuthHeader != "env-scan-header" {
		t.Fatalf("scan creds not overridden: %+v", cfg.AlistServer)
	}
}

func TestApplyEnvOverridesSecretsEmptyKeepsFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AlistServer.ScanPassword = "file-pass"
	cfg.applyEnvOverrides()
	if cfg.AlistServer.ScanPassword != "file-pass" {
		t.Fatalf("ScanPassword=%q, want file value when env unset", cfg.AlistServer.ScanPassword)
	}
}
