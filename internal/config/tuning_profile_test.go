package config

import "testing"

func TestApplyTuningProfileClient(t *testing.T) {
	t.Setenv("TUNING_PROFILE", "client")
	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	s := cfg.AlistServer
	if s.RangeFailToDowngrade != 2 || s.RangeSuccessToRecover != 5 {
		t.Fatalf("client profile range tuning=%d/%d, want 2/5", s.RangeFailToDowngrade, s.RangeSuccessToRecover)
	}
	if s.ProbeConcurrency != 2 || s.ProbeProviderConcurrency != 1 {
		t.Fatalf("client profile probe concurrency=%d/%d, want 2/1", s.ProbeConcurrency, s.ProbeProviderConcurrency)
	}
	if s.RangeReprobeMinutes != 20 {
		t.Fatalf("client reprobe=%d, want 20", s.RangeReprobeMinutes)
	}
	if s.DecryptedBlockCacheMb != 64 {
		t.Fatalf("client decrypted block cache=%d, want 64", s.DecryptedBlockCacheMb)
	}
	if s.MaxActiveStreams != 8 {
		t.Fatalf("client max streams=%d, want 8", s.MaxActiveStreams)
	}
}

func TestApplyTuningProfileServerIsNoOp(t *testing.T) {
	t.Setenv("TUNING_PROFILE", "server")
	cfg := DefaultConfig()
	cfg.applyEnvOverrides()

	// server profile must keep DefaultConfig values untouched.
	want := DefaultConfig().AlistServer
	got := cfg.AlistServer
	if got.ProbeConcurrency != want.ProbeConcurrency ||
		got.RangeFailToDowngrade != want.RangeFailToDowngrade ||
		got.MaxActiveStreams != want.MaxActiveStreams ||
		got.DecryptedBlockCacheMb != want.DecryptedBlockCacheMb {
		t.Fatalf("server profile altered defaults: %+v vs %+v", got, want)
	}
}

func TestTuningProfileAliasesMobileExe(t *testing.T) {
	for _, name := range []string{"mobile", "exe"} {
		t.Setenv("TUNING_PROFILE", name)
		cfg := DefaultConfig()
		cfg.applyEnvOverrides()
		if cfg.AlistServer.ProbeConcurrency != 2 {
			t.Fatalf("profile %q: probe concurrency=%d, want 2", name, cfg.AlistServer.ProbeConcurrency)
		}
	}
}

func TestExplicitEnvWinsOverTuningProfile(t *testing.T) {
	t.Setenv("TUNING_PROFILE", "client")
	t.Setenv("PROBE_CONCURRENCY", "9")
	t.Setenv("RANGE_SUCCESS_TO_RECOVER", "7")
	cfg := DefaultConfig()
	cfg.applyEnvOverrides()
	if cfg.AlistServer.ProbeConcurrency != 9 {
		t.Fatalf("explicit PROBE_CONCURRENCY should win: got %d", cfg.AlistServer.ProbeConcurrency)
	}
	if cfg.AlistServer.RangeSuccessToRecover != 7 {
		t.Fatalf("explicit RANGE_SUCCESS_TO_RECOVER should win: got %d", cfg.AlistServer.RangeSuccessToRecover)
	}
}
