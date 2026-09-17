package config

import "testing"

func TestDebugAccessors(t *testing.T) {
	cfg := &Config{Debug: &DebugConfig{Enabled: true, Token: "sekrit", MaxLogLines: 42}}
	if !cfg.DebugEnabled() {
		t.Fatal("DebugEnabled() = false, want true")
	}
	if got := cfg.DebugToken(); got != "sekrit" {
		t.Fatalf("DebugToken() = %q, want %q", got, "sekrit")
	}
	if got := cfg.DebugMaxLogLines(); got != 42 {
		t.Fatalf("DebugMaxLogLines() = %d, want 42", got)
	}
}

func TestDebugAccessorsDefaults(t *testing.T) {
	// nil debug config must stay fully disabled with default sizing — debug
	// mode must never turn on implicitly.
	cfg := &Config{}
	if cfg.DebugEnabled() {
		t.Fatal("DebugEnabled() = true when no debug config present")
	}
	if got := cfg.DebugToken(); got != "" {
		t.Fatalf("DebugToken() = %q, want empty", got)
	}
	if got := cfg.DebugMaxLogLines(); got != 500 {
		t.Fatalf("DebugMaxLogLines() = %d, want 500", got)
	}
}

func TestDebugMaxLogLinesBounds(t *testing.T) {
	if got := (&Config{Debug: &DebugConfig{MaxLogLines: -5}}).DebugMaxLogLines(); got != 500 {
		t.Fatalf("negative MaxLogLines = %d, want default 500", got)
	}
	if got := (&Config{Debug: &DebugConfig{MaxLogLines: 9999999}}).DebugMaxLogLines(); got != 100000 {
		t.Fatalf("huge MaxLogLines = %d, want capped 100000", got)
	}
}
