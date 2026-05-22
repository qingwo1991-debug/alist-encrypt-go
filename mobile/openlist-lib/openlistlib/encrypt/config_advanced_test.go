package encrypt

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetAdvancedConfigFromJSON_Persisted(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "encrypt_config.json")
	manager := NewConfigManager(configPath)
	if err := manager.Load(); err != nil {
		t.Fatalf("Load default config failed: %v", err)
	}

	payload := `{
		"playFirstFallback": true,
		"enableRangeCompatCache": true,
		"rangeCompatTtlMinutes": 43200,
		"rangeCompatMinFailures": 2,
		"rangeSkipMaxBytes": 268435456,
		"enableParallelDecrypt": true,
		"parallelDecryptConcurrency": 8,
		"streamBufferKb": 1024,
		"webdavNegativeCacheTtlMinutes": 10
	}`
	if err := manager.SetAdvancedConfigFromJSON(payload); err != nil {
		t.Fatalf("SetAdvancedConfigFromJSON failed: %v", err)
	}

	reloaded := NewConfigManager(configPath)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload config failed: %v", err)
	}
	cfg := reloaded.GetConfig()
	if !cfg.EnableParallelDecrypt || cfg.ParallelDecryptConcurrency != 8 {
		t.Fatalf("unexpected parallel decrypt config: enabled=%v conc=%d", cfg.EnableParallelDecrypt, cfg.ParallelDecryptConcurrency)
	}
	if !cfg.EnableRangeCompatCache || cfg.RangeCompatMinFailures != 2 || cfg.RangeSkipMaxBytes != defaultRangeSkipMaxBytes {
		t.Fatalf("unexpected range config: enabled=%v min=%d skip=%d", cfg.EnableRangeCompatCache, cfg.RangeCompatMinFailures, cfg.RangeSkipMaxBytes)
	}
	if cfg.StreamBufferKB != 1024 {
		t.Fatalf("unexpected stream buffer: %d", cfg.StreamBufferKB)
	}
}

func TestSetAdvancedConfigFromJSON_ClampDefaults(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "encrypt_config.json")
	manager := NewConfigManager(configPath)
	if err := manager.Load(); err != nil {
		t.Fatalf("Load default config failed: %v", err)
	}

	payload := `{
		"rangeCompatMinFailures": 0,
		"rangeSkipMaxBytes": 0,
		"parallelDecryptConcurrency": 0,
		"streamBufferKb": 0,
		"webdavNegativeCacheTtlMinutes": 0
	}`
	if err := manager.SetAdvancedConfigFromJSON(payload); err != nil {
		t.Fatalf("SetAdvancedConfigFromJSON failed: %v", err)
	}
	cfg := manager.GetConfig()
	if cfg.RangeCompatMinFailures != 2 {
		t.Fatalf("unexpected range min failures: %d", cfg.RangeCompatMinFailures)
	}
	if cfg.RangeSkipMaxBytes != defaultRangeSkipMaxBytes {
		t.Fatalf("unexpected range skip max bytes: %d", cfg.RangeSkipMaxBytes)
	}
	if cfg.ParallelDecryptConcurrency != 8 {
		t.Fatalf("unexpected parallel decrypt concurrency: %d", cfg.ParallelDecryptConcurrency)
	}
	if cfg.StreamBufferKB != 1024 {
		t.Fatalf("unexpected stream buffer kb: %d", cfg.StreamBufferKB)
	}
	if cfg.WebDAVNegativeCacheTTLMinutes != 10 {
		t.Fatalf("unexpected webdav negative ttl: %d", cfg.WebDAVNegativeCacheTTLMinutes)
	}
}

func TestLoadLegacyDefaultsForBoolAdvancedFlags(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "encrypt_config.json")
	raw := `{
		"enableParallelDecrypt": false,
		"parallelDecryptConcurrency": 0,
		"streamBufferKb": 0,
		"enableRangeCompatCache": false,
		"rangeCompatTtlMinutes": 0,
		"rangeCompatMinFailures": 0,
		"rangeSkipMaxBytes": 0
	}`
	if err := os.WriteFile(configPath, []byte(raw), 0644); err != nil {
		t.Fatalf("write config failed: %v", err)
	}
	manager := NewConfigManager(configPath)
	if err := manager.Load(); err != nil {
		t.Fatalf("Load config failed: %v", err)
	}
	cfg := manager.GetConfig()
	if !cfg.EnableParallelDecrypt {
		t.Fatalf("expected legacy default enableParallelDecrypt=true")
	}
	if !cfg.EnableRangeCompatCache {
		t.Fatalf("expected legacy default enableRangeCompatCache=true")
	}
	if cfg.ParallelDecryptConcurrency != 8 || cfg.StreamBufferKB != 1024 {
		t.Fatalf("unexpected parallel defaults: conc=%d stream=%d", cfg.ParallelDecryptConcurrency, cfg.StreamBufferKB)
	}
	if cfg.RangeCompatMinFailures != 2 || cfg.RangeSkipMaxBytes != defaultRangeSkipMaxBytes {
		t.Fatalf("unexpected range defaults: min=%d skip=%d", cfg.RangeCompatMinFailures, cfg.RangeSkipMaxBytes)
	}
}
