package config

import (
	"encoding/json"
	"github.com/alist-encrypt-go/internal/recovery"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecoverySurvivesManagedConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.configPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(filepath.Join(dir, recovery.SidecarName), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.BindRecoveryState(recovery.Load(dir))
	next := cfg.AlistServerSnapshot()
	next.FilenameWriteLimits = nil
	next.PasswdList = nil
	if err := cfg.UpdateAlistServer(next); err != nil {
		t.Fatal(err)
	}
	cfg.BindRecoveryState(recovery.Load(t.TempDir()))
	if !cfg.RecoveryRequired() {
		t.Fatal("management/rebinding cleared fence")
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "recovery") {
		t.Fatal("runtime state serialized")
	}
}
