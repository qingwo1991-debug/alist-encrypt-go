package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigGeneratesRandomJWTSecret(t *testing.T) {
	baseDir := t.TempDir()
	cfg := loadConfigAt(filepath.Join(baseDir, "conf", "config.json"))

	if cfg.JWTSecret == "" {
		t.Fatal("expected generated jwt secret")
	}
	if cfg.JWTSecret == "alist-encrypt-secret" {
		t.Fatal("expected non-default jwt secret")
	}
	if len(cfg.JWTSecret) != 64 {
		t.Fatalf("jwt secret len=%d, want 64", len(cfg.JWTSecret))
	}
}

func TestConfigSaveUses0600Permissions(t *testing.T) {
	baseDir := t.TempDir()
	cfg := loadConfigAt(filepath.Join(baseDir, "conf", "config.json"))
	if err := cfg.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(filepath.Join(baseDir, "conf", "config.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%#o, want %#o", got, 0o600)
	}
}

func TestConfigSavePreservesDatabaseConfig(t *testing.T) {
	baseDir := t.TempDir()
	cfg := loadConfigAt(filepath.Join(baseDir, "conf", "config.json"))
	cfg.Database.Type = "mysql"
	cfg.Database.DSN = "user:pass@tcp(localhost:3306)/alist"
	if err := cfg.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(baseDir, "conf", "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Contains(data, []byte(`"database"`)) {
		t.Fatalf("saved config missing database section: %s", data)
	}
	if !bytes.Contains(data, []byte(`"type": "mysql"`)) {
		t.Fatalf("saved config missing database type: %s", data)
	}
}
