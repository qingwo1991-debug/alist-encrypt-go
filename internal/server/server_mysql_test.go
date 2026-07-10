package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestNewFailsWhenConfiguredDatabaseCannotInitialize(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Database.Type = "unsupported"
	cfg.Database.DSN = "configured"

	srv, err := New(cfg)
	if err == nil {
		if srv != nil {
			_ = srv.store.Close()
		}
		t.Fatal("New succeeded despite an explicitly configured unsupported database")
	}
	if !strings.Contains(err.Error(), "failed to initialize MySQL store") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(cfg.DataDir, "alist-encrypt.db")); !os.IsNotExist(statErr) {
		t.Fatalf("BoltDB fallback was created, stat error: %v", statErr)
	}
}
