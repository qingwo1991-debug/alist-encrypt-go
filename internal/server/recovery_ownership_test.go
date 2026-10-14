//go:build unix

package server

import (
	"context"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/recovery"
	"strings"
	"testing"
)

func TestServerRefusesOwnedStoreBeforeDatabaseBootstrap(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	l, err := recovery.Acquire(context.Background(), cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A deliberately invalid DB configuration must not win over lifetime ownership.
	cfg.Database = &config.DBConfig{Type: "unsupported"}
	if s, err := New(cfg); err == nil {
		if s != nil {
			s.Shutdown(context.Background())
		}
		t.Fatal("server admitted occupied store")
	} else if !strings.Contains(err.Error(), "store ownership") {
		t.Fatalf("database bootstrapped before ownership: %v", err)
	}
}
