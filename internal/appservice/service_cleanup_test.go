package appservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

func TestCleanupLegacyBoltDBRefusesToDeleteActiveStore(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "alist-encrypt.db")
	want := []byte("active bolt database")
	if err := os.WriteFile(dbPath, want, 0o600); err != nil {
		t.Fatalf("write active database fixture: %v", err)
	}

	svc := New(Deps{
		Cfg:        &config.Config{DataDir: dataDir},
		MySQLStore: &mysqlstore.Store{},
	})
	message, err := svc.CleanupLegacyBoltDB()
	if err == nil {
		t.Fatal("CleanupLegacyBoltDB() error = nil, want safe refusal")
	}
	if message != "" {
		t.Fatalf("CleanupLegacyBoltDB() message = %q, want empty on refusal", message)
	}
	if !strings.Contains(err.Error(), "不能删除") {
		t.Fatalf("CleanupLegacyBoltDB() error = %q, want explicit refusal", err)
	}

	got, readErr := os.ReadFile(dbPath)
	if readErr != nil {
		t.Fatalf("active database was removed: %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("active database content changed: got %q want %q", got, want)
	}
}

func TestCleanupLegacyBoltDBStillRequiresMySQL(t *testing.T) {
	svc := New(Deps{Cfg: &config.Config{DataDir: t.TempDir()}})
	if _, err := svc.CleanupLegacyBoltDB(); err == nil || !strings.Contains(err.Error(), "MySQL") {
		t.Fatalf("CleanupLegacyBoltDB() error = %v, want MySQL requirement", err)
	}
}
