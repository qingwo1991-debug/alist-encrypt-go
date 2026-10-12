package encrypt

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestProxyLifecycleStoreBackupJoinedOnClose(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	store, err := newLocalStoreWithBackup(t.TempDir(), func(string) error { close(entered); <-release; return nil })
	if err != nil {
		t.Fatal(err)
	}
	lifecycleWait(t, entered)
	first := make(chan struct{})
	second := make(chan struct{})
	go func() { _ = store.Close(); close(first) }()
	go func() { _ = store.Close(); close(second) }()
	select {
	case <-first:
		t.Fatal("Close abandoned backup")
	case <-second:
		t.Fatal("concurrent Close returned before actual completion")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	lifecycleWait(t, first)
	lifecycleWait(t, second)
	if err := store.db.Ping(); err == nil {
		t.Fatal("SQLite not closed")
	}
}
func TestProxyLifecycleStoreBackupConstructorFailureJoined(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "local_media.db"), 0755); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	completed := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := newLocalStoreWithBackup(dir, func(string) error { close(entered); <-release; return nil })
		result <- err
		close(completed)
	}()
	lifecycleWait(t, entered)
	select {
	case <-completed:
		t.Fatal("failed constructor abandoned backup")
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	lifecycleWait(t, completed)
	if err := <-result; err == nil {
		t.Fatal("expected invalid database path failure")
	}
}
func TestProxyLifecycleStoreBackupUniqueFiles(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "local_media.db")
	if err := os.WriteFile(db, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := backupLocalStoreDB(db); err != nil {
		t.Fatal(err)
	}
	first, err := filepath.Glob(db + ".bak-*")
	if err != nil || len(first) != 1 {
		t.Fatalf("first backups: %v %v", first, err)
	}
	if err := os.WriteFile(db, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := backupLocalStoreDB(db); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(db + ".bak-*")
	if err != nil || len(paths) != 2 {
		t.Fatalf("distinct backups: %v %v", paths, err)
	}
	b, err := os.ReadFile(first[0])
	if err != nil || string(b) != "first" {
		t.Fatalf("prior backup overwritten: %q %v", b, err)
	}
}
