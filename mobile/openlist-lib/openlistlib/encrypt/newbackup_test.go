package encrypt

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestProxyLifecycleStopFlushesPlaybackSessions(t *testing.T) {
	p := lifecycleTestServer(t)
	p.ensurePlaybackSessionTracker().record("/movie.mp4", "provider", "video/mp4", 4096, 8192, 1, false, 0, 2, 3, 4)
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	reopened, err := newLocalStore(filepath.Dir(p.config.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rows, err := reopened.ListPlaybackStats(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("session not persisted before close: %d rows", len(rows))
	}
}

func TestProxyLifecycleStoreBackupSynchronousBeforeMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local_media.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, backupTestOldSchema)
	before := backupTestSchema(t, db)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	type constructorResult struct {
		store *localStore
		err   error
	}
	result := make(chan constructorResult, 1)
	defer unblock()
	go func() {
		store, err := newLocalStoreWithBackup(dir, func(got string) error {
			if got != path {
				return errors.New("backup received wrong database path")
			}
			close(entered)
			<-release
			return backupLocalStoreDB(got)
		})
		result <- constructorResult{store, err}
	}()
	lifecycleWait(t, entered)
	if got := backupTestSchema(t, db); got != before {
		t.Fatal("schema changed while startup backup was blocked")
	}
	select {
	case got := <-result:
		if got.store != nil {
			_ = got.store.Close()
		}
		t.Fatalf("constructor returned before backup completed: %v", got.err)
	case <-time.After(30 * time.Millisecond):
	}
	unblock()
	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		defer got.store.Close()
		if backupTestSchema(t, db) == before {
			t.Fatal("constructor did not initialize/migrate schema after backup")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("constructor did not finish after backup completed")
	}
	paths, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(paths) != 1 {
		t.Fatalf("startup snapshots: %v, %v", paths, err)
	}
	snapshot := backupTestOpenDB(t, filepath.Join(paths[0], "database.sqlite"), true)
	if got := backupTestSchema(t, snapshot); got != before {
		t.Fatal("startup snapshot contains migrated schema instead of pre-migration schema")
	}
}

func TestProxyLifecycleStoreBackupFailurePreventsSchemaInit(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "old-schema"}[existing], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "local_media.db")
			var before string
			if existing {
				db := backupTestOpenDB(t, path, false)
				backupTestExec(t, db, backupTestOldSchema)
				before = backupTestSchema(t, db)
			}
			failure := errors.New("snapshot unavailable")
			calls := 0
			store, err := newLocalStoreWithBackup(dir, func(got string) error {
				calls++
				if got != path {
					t.Errorf("backup path = %q, want %q", got, path)
				}
				return failure
			})
			if store != nil {
				_ = store.Close()
				t.Fatal("backup failure returned a usable store")
			}
			if !errors.Is(err, failure) || calls != 1 {
				t.Fatalf("failure = %v, backup calls = %d", err, calls)
			}
			if existing {
				db := backupTestOpenDB(t, path, true)
				if backupTestSchema(t, db) != before {
					t.Fatal("backup failure mutated old schema")
				}
			} else {
				backupTestAssertMissing(t, path)
			}
		})
	}
}

func TestProxyLifecycleStoreBackupUniqueSnapshots(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local_media.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value TEXT NOT NULL); INSERT INTO fixture VALUES ('first')")
	if err := backupLocalStoreDB(path); err != nil {
		t.Fatal(err)
	}
	first, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(first) != 1 {
		t.Fatalf("first snapshots: %v %v", first, err)
	}
	backupTestExec(t, db, "UPDATE fixture SET value = 'second'")
	if err := backupLocalStoreDB(path); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(paths) != 2 {
		t.Fatalf("distinct snapshots: %v %v", paths, err)
	}
	old := backupTestOpenDB(t, filepath.Join(first[0], "database.sqlite"), true)
	var value string
	if err := old.QueryRow("SELECT value FROM fixture").Scan(&value); err != nil || value != "first" {
		t.Fatalf("prior snapshot overwritten: %q %v", value, err)
	}
}
