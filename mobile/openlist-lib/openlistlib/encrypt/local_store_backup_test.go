package encrypt

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

const backupTestOldSchema = `CREATE TABLE local_media_size (
 key TEXT PRIMARY KEY, provider_host TEXT NOT NULL, original_path TEXT NOT NULL,
 size INTEGER NOT NULL, last_accessed INTEGER NOT NULL, updated_at INTEGER NOT NULL);
 INSERT INTO local_media_size VALUES ('old', 'provider', '/old', 42, 1, 1);`

func backupTestOpenDB(t *testing.T, path string, readonly bool) *sql.DB {
	t.Helper()
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("_busy_timeout", "1000")
	if readonly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rwc")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func backupTestExec(t *testing.T, db *sql.DB, query string) {
	t.Helper()
	if _, err := db.Exec(query); err != nil {
		t.Fatal(err)
	}
}

func backupTestSchema(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query("SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master ORDER BY type, name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result strings.Builder
	for rows.Next() {
		var kind, name, table, statement string
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&result, "%s\t%s\t%s\t%s\n", kind, name, table, statement)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result.String()
}

func backupTestAssertMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected no file at %q, got %v", path, err)
	}
}

func backupTestSnapshot(t *testing.T, path string) string {
	t.Helper()
	dir, err := snapshotLocalStoreDB(context.Background(), path)
	if err != nil || dir == "" {
		t.Fatalf("snapshot = %q, %v", dir, err)
	}
	for _, name := range []string{"database.sqlite", "manifest.json"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("snapshot member %s: %v", name, err)
		}
	}
	return dir
}

func backupTestFileHash(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestLocalStoreSnapshotMissingDatabase(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "missing.db")
	dir, err := snapshotLocalStoreDB(context.Background(), path)
	if err != nil || dir != "" {
		t.Fatalf("missing database snapshot = %q, %v", dir, err)
	}
	if err := backupLocalStoreDB(path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing database created artifacts: %v, %v", entries, err)
	}
}

func TestLocalStoreSnapshotWALCommittedRelationsExcludeUncommitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, `PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
 CREATE TABLE parent(id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
 CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id), version INTEGER NOT NULL);
 INSERT INTO parent VALUES (1, 1); INSERT INTO child VALUES (1, 1, 1);
 PRAGMA wal_checkpoint(TRUNCATE);
 BEGIN; UPDATE parent SET version=2; UPDATE child SET version=2; COMMIT;`)
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("fixture has no committed WAL: %v", err)
	}
	writer := backupTestOpenDB(t, path, false)
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE parent SET version=3; UPDATE child SET version=3"); err != nil {
		t.Fatal(err)
	}
	dir := backupTestSnapshot(t, path)
	snapshot := backupTestOpenDB(t, filepath.Join(dir, "database.sqlite"), true)
	var parent, child int
	if err := snapshot.QueryRow("SELECT parent.version, child.version FROM parent JOIN child ON child.parent_id=parent.id").Scan(&parent, &child); err != nil {
		t.Fatal(err)
	}
	if parent != 2 || child != 2 {
		t.Fatalf("snapshot must include committed WAL, not uncommitted or mixed relation: %d/%d", parent, child)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyLocalStoreSnapshot(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
}

func TestLocalStoreSnapshotConcurrentWALRelations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, `PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
 CREATE TABLE parent(id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
 CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL REFERENCES parent(id), version INTEGER NOT NULL);
 INSERT INTO parent VALUES (1, 0); INSERT INTO child VALUES (1, 1, 0);`)
	stop := make(chan struct{})
	done := make(chan error, 1)
	started := make(chan struct{})
	var once sync.Once
	stopWriter := func() { once.Do(func() { close(stop) }) }
	defer stopWriter()
	go func() {
		for version := 1; ; version++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			tx, err := db.Begin()
			if err == nil {
				_, err = tx.Exec("UPDATE parent SET version=?", version)
				if err == nil {
					_, err = tx.Exec("UPDATE child SET version=?", version)
				}
				if err == nil {
					err = tx.Commit()
				} else {
					_ = tx.Rollback()
				}
			}
			if err != nil {
				done <- err
				return
			}
			if version == 1 {
				close(started)
			}
		}
	}()
	defer func() {
		stopWriter()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("concurrent writer: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("concurrent writer did not stop")
		}
	}()
	lifecycleWait(t, started)
	for i := 0; i < 3; i++ {
		dir := backupTestSnapshot(t, path)
		snapshot := backupTestOpenDB(t, filepath.Join(dir, "database.sqlite"), true)
		var parent, child int
		if err := snapshot.QueryRow("SELECT parent.version, child.version FROM parent JOIN child ON parent.id=child.parent_id").Scan(&parent, &child); err != nil {
			t.Fatal(err)
		}
		if parent != child || parent < 1 {
			t.Fatalf("inconsistent concurrent transaction snapshot: %d/%d", parent, child)
		}
	}
}

func TestLocalStoreSnapshotFailurePreservesPreviousPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "preserve.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES (7)")
	dir := backupTestSnapshot(t, path)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := backupTestFileHash(t, filepath.Join(dir, "database.sqlite"))
	if err := os.WriteFile(path, []byte("corrupt replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := backupLocalStoreDB(path); err == nil {
		t.Fatal("corrupt source backup succeeded")
	}
	if got := backupTestFileHash(t, filepath.Join(dir, "database.sqlite")); got != before {
		t.Fatal("failed backup changed earlier publication")
	}
	if _, err := verifyLocalStoreSnapshot(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 {
		t.Fatalf("failed backup left artifacts: %v, %v", entries, err)
	}
}

func TestLocalStoreSnapshotManifestAndReadOnlyVerification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE z(value TEXT); CREATE TABLE a(value INTEGER); INSERT INTO a VALUES (9)")
	dir := backupTestSnapshot(t, path)
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored localSnapshotManifest
	if err := json.Unmarshal(manifestBytes, &stored); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(dir, "database.sqlite")
	beforeHash := backupTestFileHash(t, database)
	info, err := os.Stat(database)
	if err != nil {
		t.Fatal(err)
	}
	entriesBefore, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := verifyLocalStoreSnapshot(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored, manifest) {
		t.Fatalf("verified manifest differs from published manifest: %+v / %+v", stored, manifest)
	}
	if manifest.FormatVersion <= 0 || manifest.SQLiteVersion == "" || manifest.Semantics == "" {
		t.Fatalf("missing manifest identity/semantics: %+v", manifest)
	}
	if manifest.Size != info.Size() || manifest.SHA256 != beforeHash {
		t.Fatalf("manifest file size/hash do not describe published database: %+v", manifest)
	}
	if decoded, err := hex.DecodeString(manifest.SchemaSHA256); err != nil || len(decoded) != sha256.Size {
		t.Fatalf("invalid schema hash %q", manifest.SchemaSHA256)
	}
	if !sort.StringsAreSorted(manifest.Tables) || !reflect.DeepEqual(manifest.Tables, []string{"a", "z"}) {
		t.Fatalf("manifest tables = %v", manifest.Tables)
	}
	entriesAfter, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if beforeHash != backupTestFileHash(t, database) || !info.ModTime().Equal(backupTestModTime(t, database)) || !reflect.DeepEqual(entriesBefore, entriesAfter) {
		t.Fatal("read-only verification modified database or created sidecars")
	}
}

func backupTestModTime(t *testing.T, path string) time.Time {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.ModTime()
}

func TestLocalStoreSnapshotCompleteSchemaInventoryAndExactTTLValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "complete.db")
	db := backupTestOpenDB(t, path, false)
	if err := initLocalSchema(db); err != nil {
		t.Fatal(err)
	}
	backupTestExec(t, db, `INSERT INTO local_range_compat VALUES ('expired', 1, 8, 2);
 INSERT INTO local_range_probe_target VALUES ('expired', 'https://example.invalid', '/old', 3, 4);
 INSERT INTO local_media_size(key, provider_host, original_path, size, last_accessed, updated_at) VALUES ('expired', 'provider', '/old', 42, 5, 6);
 INSERT INTO local_media_strategy VALUES ('expired', 'wifi', 'range', 'provider', '/old', 7, 8);`)
	before := backupTestSchema(t, db)
	rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	dir := backupTestSnapshot(t, path)
	manifest, err := verifyLocalStoreSnapshot(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.Tables, tables) {
		t.Fatalf("full schema inventory = %v, want %v", manifest.Tables, tables)
	}
	snapshot := backupTestOpenDB(t, filepath.Join(dir, "database.sqlite"), true)
	for _, checked := range []*sql.DB{db, snapshot} {
		if backupTestSchema(t, checked) != before {
			t.Fatal("full schema changed during snapshot")
		}
		for _, fixture := range []struct {
			query string
			want  []int64
		}{
			{"SELECT blocked_until, failures, updated_at FROM local_range_compat WHERE key='expired'", []int64{1, 8, 2}},
			{"SELECT next_probe_at, updated_at FROM local_range_probe_target WHERE key='expired'", []int64{3, 4}},
			{"SELECT size, last_accessed, updated_at FROM local_media_size WHERE key='expired'", []int64{42, 5, 6}},
			{"SELECT last_accessed, updated_at FROM local_media_strategy WHERE key='expired'", []int64{7, 8}},
		} {
			got := make([]int64, len(fixture.want))
			dest := make([]any, len(got))
			for i := range got {
				dest[i] = &got[i]
			}
			if err := checked.QueryRow(fixture.query).Scan(dest...); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, fixture.want) {
				t.Fatalf("snapshot/source TTL fields changed: %s = %v, want %v", fixture.query, got, fixture.want)
			}
		}
	}
}

func TestLocalStoreSnapshotPreservesOldSchemaAndExpiredRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, backupTestOldSchema+`
 CREATE TABLE local_range_compat(key TEXT PRIMARY KEY, blocked_until INTEGER, failures INTEGER, updated_at INTEGER);
 INSERT INTO local_range_compat VALUES ('expired', 1, 8, 1);
 CREATE TABLE local_range_probe_target(key TEXT PRIMARY KEY, sample_url TEXT, source_path TEXT, next_probe_at INTEGER, updated_at INTEGER);
 INSERT INTO local_range_probe_target VALUES ('expired', 'https://example.invalid', '/old', 1, 1);
 CREATE TABLE local_db_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
 INSERT INTO local_db_meta VALUES ('schema_version', '1', 1);`)
	before := backupTestSchema(t, db)
	dir := backupTestSnapshot(t, path)
	if got := backupTestSchema(t, db); got != before {
		t.Fatal("snapshot migrated source database")
	}
	snapshot := backupTestOpenDB(t, filepath.Join(dir, "database.sqlite"), true)
	if got := backupTestSchema(t, snapshot); got != before {
		t.Fatal("snapshot migrated old schema")
	}
	for _, table := range []string{"local_media_size", "local_range_compat", "local_range_probe_target"} {
		var count int
		if err := snapshot.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expired rows discarded from %s: %d, %v", table, count, err)
		}
	}
	var version string
	if err := snapshot.QueryRow("SELECT value FROM local_db_meta WHERE key='schema_version'").Scan(&version); err != nil || version != "1" {
		t.Fatalf("schema version changed: %q, %v", version, err)
	}
}

func TestLocalStoreSnapshotRejectsInvalidSourceWithoutPublishedArtifacts(t *testing.T) {
	for _, kind := range []string{"garbage", "empty", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "bad.db")
			if kind == "directory" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				data := []byte("not a sqlite database")
				if kind == "empty" {
					data = nil
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			dir, err := snapshotLocalStoreDB(context.Background(), path)
			if err == nil || dir != "" {
				t.Fatalf("invalid source snapshot = %q, %v", dir, err)
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 1 {
				t.Fatalf("failed snapshot left artifacts: %v, %v", entries, err)
			}
		})
	}
}

func TestLocalStoreSnapshotCanceledBeforeStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value INTEGER)")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir, err := snapshotLocalStoreDB(ctx, path)
	if !errors.Is(err, context.Canceled) || dir != "" {
		t.Fatalf("canceled snapshot = %q, %v", dir, err)
	}
	paths, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(paths) != 0 {
		t.Fatalf("canceled snapshot published artifacts: %v, %v", paths, err)
	}
}

func TestLocalStoreSnapshotDiskSyncFailureDoesNotPublishOrPrune(t *testing.T) {
	path := filepath.Join(t.TempDir(), "disk.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES (7)")
	previous := backupTestSnapshot(t, path)
	beforeHash := backupTestFileHash(t, filepath.Join(previous, "database.sqlite"))
	backupTestExec(t, db, "UPDATE fixture SET value=8")
	calls := 0
	dir, err := snapshotLocalStoreDBWithSync(context.Background(), path, func(string) error {
		calls++
		return syscall.ENOSPC
	})
	if dir != "" || !errors.Is(err, syscall.ENOSPC) || calls != 1 {
		t.Fatalf("disk-sync failure = %q, %v, calls=%d", dir, err, calls)
	}
	if backupTestFileHash(t, filepath.Join(previous, "database.sqlite")) != beforeHash {
		t.Fatal("disk failure changed previous snapshot")
	}
	if _, err := verifyLocalStoreSnapshot(context.Background(), previous); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 {
		t.Fatalf("disk failure left staging/publication artifacts: %v, %v", entries, err)
	}
}

func TestLocalStoreSnapshotDisposableRestoreRehearsal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES ('recoverable')")
	dir := backupTestSnapshot(t, path)
	if _, err := verifyLocalStoreSnapshot(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	rehearsal := t.TempDir()
	for _, name := range []string{"database.sqlite", "manifest.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rehearsal, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := verifyLocalStoreSnapshot(context.Background(), rehearsal); err != nil {
		t.Fatal(err)
	}
	restored := backupTestOpenDB(t, filepath.Join(rehearsal, "database.sqlite"), true)
	var value string
	if err := restored.QueryRow("SELECT value FROM fixture").Scan(&value); err != nil || value != "recoverable" {
		t.Fatalf("disposable restore query: %q, %v", value, err)
	}
}

func TestLocalStoreSnapshotVerificationRejectsTampering(t *testing.T) {
	for _, kind := range []string{"database", "integrity", "hash", "schema", "size", "tables", "format", "missing-manifest", "invalid-manifest"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tamper.db")
			db := backupTestOpenDB(t, path, false)
			backupTestExec(t, db, "CREATE TABLE fixture(value TEXT); INSERT INTO fixture VALUES ('original')")
			dir := backupTestSnapshot(t, path)
			manifestPath := filepath.Join(dir, "manifest.json")
			bytes, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			var manifest localSnapshotManifest
			if err := json.Unmarshal(bytes, &manifest); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "database":
				mutated := backupTestOpenDB(t, filepath.Join(dir, "database.sqlite"), false)
				backupTestExec(t, mutated, "UPDATE fixture SET value='tampered'")
				if err := mutated.Close(); err != nil {
					t.Fatal(err)
				}
			case "integrity":
				corrupt := []byte("invalid sqlite but correctly hashed")
				if err := os.WriteFile(filepath.Join(dir, "database.sqlite"), corrupt, 0600); err != nil {
					t.Fatal(err)
				}
				manifest.SHA256 = backupTestFileHash(t, filepath.Join(dir, "database.sqlite"))
				manifest.Size = int64(len(corrupt))
			case "hash":
				manifest.SHA256 = strings.Repeat("0", 64)
			case "schema":
				manifest.SchemaSHA256 = strings.Repeat("0", 64)
			case "size":
				manifest.Size++
			case "tables":
				manifest.Tables = []string{"other"}
			case "format":
				manifest.FormatVersion = -1
			case "missing-manifest":
				if err := os.Remove(manifestPath); err != nil {
					t.Fatal(err)
				}
			case "invalid-manifest":
				if err := os.WriteFile(manifestPath, []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "database" && kind != "missing-manifest" && kind != "invalid-manifest" {
				bytes, err = json.Marshal(manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(manifestPath, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := verifyLocalStoreSnapshot(context.Background(), dir); err == nil {
				t.Fatal("verification accepted tampering")
			}
		})
	}
}

type backupTestHandle struct {
	step             func(int) (bool, error)
	finishErr        error
	steps, finishes  int
	remaining, pages int
}

func (h *backupTestHandle) Step(pages int) (bool, error) { h.steps++; return h.step(pages) }
func (h *backupTestHandle) Finish() error                { h.finishes++; return h.finishErr }
func (h *backupTestHandle) Remaining() int               { return h.remaining }
func (h *backupTestHandle) PageCount() int               { return h.pages }

// Rehearse the on-disk state left by interruption after the final-name
// reservation but before rename. Matching .bak-* is never a publication proof.
func TestLocalStoreSnapshotRejectsInterruptedPublicationReservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reservation.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value INTEGER); INSERT INTO fixture VALUES (7)")
	previous := backupTestSnapshot(t, path)
	before := backupTestFileHash(t, filepath.Join(previous, "database.sqlite"))
	for _, kind := range []string{"empty", "database-only", "manifest-only"} {
		reservation, err := os.MkdirTemp(filepath.Dir(path), filepath.Base(path)+".bak-*")
		if err != nil {
			t.Fatal(err)
		}
		var member string
		switch kind {
		case "database-only":
			member = "database.sqlite"
		case "manifest-only":
			member = "manifest.json"
		}
		if member != "" {
			data, err := os.ReadFile(filepath.Join(previous, member))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(reservation, member), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := verifyLocalStoreSnapshot(context.Background(), reservation); err == nil {
			t.Fatalf("accepted interrupted %s reservation as published", kind)
		}
		if _, err := os.Stat(reservation); err != nil {
			t.Fatalf("verification removed unowned/incomplete candidate: %v", err)
		}
	}
	candidates, err := filepath.Glob(path + ".bak-*")
	if err != nil || len(candidates) != 4 {
		t.Fatalf("candidates = %v, %v", candidates, err)
	}
	valid := 0
	for _, candidate := range candidates {
		if _, err := verifyLocalStoreSnapshot(context.Background(), candidate); err == nil {
			valid++
			if candidate != previous {
				t.Fatal("selected incomplete reservation instead of previous snapshot")
			}
		}
	}
	if valid != 1 || before != backupTestFileHash(t, filepath.Join(previous, "database.sqlite")) {
		t.Fatal("interrupted publication changed eligibility or content of previous snapshot")
	}
}

func TestLocalStoreSnapshotCancellationDuringPublicationSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel-sync.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value INTEGER)")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	dir, err := snapshotLocalStoreDBWithSync(ctx, path, func(name string) error {
		calls++
		if err := syncSnapshotPath(name); err != nil {
			return err
		}
		if calls == 4 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || dir == "" || calls != 4 {
		t.Fatalf("publication cancellation = %q, %v, syncs=%d", dir, err, calls)
	}
	if _, err := verifyLocalStoreSnapshot(context.Background(), dir); err != nil {
		t.Fatalf("published good snapshot lost on cancellation: %v", err)
	}
}

func TestLocalStoreSnapshotRejectsWALHeadersAndSidecars(t *testing.T) {
	for _, kind := range []string{"wal-header", "-wal", "-shm", "-journal"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "standalone.db")
			db := backupTestOpenDB(t, path, false)
			backupTestExec(t, db, "CREATE TABLE fixture(value INTEGER)")
			dir := backupTestSnapshot(t, path)
			database := filepath.Join(dir, "database.sqlite")
			if kind == "wal-header" {
				data, err := os.ReadFile(database)
				if err != nil {
					t.Fatal(err)
				}
				data[18], data[19] = 2, 2
				if err := os.WriteFile(database, data, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(database+kind, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyLocalStoreSnapshot(context.Background(), dir); err == nil {
				t.Fatal("accepted a non-self-contained package")
			}
		})
	}
}

func TestLocalStoreSnapshotPrivateMultiStepAndLegacyRetention(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "large.db")
	db := backupTestOpenDB(t, path, false)
	backupTestExec(t, db, "CREATE TABLE fixture(value BLOB); INSERT INTO fixture VALUES (zeroblob(2097152))")
	legacy := path + ".bak-legacy"
	if err := os.WriteFile(legacy, []byte("historical"), 0600); err != nil {
		t.Fatal(err)
	}
	unknown := path + ".bak-unknown"
	if err := os.Mkdir(unknown, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		dir := backupTestSnapshot(t, path)
		for _, name := range []string{"database.sqlite", "manifest.json"} {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("sensitive member permissions: %s %v", name, err)
			}
		}
		copy := backupTestOpenDB(t, filepath.Join(dir, "database.sqlite"), true)
		var pages int
		if err := copy.QueryRow("PRAGMA page_count").Scan(&pages); err != nil || pages <= 128 {
			t.Fatalf("fixture did not force multiple backup steps: %d, %v", pages, err)
		}
	}
	data, err := os.ReadFile(legacy)
	if err != nil || string(data) != "historical" {
		t.Fatalf("legacy backup changed: %q, %v", data, err)
	}
	if info, err := os.Stat(unknown); err != nil || !info.IsDir() {
		t.Fatalf("unknown candidate removed: %v", err)
	}
}

func TestLocalStoreFailedMigrationDoesNotPublishSchemaVersion(t *testing.T) {
	for _, deniedTable := range []string{"local_media_size", "playback_stats"} {
		t.Run(deniedTable, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "migration.db")
			db := backupTestOpenDB(t, path, false)
			backupTestExec(t, db, backupTestOldSchema+`CREATE TABLE local_db_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL);
			INSERT INTO local_db_meta VALUES ('schema_version', '1', 123);`)
			conn, err := db.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Raw(func(driver any) error {
				driver.(*sqlite3.SQLiteConn).RegisterAuthorizer(func(operation int, arg1, arg2, database string) int {
					if operation == sqlite3.SQLITE_ALTER_TABLE && arg2 == deniedTable {
						return sqlite3.SQLITE_DENY
					}
					return sqlite3.SQLITE_OK
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if err := initLocalSchema(db); err == nil {
				t.Fatal("expected denied schema migration")
			}
			var version string
			var updated int64
			if err := db.QueryRow("SELECT value, updated_at FROM local_db_meta WHERE key='schema_version'").Scan(&version, &updated); err != nil {
				t.Fatal(err)
			}
			if version != "1" || updated != 123 {
				t.Fatalf("failed migration published version/timestamp: %q/%d", version, updated)
			}
		})
	}
}

func TestRunSQLiteBackupFinishesExactlyOnce(t *testing.T) {
	stepErr := errors.New("step failure")
	finishErr := errors.New("finish failure")
	for _, kind := range []string{"complete", "step-error", "finish-error", "step-and-finish-error", "canceled", "deadline", "cancel-during-step", "no-progress", "changing-page-count", "progress"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			h := &backupTestHandle{remaining: 10, pages: 10}
			h.step = func(pages int) (bool, error) {
				if pages <= 0 {
					t.Errorf("unbounded/nonpositive page budget: %d", pages)
				}
				return true, nil
			}
			var want error
			switch kind {
			case "step-error":
				h.step = func(int) (bool, error) { return false, stepErr }
				want = stepErr
			case "finish-error":
				h.finishErr = finishErr
				want = finishErr
			case "step-and-finish-error":
				h.step = func(int) (bool, error) { return false, stepErr }
				h.finishErr = finishErr
				want = stepErr
			case "changing-page-count":
				h.step = func(int) (bool, error) { h.pages++; h.remaining++; return false, nil }
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				want = context.DeadlineExceeded
			case "cancel-during-step":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				h.step = func(int) (bool, error) { cancel(); return false, nil }
				want = context.Canceled
			case "no-progress":
				h.step = func(int) (bool, error) { return false, nil }
			case "progress":
				h.step = func(int) (bool, error) { h.remaining--; return h.remaining == 0, nil }
			}
			err := runSQLiteBackup(ctx, h, 20*time.Millisecond)
			if h.finishes != 1 {
				t.Fatalf("Finish calls = %d, want exactly 1", h.finishes)
			}
			if kind == "step-and-finish-error" && !errors.Is(err, finishErr) {
				t.Fatalf("lost Finish error: %v", err)
			}
			if kind == "no-progress" || kind == "changing-page-count" {
				if err == nil {
					t.Fatal("stalled backup succeeded")
				}
			} else if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
			if (kind == "canceled" || kind == "deadline") && h.steps != 0 {
				t.Fatalf("Step called after canceled context: %d", h.steps)
			}
		})
	}
}
