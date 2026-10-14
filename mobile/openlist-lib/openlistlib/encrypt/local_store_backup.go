package encrypt

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/mattn/go-sqlite3"
)

const localSnapshotSemantics = "committed database transactions; excludes unflushed application buffers; no cross-store watermark"
const localSnapshotTimeout = 30 * time.Second
const localSnapshotStallLimit = 2 * time.Second

// These are database snapshots, not live restore packages. Restoring old audit
// state requires an exclusive service stop and a reconciliation/write fence;
// neither a live restore API nor a runtime worker is introduced here.
type localSnapshotManifest struct {
	FormatVersion int      `json:"format_version"`
	Component     string   `json:"component"`
	CreatedAt     string   `json:"created_at"`
	SQLiteVersion string   `json:"sqlite_version"`
	SchemaSHA256  string   `json:"schema_sha256"`
	SHA256        string   `json:"sha256"`
	Size          int64    `json:"size"`
	Semantics     string   `json:"semantics"`
	Sensitivity   string   `json:"sensitivity"`
	Tables        []string `json:"tables"`
}

type sqliteBackupHandle interface {
	Step(int) (bool, error)
	Finish() error
	Remaining() int
	PageCount() int
}

// mattn/go-sqlite3 v1.14.22 maps SQLITE_BUSY and SQLITE_LOCKED to
// (false,nil). Count real page progress, not nil errors, and always Finish once.
func runSQLiteBackup(ctx context.Context, b sqliteBackupHandle, stallLimit time.Duration) (err error) {
	defer func() { err = errors.Join(err, b.Finish()) }()
	lastProgress := time.Now()
	previousRemaining, previousPages := -1, -1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := b.Step(128)
		if err != nil {
			return err
		}
		if done {
			return ctx.Err()
		}
		remaining, pages := b.Remaining(), b.PageCount()
		if previousRemaining >= 0 && pages == previousPages && remaining < previousRemaining {
			lastProgress = time.Now()
		}
		previousRemaining, previousPages = remaining, pages
		if time.Since(lastProgress) >= stallLimit {
			return errors.New("SQLite snapshot made no progress within budget")
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func sqliteSnapshotDSN(path, mode string) string {
	return (&url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode + "&_busy_timeout=0"}).String()
}

func backupLocalStoreDB(path string) error {
	_, err := snapshotLocalStoreDB(context.Background(), path)
	return err
}

// snapshotLocalStoreDB deliberately opens an independent read-only source pool,
// never taking the store's sole MaxOpenConns(1) connection. mode=ro (NOT
// immutable) reads committed WAL frames. The caller owns cancellation/join;
// startup calls this synchronously, before any schema initialization.
func snapshotLocalStoreDB(parent context.Context, path string) (string, error) {
	return snapshotLocalStoreDBWithSync(parent, path, syncSnapshotPath)
}

// A per-call durability operation permits deterministic disk-error rehearsal
// without global hooks, privileges, or filling the host filesystem.
func snapshotLocalStoreDBWithSync(parent context.Context, path string, syncPath func(string) error) (published string, err error) {
	ctx, cancel := context.WithTimeout(parent, localSnapshotTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", errors.New("existing local database is not a nonempty regular SQLite file")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(filepath.Dir(path), ".local-snapshot-stage-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(stage) }()
	dbPath := filepath.Join(stage, "database.sqlite")
	f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := copySQLiteSnapshot(ctx, path, dbPath); err != nil {
		return "", err
	}
	manifest, err := inspectLocalSnapshot(ctx, dbPath)
	if err != nil {
		return "", err
	}
	manifest.FormatVersion = 1
	manifest.Component = "local_media.db"
	manifest.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	manifest.Semantics = localSnapshotSemantics
	manifest.Sensitivity = "sensitive plaintext database; private 0600; not encrypted"
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), data, 0600); err != nil {
		return "", err
	}
	if _, err := verifyLocalStoreSnapshot(ctx, stage); err != nil {
		return "", err
	}
	for _, name := range []string{dbPath, filepath.Join(stage, "manifest.json"), stage} {
		if err := syncPath(name); err != nil {
			return "", err
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Reserve a fresh, private destination with O_EXCL semantics (MkdirTemp).
	// Rename replaces only OUR empty reservation, never a previous snapshot.
	// IMPORTANT: .bak-* is a candidate namespace, NOT a completeness marker.
	// A crash before Rename can leave this empty reservation. Discovery must
	// call verifyLocalStoreSnapshot, never trust a matching pathname alone.
	destination, err := os.MkdirTemp(filepath.Dir(path), filepath.Base(path)+".bak-*")
	if err != nil {
		return "", err
	}
	if err := os.Rename(stage, destination); err != nil {
		_ = os.Remove(destination)
		return "", err
	}
	// Keep the published complete snapshot even if directory durability fails.
	if err := syncPath(filepath.Dir(path)); err != nil {
		return "", fmt.Errorf("snapshot published at %s but directory sync failed: %w", destination, err)
	}
	if err := ctx.Err(); err != nil {
		return destination, err
	}
	// No automatic pruning: legacy .bak files and unverified directories are
	// never deleted. Retention can be added with an explicit verified inventory.
	return destination, nil
}

func copySQLiteSnapshot(ctx context.Context, sourcePath, destinationPath string) error {
	source, err := sql.Open("sqlite3", sqliteSnapshotDSN(sourcePath, "ro"))
	if err != nil {
		return err
	}
	defer source.Close()
	source.SetMaxOpenConns(1)
	src, err := source.Conn(ctx)
	if err != nil {
		return err
	}
	defer src.Close()
	// BEGIN alone is deferred; the actual read pins the WAL read mark BEFORE
	// entering Raw. Never issue SQL through the same pool from a Raw callback.
	if _, err := src.ExecContext(ctx, "BEGIN"); err != nil {
		return err
	}
	defer src.ExecContext(context.Background(), "ROLLBACK")
	var schemaCount int
	if err := src.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema").Scan(&schemaCount); err != nil {
		return err
	}
	destination, err := sql.Open("sqlite3", sqliteSnapshotDSN(destinationPath, "rw"))
	if err != nil {
		return err
	}
	defer destination.Close()
	destination.SetMaxOpenConns(1)
	dst, err := destination.Conn(ctx)
	if err != nil {
		return err
	}
	defer dst.Close()
	err = src.Raw(func(sourceDriver any) error {
		sourceConn, ok := sourceDriver.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("unexpected SQLite source driver")
		}
		return dst.Raw(func(destinationDriver any) error {
			destinationConn, ok := destinationDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("unexpected SQLite destination driver")
			}
			backup, err := destinationConn.Backup("main", sourceConn, "main")
			if err != nil {
				return err
			}
			return runSQLiteBackup(ctx, backup, localSnapshotStallLimit)
		})
	})
	if err == nil {
		// Publish a self-contained main database, not a snapshot that later
		// needs sidecars or creates WAL/SHM files during read-only verification.
		var mode string
		err = dst.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&mode)
		if err == nil && mode != "delete" {
			err = fmt.Errorf("snapshot destination journal mode: %s", mode)
		}
	}
	// Explicitly close the destination before inspecting/hash/fsync publication.
	// The deferred closes are harmless fallback paths, not ignored final I/O.
	return errors.Join(err, dst.Close(), destination.Close())
}

func syncSnapshotPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func inspectLocalSnapshot(ctx context.Context, path string) (localSnapshotManifest, error) {
	var result localSnapshotManifest
	// Owned packages must be standalone DELETE-journal databases. Reject a
	// WAL-mode header before opening SQLite, which could create SHM sidecars.
	fheader, err := os.Open(path)
	if err != nil {
		return result, err
	}
	var header [20]byte
	_, err = io.ReadFull(fheader, header[:])
	err = errors.Join(err, fheader.Close())
	if err != nil {
		return result, err
	}
	if string(header[:16]) != "SQLite format 3\x00" || header[18] != 1 || header[19] != 1 {
		return result, errors.New("snapshot is not a standalone rollback-journal SQLite database")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			return result, fmt.Errorf("snapshot sidecar present or inaccessible: %s (%v)", suffix, err)
		}
	}
	db, err := sql.Open("sqlite3", sqliteSnapshotDSN(path, "ro"))
	if err != nil {
		return result, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return result, err
	}
	count := 0
	for rows.Next() {
		var status string
		if err := rows.Scan(&status); err != nil {
			rows.Close()
			return result, err
		}
		if status != "ok" {
			rows.Close()
			return result, fmt.Errorf("snapshot integrity: %s", status)
		}
		count++
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return result, err
	}
	if count != 1 {
		return result, errors.New("snapshot integrity check returned no definitive result")
	}
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&result.SQLiteVersion); err != nil {
		return result, err
	}
	rows, err = db.QueryContext(ctx, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name,tbl_name")
	if err != nil {
		return result, err
	}
	schemaHash := sha256.New()
	encoder := json.NewEncoder(schemaHash)
	for rows.Next() {
		var kind, name, table string
		var definition sql.NullString
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			rows.Close()
			return result, err
		}
		if err := encoder.Encode([]any{kind, name, table, definition}); err != nil {
			rows.Close()
			return result, err
		}
		if kind == "table" {
			result.Tables = append(result.Tables, name)
		}
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return result, err
	}
	result.SchemaSHA256 = hex.EncodeToString(schemaHash.Sum(nil))
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	hash := sha256.New()
	result.Size, err = io.Copy(hash, &snapshotContextReader{ctx: ctx, reader: f})
	result.SHA256 = hex.EncodeToString(hash.Sum(nil))
	return result, err
}

type snapshotContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *snapshotContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Verification never calls initLocalSchema. It accepts old schemas as they are,
// preserving confirmation/expiry timestamps byte-for-byte. A restore rehearsal
// should copy into a disposable directory and call this, never a live DB path.
func verifyLocalStoreSnapshot(ctx context.Context, dir string) (localSnapshotManifest, error) {
	var manifest localSnapshotManifest
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return manifest, err
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, err
	}
	if manifest.FormatVersion != 1 || manifest.Component != "local_media.db" || manifest.Semantics != localSnapshotSemantics || manifest.SQLiteVersion == "" {
		return manifest, errors.New("unsupported local snapshot manifest")
	}
	actual, err := inspectLocalSnapshot(ctx, filepath.Join(dir, "database.sqlite"))
	if err != nil {
		return manifest, err
	}
	if actual.Size != manifest.Size || actual.SHA256 != manifest.SHA256 || actual.SchemaSHA256 != manifest.SchemaSHA256 || !reflect.DeepEqual(actual.Tables, manifest.Tables) {
		return manifest, errors.New("snapshot manifest does not match database")
	}
	return manifest, nil
}
