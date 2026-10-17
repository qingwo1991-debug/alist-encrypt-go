package storage

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/recovery"
	bolt "go.etcd.io/bbolt"
)

type RestoreOptions struct {
	StoreDir     string
	Bundle       string
	Config       string
	ConfigSHA256 string
	MaxBytes     int64
}
type RestoreReport struct {
	Component       string `json:"component"`
	FullRestore     bool   `json:"full_restore"`
	ConfigMode      string `json:"config_mode"`
	ConfigSHA256    string `json:"config_sha256"`
	SourceSHA256    string `json:"source_db_sha256"`
	InstalledSHA256 string `json:"installed_db_sha256"`
	RollbackBundle  string `json:"rollback_bundle"`
	Stage           string `json:"stage"`
	Reconciliation  string `json:"reconciliation"`
}

// canonicalPath rejects relative paths and symlinks in every existing component.
// Parents are trusted operator-owned directories; no attacker may swap them.
func canonicalPath(p string, dir bool) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("absolute canonical path required")
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	if real != p {
		return errors.New("symlink paths unsupported")
	}
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if dir {
		if !st.IsDir() {
			return errors.New("directory required")
		}
	} else if !st.Mode().IsRegular() {
		return errors.New("regular file required")
	}
	return nil
}

// VerifyBundle reads an immutable input and uses controlled temporary extraction;
// it neither initializes buckets nor opens a service DB for writing.
func VerifyBundle(ctx context.Context, path string, max int64) error {
	if err := canonicalPath(path, false); err != nil {
		return err
	}
	return ValidateSnapshotBundle(ctx, path, max)
}

func hashFile(ctx context.Context, p string, max int64) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(&snapshotWriter{ctx: ctx, dst: h, left: max}, f)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RestoreOffline only restores the root Bolt component. It never modifies the
// external config, touches MySQL/SQLite, makes provider requests or clears fences.
// Every database byte change happens after durable prepared marker publication.
func RestoreOffline(ctx context.Context, o RestoreOptions) (RestoreReport, error) {
	return restoreOffline(ctx, o, os.Rename, recovery.SyncDir)
}

// Per-call filesystem hooks permit deterministic fault rehearsal without global
// mutation, filling a host disk, or privileges.
func restoreOffline(ctx context.Context, o RestoreOptions, rename func(string, string) error, syncDir func(string) error) (report RestoreReport, err error) {
	report = RestoreReport{Component: "root-bolt", ConfigMode: "external-required", Stage: "preflight", Reconciliation: "unknown: remote objects not enumerated"}
	if o.MaxBytes <= 0 || o.MaxBytes > 1<<40 {
		return report, errors.New("positive byte budget required")
	}
	for _, p := range []struct {
		p   string
		dir bool
	}{{o.StoreDir, true}, {o.Bundle, false}, {o.Config, false}} {
		if err = canonicalPath(p.p, p.dir); err != nil {
			return report, err
		}
	}
	dbPath := filepath.Join(o.StoreDir, "alist-encrypt.db")
	if err = canonicalPath(dbPath, false); err != nil {
		return report, err
	}
	// Reject reserved names AND inode aliases before acquiring/creating the lock
	// or publishing any marker. Otherwise a pinned config at the sidecar path
	// would be overwritten by the protocol itself.
	for _, input := range []string{o.Bundle, o.Config} {
		a, e := os.Stat(input)
		if e != nil {
			return report, e
		}
		for _, name := range []string{"alist-encrypt.db", recovery.SidecarName, ".store-maint.lock"} {
			reserved := filepath.Join(o.StoreDir, name)
			if input == reserved {
				return report, errors.New("input uses reserved store path")
			}
			b, e := os.Stat(reserved)
			if e == nil && os.SameFile(a, b) {
				return report, errors.New("input aliases reserved store inode")
			}
			if e != nil && !os.IsNotExist(e) {
				return report, e
			}
		}
	}
	lockCtx, cancel := context.WithTimeout(ctx, time.Second)
	owner, err := recovery.Acquire(lockCtx, o.StoreDir)
	cancel()
	if err != nil {
		return report, fmt.Errorf("stop service and acquire exclusive ownership: %w", err)
	}
	defer func() { err = errors.Join(err, owner.Close()) }()
	// Do not overwrite the only durable operation history. Recovery of an already
	// fenced/marked store requires a future explicitly audited repair protocol.
	if recovery.Load(o.StoreDir).Required() {
		return report, errors.New("existing recovery state requires audited repair; nested restore refused")
	}
	current, e := bolt.Open(dbPath, 0600, &bolt.Options{ReadOnly: true, Timeout: 100 * time.Millisecond})
	if e != nil {
		return report, e
	}
	marked := false
	e = current.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(BucketConfig); b != nil {
			key := []byte(recovery.StickyKey)
			marked = b.Get(key) != nil || b.Bucket(key) != nil
		}
		return nil
	})
	e = errors.Join(e, current.Close())
	if e != nil {
		return report, e
	}
	if marked {
		return report, errors.New("existing sticky recovery state requires audited repair; nested restore refused")
	}
	// Pin the exact operator-supplied config, not config.Load/default generation.
	cs, err := os.Stat(o.Config)
	if err != nil || cs.Size() > 4<<20 {
		return report, errors.New("external config size invalid")
	}
	raw, err := os.ReadFile(o.Config)
	if err != nil {
		return report, err
	}
	sum := sha256.Sum256(raw)
	report.ConfigSHA256 = hex.EncodeToString(sum[:])
	if report.ConfigSHA256 != o.ConfigSHA256 {
		return report, errors.New("external config digest mismatch")
	}
	if err = config.ValidateRestoreConfig(raw, o.StoreDir); err != nil {
		return report, err
	}
	stage, err := os.MkdirTemp(o.StoreDir, ".restore-")
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(stage)) }()
	// Copy the bundle first; validation and extraction use these same private bytes.
	source, err := os.Open(o.Bundle)
	if err != nil {
		return report, err
	}
	copied := filepath.Join(stage, "input.tar")
	out, err := os.OpenFile(copied, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		source.Close()
		return report, err
	}
	_, err = io.Copy(&snapshotWriter{ctx: ctx, dst: out, left: o.MaxBytes + (1 << 20)}, source)
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close(), source.Close())
	if err != nil {
		return report, err
	}
	if err = ValidateSnapshotBundle(ctx, copied, o.MaxBytes); err != nil {
		return report, err
	}
	f, err := os.Open(copied)
	if err != nil {
		return report, err
	}
	tr := tar.NewReader(f)
	if _, err = tr.Next(); err != nil {
		f.Close()
		return report, err
	}
	var m SnapshotManifest
	if err = json.NewDecoder(tr).Decode(&m); err != nil {
		f.Close()
		return report, err
	}
	if _, err = tr.Next(); err != nil {
		f.Close()
		return report, err
	}
	installed := filepath.Join(stage, "database.bolt")
	out, err = os.OpenFile(installed, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		f.Close()
		return report, err
	}
	_, err = io.Copy(&snapshotWriter{ctx: ctx, dst: out, left: o.MaxBytes}, tr)
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close(), f.Close())
	if err != nil {
		return report, err
	}
	if err = ValidateSnapshot(ctx, installed, m); err != nil {
		return report, err
	}
	report.SourceSHA256 = m.SHA256
	// Preserve the present DB in a published verified rollback bundle before fence
	// or target changes. Snapshot uses a read-only connection, never NewStore.
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return report, err
	}
	op := hex.EncodeToString(nonce[:])
	backupName := "pre-restore-" + op + ".tar"
	if _, err = CreateOfflineSnapshot(ctx, dbPath, o.StoreDir, backupName, SnapshotOptions{MaxBytes: o.MaxBytes}); err != nil {
		return report, err
	}
	report.RollbackBundle = filepath.Join(o.StoreDir, backupName)
	bundleHash, err := hashFile(ctx, copied, o.MaxBytes+(1<<20))
	if err != nil {
		return report, err
	}
	generation := binary.BigEndian.Uint64(nonce[:8])
	if generation == 0 {
		generation = 1
	}
	marker := recovery.Marker{Version: 1, Stage: "prepared", OperationID: op, BundleSHA256: bundleHash, Generation: generation}
	if err = recovery.WriteMarker(o.StoreDir, marker); err != nil {
		return report, err
	}
	report.Stage = "prepared"
	if err = ctx.Err(); err != nil {
		return report, err
	}
	marker.Stage = "restoring"
	if err = recovery.WriteMarker(o.StoreDir, marker); err != nil {
		return report, err
	}
	report.Stage = "restoring"
	// Change only the verified private copy. This changes its hash/tx watermark;
	// validate it using a new local manifest, never the original bundle identity.
	db, err := bolt.Open(installed, 0600, &bolt.Options{Timeout: 100 * time.Millisecond})
	if err != nil {
		return report, err
	}
	markRaw, _ := json.Marshal(marker)
	err = db.Update(func(tx *bolt.Tx) error {
		if err := invalidateRestoreTransport(tx); err != nil {
			return err
		}
		b := tx.Bucket(BucketConfig)
		if b == nil {
			return errors.New("missing config bucket")
		}
		return b.Put([]byte(recovery.StickyKey), markRaw)
	})
	if err == nil {
		err = db.Sync()
	}
	if err == nil {
		err = db.View(func(tx *bolt.Tx) error { m.TxID = uint64(tx.ID()); return nil })
	}
	err = errors.Join(err, db.Close())
	if err != nil {
		return report, err
	}
	st, err := os.Stat(installed)
	if err != nil {
		return report, err
	}
	m.Bytes = st.Size()
	m.SHA256, err = hashFile(ctx, installed, o.MaxBytes)
	if err != nil {
		return report, err
	}
	if err = ValidateSnapshot(ctx, installed, m); err != nil {
		return report, err
	}
	report.InstalledSHA256 = m.SHA256
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = rename(installed, dbPath); err != nil {
		return report, err
	}
	if err = syncDir(o.StoreDir); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	marker.Stage = "reconciliation-required"
	if err = recovery.WriteMarker(o.StoreDir, marker); err != nil {
		return report, err
	}
	report.Stage = marker.Stage
	if err = ctx.Err(); err != nil {
		return report, err
	}
	return report, nil
}
