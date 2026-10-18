package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// ValidateSnapshot opens an offline snapshot read-only, never through NewStore
// (which initializes buckets). It neither repairs nor changes source bytes.
// Callers must ensure the input is an immutable, trusted local regular file.
// bbolt mmap/check/open and disk syscalls are cooperative, not hard-real-time
// cancellable. tx.Check is always fully drained before the read transaction ends.
func ValidateSnapshot(ctx context.Context, dbPath string, m SnapshotManifest) (err error) {
	if ctx == nil || m.Format != SnapshotFormat || m.Schema != SnapshotSchema || m.Component != "root-bolt" || m.Semantics != SnapshotSemantics || m.Sensitivity != "sensitive-unencrypted" || m.CreatedAt.IsZero() || m.TxID == 0 || !validSnapshotOptions(SnapshotOptions{MaxBytes: m.Bytes, Commit: m.Commit}) {
		return errors.New("invalid snapshot manifest")
	}
	digest, e := hex.DecodeString(m.SHA256)
	if e != nil || len(digest) != sha256.Size {
		return errors.New("invalid snapshot digest")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(dbPath)
	if err != nil {
		return err
	}
	info, statErr := f.Stat()
	if statErr != nil {
		return errors.Join(statErr, f.Close())
	}
	if !info.Mode().IsRegular() || info.Size() != m.Bytes {
		return errors.Join(errors.New("snapshot size/type mismatch"), f.Close())
	}
	hash := sha256.New()
	_, err = io.Copy(&snapshotWriter{ctx: ctx, dst: hash, left: m.Bytes}, f)
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if !bytes.Equal(hash.Sum(nil), digest) {
		return errors.New("snapshot hash mismatch")
	}
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{ReadOnly: true, Timeout: 100 * time.Millisecond})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	return db.View(func(tx *bolt.Tx) error {
		if uint64(tx.ID()) != m.TxID {
			return errors.New("snapshot transaction watermark mismatch")
		}
		var checkErr error
		for e := range tx.Check() {
			// Drain even after cancellation/error: Check owns a goroutine using this tx.
			if checkErr == nil {
				checkErr = e
			}
		}
		if e := errors.Join(checkErr, ctx.Err()); e != nil {
			return e
		}
		for _, name := range [][]byte{BucketUsers, BucketPasswd, BucketConfig, BucketFileInfo, BucketFileSize, BucketDirSync, BucketStats} {
			if tx.Bucket(name) == nil {
				return errors.New("missing root schema bucket")
			}
		}
		if e := validateAuditPair(ctx, tx, filenameReservations, filenameOriginalIndex, false); e != nil {
			return e
		}
		return validateAuditPair(ctx, tx, verifiedMediaAliases, verifiedMediaReverse, true)
	})
}

func validBackupFilename(r FilenameRecord) bool {
	token, err := hex.DecodeString(r.Token)
	return validFilenameOrigin(r.Origin) && validFilenamePath(r.EncryptedPath) && validFilenamePath(r.OriginalPath) && r.DisplayName != "" && r.DisplayName != "." && r.DisplayName != ".." && path.Base(r.DisplayName) == r.DisplayName && !strings.ContainsAny(r.DisplayName, "\x00\r\n\\") && validFilenameScope(r.AuthScope) && validFilenameScope(r.RuleFingerprint) && r.CiphertextSize >= 0 && err == nil && len(token) == 16 && !r.CreatedAt.IsZero() && !r.UpdatedAt.Before(r.CreatedAt) && (r.Status == FilenamePending || r.Status == FilenameComplete || r.Status == FilenameFailed)
}

func auditRecordKeys(raw []byte, alias bool) (primary, reverse []byte, err error) {
	if alias {
		var r VerifiedMediaAlias
		if json.Unmarshal(raw, &r) != nil || !validMediaAlias(r) {
			return nil, nil, errors.New("invalid alias record structure")
		}
		// validMediaAlias checks structure and provenance, not the 24h lookup TTL.
		return filenameKey(r.Origin, r.EncryptedPath, r.AuthScope, r.RuleFingerprint), filenameKey(r.Origin, r.DisplayPath, r.AuthScope, r.RuleFingerprint), nil
	}
	var r FilenameRecord
	if json.Unmarshal(raw, &r) != nil || !validBackupFilename(r) {
		return nil, nil, errors.New("invalid filename record structure")
	}
	return filenameKey(r.Origin, r.EncryptedPath), filenameKey(r.Origin, r.OriginalPath, r.AuthScope, r.RuleFingerprint), nil
}

func validateAuditPair(ctx context.Context, tx *bolt.Tx, primaryName, reverseName []byte, alias bool) error {
	primary, reverse := tx.Bucket(primaryName), tx.Bucket(reverseName)
	// Both absent is the valid legacy/lazy initialization state; one absent is
	// not silently initialized, even if the surviving bucket happens to be empty.
	if primary == nil && reverse == nil {
		return nil
	}
	if primary == nil || reverse == nil {
		return errors.New("missing audit index bucket")
	}
	if err := primary.ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if v == nil {
			return errors.New("nested bucket in audit records")
		}
		pk, rk, err := auditRecordKeys(v, alias)
		if err != nil {
			return err
		}
		if !bytes.Equal(k, pk) || !bytes.Equal(reverse.Get(rk), pk) {
			return errors.New("audit primary/index mismatch")
		}
		return nil
	}); err != nil {
		return err
	}
	return reverse.ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if v == nil {
			return errors.New("nested bucket in audit index")
		}
		raw := primary.Get(v)
		if raw == nil {
			return errors.New("orphan audit reverse index")
		}
		pk, rk, err := auditRecordKeys(raw, alias)
		if err != nil {
			return err
		}
		if !bytes.Equal(pk, v) || !bytes.Equal(rk, k) {
			return errors.New("audit reverse key mismatch")
		}
		return nil
	})
}
