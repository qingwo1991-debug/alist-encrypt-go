package storage

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

const backupTestBudget = 16 << 20

func TestSnapshotBundleStrictStandaloneUSTAR(t *testing.T) {
	s := backupFixture(t)
	dir := t.TempDir()
	if _, err := s.CreateSnapshot(context.Background(), dir, "good.tar", SnapshotOptions{MaxBytes: backupTestBudget}); err != nil {
		t.Fatal(err)
	}
	goodPath := filepath.Join(dir, "good.tar")
	good, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"append-nonzero", "concat-archive", "pax", "gnu", "linkname", "zero-padding", "missing-terminator"} {
		t.Run(kind, func(t *testing.T) {
			var candidate []byte
			switch kind {
			case "append-nonzero":
				candidate = append(append([]byte(nil), good...), append([]byte{1}, make([]byte, 511)...)...)
			case "concat-archive":
				candidate = append(append([]byte(nil), good...), good...)
			case "zero-padding":
				candidate = append(append([]byte(nil), good...), make([]byte, 1024)...)
			case "missing-terminator":
				candidate = append([]byte(nil), good[:len(good)-1024]...)
			default:
				var buf bytes.Buffer
				tw := tar.NewWriter(&buf)
				tr := tar.NewReader(bytes.NewReader(good))
				for {
					h, e := tr.Next()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					switch kind {
					case "pax":
						h.Format = tar.FormatPAX
						h.PAXRecords = map[string]string{"private.secret": "not-allowed"}
					case "gnu":
						h.Format = tar.FormatGNU
					case "linkname":
						h.Linkname = "unexpected-sensitive-target"
					}
					if e = tw.WriteHeader(h); e != nil {
						t.Fatal(e)
					}
					if _, e = io.Copy(tw, tr); e != nil {
						t.Fatal(e)
					}
				}
				if e := tw.Close(); e != nil {
					t.Fatal(e)
				}
				candidate = buf.Bytes()
			}
			file := filepath.Join(dir, kind+".tar")
			if err := os.WriteFile(file, candidate, 0600); err != nil {
				t.Fatal(err)
			}
			err := ValidateSnapshotBundle(context.Background(), file, backupTestBudget)
			if kind == "zero-padding" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid standalone bundle accepted")
			}
			after, err := os.ReadFile(goodPath)
			if err != nil || !bytes.Equal(after, good) {
				t.Fatal("validation changed previous good backup")
			}
		})
	}
}

func backupFixture(t *testing.T) *Store {
	t.Helper()
	s := filenameTestStore(t)
	for i, status := range []string{FilenamePending, FilenameComplete, FilenameFailed} {
		r := filenameTestRecord()
		r.EncryptedPath = "/enc/" + status + ".bin"
		r.OriginalPath = "/enc/中文原名-" + status + ".mp4"
		r.DisplayName = status + ".bin"
		rec, err := s.ReserveFilename(r)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 {
			if err = s.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, status); err != nil {
				t.Fatal(err)
			}
		}
	}
	alias := filenameTestAlias()
	alias.DisplayPath = "/enc/中文别名.mp4"
	alias.VerifiedAt = time.Now().Add(-48 * time.Hour)
	if err := s.PutVerifiedMediaAlias(alias); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucket([]byte("unknown-future-bucket"))
		if err != nil {
			return err
		}
		child, err := b.CreateBucket([]byte("nested"))
		if err != nil {
			return err
		}
		return child.Put([]byte("opaque"), []byte("preserved"))
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func snapshotTestFile(t *testing.T, s *Store) (string, SnapshotManifest) {
	t.Helper()
	var buf bytes.Buffer
	m, err := s.Snapshot(context.Background(), &buf, SnapshotOptions{MaxBytes: backupTestBudget})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "snapshot.bolt")
	if err = os.WriteFile(name, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return name, m
}

func TestSnapshotRealAuditAndOfflineValidation(t *testing.T) {
	s := backupFixture(t)
	// An attempted rolled-back write changes the process counter, not tx.ID.
	if err := s.update(func(tx *bolt.Tx) error { return errors.New("rollback") }); err == nil {
		t.Fatal("expected rollback")
	}
	file, m := snapshotTestFile(t, s)
	var id uint64
	if err := s.db.View(func(tx *bolt.Tx) error { id = uint64(tx.ID()); return nil }); err != nil {
		t.Fatal(err)
	}
	if m.TxID != id || m.Semantics != "committed transactions" {
		t.Fatalf("bad watermark: %+v", m)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateSnapshot(context.Background(), file, m); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("validation modified source: %v", err)
	}
	// This is an isolated readonly drill, NOT a writable production restore.
	db, err := bolt.Open(file, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		if got := tx.Bucket([]byte("unknown-future-bucket")).Bucket([]byte("nested")).Get([]byte("opaque")); string(got) != "preserved" {
			t.Error("unknown bucket lost")
		}
		for _, status := range []string{FilenamePending, FilenameComplete, FilenameFailed} {
			raw := tx.Bucket(filenameReservations).Get(filenameKey("http://alist:5244", "/enc/"+status+".bin"))
			if !bytes.Contains(raw, []byte("中文原名")) || !bytes.Contains(raw, []byte(status)) {
				t.Errorf("record lost: %s", status)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type backupGateWriter struct {
	buf     bytes.Buffer
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *backupGateWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	return w.buf.Write(p)
}

func TestSnapshotConcurrentTransactionWatermark(t *testing.T) {
	s := backupFixture(t)
	if err := s.Set(BucketConfig, "generation", []byte("old")); err != nil {
		t.Fatal(err)
	}
	gate := &backupGateWriter{entered: make(chan struct{}), release: make(chan struct{})}
	type result struct {
		m   SnapshotManifest
		err error
	}
	done := make(chan result, 1)
	go func() {
		m, e := s.Snapshot(context.Background(), gate, SnapshotOptions{MaxBytes: backupTestBudget})
		done <- result{m, e}
	}()
	<-gate.entered
	started := make(chan struct{})
	updated := make(chan error, 1)
	go func() {
		updated <- s.db.Update(func(tx *bolt.Tx) error {
			close(started)
			return tx.Bucket(BucketConfig).Put([]byte("generation"), []byte("new"))
		})
	}()
	<-started
	close(gate.release)
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "isolated.bolt")
	if err := os.WriteFile(file, gate.buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshot(context.Background(), file, got.m); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(file, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.View(func(tx *bolt.Tx) error {
		if string(tx.Bucket(BucketConfig).Get([]byte("generation"))) != "old" {
			t.Error("new transaction mixed into old snapshot")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var current uint64
	if err = s.db.View(func(tx *bolt.Tx) error { current = uint64(tx.ID()); return nil }); err != nil {
		t.Fatal(err)
	}
	if current <= got.m.TxID {
		t.Fatal("concurrent transaction watermark not separated")
	}
}

type backupShortWriter struct{}

func (backupShortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

type backupCancelWriter struct {
	cancel context.CancelFunc
	calls  int
}

func (w *backupCancelWriter) Write(p []byte) (int, error) { w.calls++; w.cancel(); return len(p), nil }

func TestSnapshotCancellationBudgetAndShortWrite(t *testing.T) {
	s := backupFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Snapshot(ctx, io.Discard, SnapshotOptions{MaxBytes: backupTestBudget}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := s.Snapshot(ctx, io.Discard, SnapshotOptions{MaxBytes: backupTestBudget}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := s.Snapshot(context.Background(), io.Discard, SnapshotOptions{MaxBytes: 1}); !errors.Is(err, ErrSnapshotBudget) {
		t.Fatalf("budget: %v", err)
	}
	if _, err := s.Snapshot(context.Background(), backupShortWriter{}, SnapshotOptions{MaxBytes: backupTestBudget}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	writer := &backupCancelWriter{cancel: cancel}
	if _, err := s.Snapshot(ctx, writer, SnapshotOptions{MaxBytes: backupTestBudget}); !errors.Is(err, context.Canceled) || writer.calls != 1 {
		t.Fatalf("chunk cancellation: calls=%d err=%v", writer.calls, err)
	}
}

func TestSnapshotGateCancellationJoinsWriter(t *testing.T) {
	s := backupFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gate := &backupGateWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, err := s.Snapshot(ctx, gate, SnapshotOptions{MaxBytes: backupTestBudget}); done <- err }()
	<-gate.entered
	cancel()
	select {
	case err := <-done:
		t.Fatalf("must not abandon blocked writer: %v", err)
	default:
	}
	close(gate.release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSnapshotRejectsDamagedHashAndAuditIndexes(t *testing.T) {
	for _, kind := range []string{"hash", "missing-index", "missing-entry", "orphan-index", "wrong-reverse", "bad-primary", "alias-missing-index", "alias-orphan"} {
		t.Run(kind, func(t *testing.T) {
			s := backupFixture(t)
			if kind != "hash" {
				err := s.db.Update(func(tx *bolt.Tx) error {
					rec := filenameTestRecord()
					rec.EncryptedPath = "/enc/pending.bin"
					rec.OriginalPath = "/enc/中文原名-pending.mp4"
					key := filenameKey(rec.Origin, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint)
					switch kind {
					case "missing-index":
						return tx.DeleteBucket(filenameOriginalIndex)
					case "missing-entry":
						return tx.Bucket(filenameOriginalIndex).Delete(key)
					case "orphan-index":
						return tx.Bucket(filenameOriginalIndex).Put([]byte("orphan"), []byte("absent"))
					case "wrong-reverse":
						return tx.Bucket(filenameOriginalIndex).Put([]byte("wrong-key"), tx.Bucket(filenameOriginalIndex).Get(key))
					case "bad-primary":
						return tx.Bucket(filenameReservations).Put([]byte("wrong-key"), []byte(`{}`))
					case "alias-missing-index":
						return tx.DeleteBucket(verifiedMediaReverse)
					case "alias-orphan":
						return tx.Bucket(verifiedMediaReverse).Put([]byte("orphan"), []byte("absent"))
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			file, m := snapshotTestFile(t, s)
			if kind == "hash" {
				m.SHA256 = strings.Repeat("0", 64)
			}
			before, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if err = ValidateSnapshot(context.Background(), file, m); err == nil {
				t.Fatal("damage accepted")
			}
			after, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("validator repaired/changed input")
			}
		})
	}
}

func TestCreateSnapshotVerifiedPrivateNoOverwrite(t *testing.T) {
	s := backupFixture(t)
	dir := t.TempDir()
	o := SnapshotOptions{MaxBytes: backupTestBudget, Commit: strings.Repeat("a", 40)}
	m, err := s.CreateSnapshot(context.Background(), dir, "good.tar", o)
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "good.tar")
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	if err = ValidateSnapshotBundle(context.Background(), name, o.MaxBytes); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSnapshot(context.Background(), dir, "good.tar", o); err == nil {
		t.Fatal("overwrote existing bundle")
	}
	if _, err = s.CreateSnapshot(context.Background(), dir, "failed.tar", SnapshotOptions{MaxBytes: 1}); !errors.Is(err, ErrSnapshotBudget) {
		t.Fatalf("budget: %v", err)
	}
	after, err := os.ReadFile(name)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failure changed prior backup")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("staging leak: %v %v", entries, err)
	}
	if m.Commit != o.Commit {
		t.Fatal("commit lost")
	}
	if _, err = s.CreateSnapshot(context.Background(), dir, "../escape", o); err == nil {
		t.Fatal("unsafe path accepted")
	}
	// Inspect only the manifest: the DB intentionally contains sensitive names.
	tr := tar.NewReader(bytes.NewReader(before))
	h, err := tr.Next()
	if err != nil || h.Name != "manifest.json" {
		t.Fatalf("manifest member: %v %v", h, err)
	}
	rawManifest, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"中文", "OriginalPath", "AuthScope", "Token", "signedURL", "http://alist"} {
		if bytes.Contains(rawManifest, []byte(secret)) {
			t.Fatalf("manifest leaked %q", secret)
		}
	}
	// A flipped database byte must fail the packaged hash.
	damaged := append([]byte(nil), before...)
	// Locate a stable DB payload, not a tar header.
	pos := bytes.Index(damaged, []byte("中文原名"))
	if pos < 0 {
		t.Fatal("fixture missing sensitive original name in DB")
	}
	damaged[pos] ^= 1
	bad := filepath.Join(dir, "damaged.tar")
	if err = os.WriteFile(bad, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if err = ValidateSnapshotBundle(context.Background(), bad, o.MaxBytes); err == nil {
		t.Fatal("damaged bundle accepted")
	}
}
