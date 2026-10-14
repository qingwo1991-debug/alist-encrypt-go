//go:build unix

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/recovery"
)

func restoreFixture(t *testing.T) (RestoreOptions, string) {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Set(BucketStats, "ttl", []byte("original-time")); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "snapshot.tar")
	if _, err = s.CreateSnapshot(ctx, dir, "snapshot.tar", SnapshotOptions{MaxBytes: 16 << 20}); err != nil {
		t.Fatal(err)
	}
	if err = s.Set(BucketStats, "ttl", []byte("later-time")); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	c := config.DefaultConfig()
	c.DataDir = dir
	c.JWTSecret = "fixture-not-production"
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "external-config.json")
	if err = os.WriteFile(cfgPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return RestoreOptions{StoreDir: dir, Bundle: bundle, Config: cfgPath, ConfigSHA256: hex.EncodeToString(h[:]), MaxBytes: 16 << 20}, filepath.Join(dir, "alist-encrypt.db")
}
func TestOfflineRestoreFencedAndRollbackPreserved(t *testing.T) {
	o, _ := restoreFixture(t)
	r, err := RestoreOffline(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if r.FullRestore || r.Stage != "reconciliation-required" || r.SourceSHA256 == r.InstalledSHA256 {
		t.Fatalf("bad report %+v", r)
	}
	if err = VerifyBundle(context.Background(), r.RollbackBundle, o.MaxBytes); err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(o.StoreDir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Get(BucketStats, "ttl")
	if err != nil || string(v) != "original-time" {
		t.Fatalf("TTL/state rewritten: %q %v", v, err)
	}
	s.Close()
	if err = os.Remove(filepath.Join(o.StoreDir, recovery.SidecarName)); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(o.StoreDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !s.RecoveryState().Required() {
		t.Fatal("missing sidecar bypassed sticky DB")
	}
}
func TestOfflineRestoreOwnershipAndPreflight(t *testing.T) {
	o, db := restoreFixture(t)
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := recovery.Acquire(context.Background(), o.StoreDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = RestoreOffline(ctx, o); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("live owner not refused: %v", err)
	}
	owner.Close()
	o.ConfigSHA256 = "wrong"
	if _, err = RestoreOffline(context.Background(), o); err == nil {
		t.Fatal("bad config accepted")
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed preflight changed DB")
	}
	if recovery.Load(o.StoreDir).Required() {
		t.Fatal("preflight created fence")
	}
}
func TestOfflineRestoreRejectsRelativeSymlinkAndCanceled(t *testing.T) {
	o, _ := restoreFixture(t)
	o.Bundle = "relative.tar"
	if _, err := RestoreOffline(context.Background(), o); err == nil {
		t.Fatal("relative accepted")
	}
	o, _ = restoreFixture(t)
	link := filepath.Join(o.StoreDir, "link.tar")
	if err := os.Symlink(o.Bundle, link); err != nil {
		t.Fatal(err)
	}
	o.Bundle = link
	if _, err := RestoreOffline(context.Background(), o); err == nil {
		t.Fatal("symlink accepted")
	}
	o, _ = restoreFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RestoreOffline(ctx, o); err == nil {
		t.Fatal("canceled operation succeeded")
	}
}
