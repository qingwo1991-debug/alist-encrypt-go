package storage

import (
	"errors"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/recovery"
	bolt "go.etcd.io/bbolt"
	"strings"
	"testing"
)

func TestNestedStickyMarkerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.update(func(tx *bolt.Tx) error {
		_, e := tx.Bucket(BucketConfig).CreateBucket([]byte(recovery.StickyKey))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := config.DefaultConfig()
	cfg.BindRecoveryState(s.RecoveryState())
	if !cfg.RecoveryRequired() {
		t.Fatal("nested sticky bucket bypassed config fence")
	}
	rec := FilenameRecord{Origin: "http://example.com", EncryptedPath: "/raw/file", OriginalPath: "/plain/file", DisplayName: "file", AuthScope: strings.Repeat("a", 64), RuleFingerprint: strings.Repeat("b", 64)}
	if _, err = s.ReserveFilename(rec); !errors.Is(err, recovery.ErrRequired) {
		t.Fatalf("nested sticky bucket bypassed reservation: %v", err)
	}
}
