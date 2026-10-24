package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestCancelledEmptyCopyDoesNotOpenDatabase(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "empty.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() // Keep its writer lock; cancellation must precede opening.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = inspect(ctx, root, path); err == nil || err.Error() != "inspection_cancelled" {
		t.Fatal("cancelled empty copy was not rejected before opening")
	}
}

func TestUnknownRootBucketsCountWithoutLeakingNames(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "unknown.db")
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"PRIVATE_A", "PRIVATE_B"} {
			if _, err := tx.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := inspect(context.Background(), root, path)
	if err != nil || r.OtherRootBucketCount != 2 {
		t.Fatal("unknown root bucket inventory failed")
	}
	output := filepath.Join(root, "report.json")
	if err = writeReport(output, r); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || strings.Contains(string(raw), "PRIVATE_") {
		t.Fatal("empty report or unknown bucket name leaked")
	}
}
