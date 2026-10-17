//go:build unix

package storage

import (
	"context"
	"errors"
	"github.com/alist-encrypt-go/internal/recovery"
	"os"
	"testing"
)

func TestOfflineRestorePublishFailuresStayFenced(t *testing.T) {
	for _, point := range []string{"rename", "dir-sync", "cancel"} {
		t.Run(point, func(t *testing.T) {
			o, db := restoreFixture(t)
			before, err := os.ReadFile(db)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			injected := errors.New("injected filesystem fault")
			rename := func(a, b string) error {
				if point == "rename" {
					return injected
				}
				if point == "cancel" {
					cancel()
					return ctx.Err()
				}
				return os.Rename(a, b)
			}
			sync := func(dir string) error {
				if point == "dir-sync" {
					return injected
				}
				return recovery.SyncDir(dir)
			}
			report, err := restoreOffline(ctx, o, rename, sync)
			if err == nil {
				t.Fatal("fault ignored")
			}
			if !recovery.Load(o.StoreDir).Required() {
				t.Fatal("fault removed fence")
			}
			if report.RollbackBundle == "" {
				t.Fatal("no rollback bundle")
			}
			if err := VerifyBundle(context.Background(), report.RollbackBundle, o.MaxBytes); err != nil {
				t.Fatal(err)
			}
			if point != "dir-sync" {
				after, err := os.ReadFile(db)
				if err != nil {
					t.Fatal(err)
				}
				if string(before) != string(after) {
					t.Fatal("failed publish changed source")
				}
			}
		})
	}
}
