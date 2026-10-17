//go:build unix

package storage

import (
	"context"
	"github.com/alist-encrypt-go/internal/recovery"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineRestoreRejectsReservedInputsBeforeWrites(t *testing.T) {
	for _, name := range []string{"alist-encrypt.db", recovery.SidecarName, ".store-maint.lock"} {
		for _, hardlink := range []bool{false, true} {
			for _, field := range []string{"config", "bundle"} {
				t.Run(name+field+map[bool]string{false: "-path", true: "-hardlink"}[hardlink], func(t *testing.T) {
					o, db := restoreFixture(t)
					reserved := filepath.Join(o.StoreDir, name)
					if name != "alist-encrypt.db" {
						raw, err := os.ReadFile(o.Config)
						if err != nil {
							t.Fatal(err)
						}
						if err = os.WriteFile(reserved, raw, 0600); err != nil {
							t.Fatal(err)
						}
					}
					before, err := os.ReadFile(reserved)
					if err != nil {
						t.Fatal(err)
					}
					dbBefore, err := os.ReadFile(db)
					if err != nil {
						t.Fatal(err)
					}
					input := reserved
					if hardlink {
						input = filepath.Join(o.StoreDir, "reserved-alias")
						if err = os.Link(reserved, input); err != nil {
							t.Fatal(err)
						}
					}
					if field == "config" {
						o.Config = input
					} else {
						o.Bundle = input
					}
					if _, err = RestoreOffline(context.Background(), o); err == nil {
						t.Fatal("reserved input accepted")
					}
					after, err := os.ReadFile(reserved)
					if err != nil {
						t.Fatal(err)
					}
					if string(after) != string(before) {
						t.Fatal("reserved file overwritten")
					}
					dbAfter, err := os.ReadFile(db)
					if err != nil {
						t.Fatal(err)
					}
					if string(dbAfter) != string(dbBefore) {
						t.Fatal("DB changed")
					}
					if name != ".store-maint.lock" {
						if _, err = os.Stat(filepath.Join(o.StoreDir, ".store-maint.lock")); !os.IsNotExist(err) {
							t.Fatalf("lock created before rejection: %v", err)
						}
					}
					matches, err := filepath.Glob(filepath.Join(o.StoreDir, "pre-restore-*.tar"))
					if err != nil || len(matches) != 0 {
						t.Fatal("rollback write before rejection")
					}
				})
			}
		}
	}
}
