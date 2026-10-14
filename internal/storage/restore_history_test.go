//go:build unix

package storage

import (
	"context"
	"errors"
	"github.com/alist-encrypt-go/internal/recovery"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineRestoreDoesNotOverwriteRecoveryHistory(t *testing.T) {
	o, _ := restoreFixture(t)
	failure := errors.New("injected rename")
	report, err := restoreOffline(context.Background(), o, func(string, string) error { return failure }, recovery.SyncDir)
	if err == nil {
		t.Fatal("fault ignored")
	}
	path := filepath.Join(o.StoreDir, recovery.SidecarName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreOffline(context.Background(), o); err == nil {
		t.Fatal("nested restore accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("prior operation journal overwritten")
	}
	if err = VerifyBundle(context.Background(), report.RollbackBundle, o.MaxBytes); err != nil {
		t.Fatal(err)
	}
}
func TestOfflineRestoreRefusesStickyWithoutSidecar(t *testing.T) {
	o, db := restoreFixture(t)
	if _, err := RestoreOffline(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(o.StoreDir, recovery.SidecarName)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = RestoreOffline(context.Background(), o); err == nil {
		t.Fatal("sticky sideless nested restore accepted")
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("sticky DB overwritten")
	}
}
