package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alist-encrypt-go/internal/storage"
)

// The fixture gates the real disk runner, not an HTTP writer or fake artifact.
// Once signaled, it still must execute/return the owned CreateSnapshot call.
func TestBackupOwnerCanceledActualDiskRunnerDrains(t *testing.T) {
	store, owner := backupFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	owner.run = func(ctx context.Context, dir, name string, opts storage.SnapshotOptions) (storage.SnapshotManifest, error) {
		close(entered)
		<-release
		return store.CreateSnapshot(ctx, dir, name, opts)
	}
	job, err := owner.create(backupMaxBytes, backupTimeout)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	owner.seal()
	running, _ := owner.status(job.ID, false)
	if running.State != "running" || !running.CancelRequested {
		t.Fatal(running)
	}
	close(release)
	owner.wait()
	final, _ := owner.status(job.ID, false)
	if final.State != "canceled" {
		t.Fatal(final)
	}
	if _, err = os.Stat(filepath.Join(owner.directory, job.ID+".tar")); !os.IsNotExist(err) {
		t.Fatal("canceled artifact published", err)
	}
	entries, err := os.ReadDir(owner.directory)
	if err != nil || len(entries) != 0 {
		t.Fatal("owned staging not drained", entries, err)
	}
}
