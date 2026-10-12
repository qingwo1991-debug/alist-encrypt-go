package op

import (
	"context"
	"errors"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// Embed Driver to stub operations that Init never invokes.
type deferredInitDriver struct {
	driver.Driver
	model.Storage
	addition struct{}
	cancel   context.CancelFunc
}

func (d *deferredInitDriver) GetStorage() *model.Storage     { return &d.Storage }
func (d *deferredInitDriver) SetStorage(s model.Storage)     { d.Storage = s }
func (d *deferredInitDriver) GetAddition() driver.Additional { return &d.addition }
func (d *deferredInitDriver) Init(context.Context) error     { d.cancel(); return nil }
func (d *deferredInitDriver) Config() driver.Config          { return driver.Config{CheckStatus: true} }

func TestBalancedReadinessUsesOnlyReadySiblings(t *testing.T) {
	const mount = "/readiness-balanced"
	mounts := []string{mount, mount + ".balance1", mount + ".balance2"}
	for _, m := range mounts {
		defer removeStorageReadiness(m)
		defer storagesMap.Delete(m)
	}
	PrepareStorageLoads([]model.Storage{{MountPath: mounts[0]}, {MountPath: mounts[1]}, {MountPath: mounts[2]}})
	for _, m := range mounts {
		d := &deferredInitDriver{Storage: model.Storage{MountPath: m}}
		d.SetStatus(WORK)
		storagesMap.Store(m, d)
	}
	readiness.Lock()
	readiness.mounts[mounts[0]].pending = false
	readiness.mounts[mounts[0]].err = context.DeadlineExceeded
	readiness.mounts[mounts[2]].pending = false
	readiness.Unlock()
	for i := 0; i < 100; i++ {
		if err := StorageReadyError(mount + "/file"); err != nil {
			t.Fatal(err)
		}
		d, _, err := GetStorageAndActualPath(mount + "/file")
		if err != nil || d == nil || d.GetStorage().MountPath != mounts[2] {
			t.Fatalf("selected %v, error %v", d, err)
		}
	}
	readiness.Lock()
	readiness.mounts[mounts[1]].pending = false
	readiness.Unlock()
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		seen[GetBalancedStorage(mount).GetStorage().MountPath] = true
	}
	if len(seen) != 2 || !seen[mounts[1]] || !seen[mounts[2]] {
		t.Fatalf("ready balance: %v", seen)
	}
	d, _ := storagesMap.Load(mounts[2])
	d.GetStorage().SetStatus("failed")
	readiness.Lock()
	readiness.mounts[mounts[1]].pending = true
	readiness.Unlock()
	if _, _, err := GetStorageAndActualPath(mount); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("all unavailable: %v", err)
	}
}

func TestCancelledInitCannotPublishReady(t *testing.T) {
	const mount = "/readiness-late-init"
	defer removeStorageReadiness(mount)
	defer storagesMap.Delete(mount)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &deferredInitDriver{cancel: cancel}
	err := initStorage(ctx, model.Storage{MountPath: mount, Addition: "{}"}, d)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("late init: %v", err)
	}
	if d.GetStorage().Status == WORK {
		t.Fatal("cancelled Init published WORK")
	}
	if err := StorageReadyError(mount); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("readiness: %v", err)
	}
}

func TestStorageReadinessIndependentMounts(t *testing.T) {
	const ready, pending = "/readiness-domestic", "/readiness-overseas"
	defer removeStorageReadiness(ready)
	defer removeStorageReadiness(pending)
	PrepareStorageLoads([]model.Storage{{MountPath: ready}, {MountPath: pending}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	beginStorageLoad(ctx, pending)
	readiness.Lock()
	readiness.mounts[ready].pending = false
	readiness.Unlock()
	if err := StorageReadyError(ready + "/movie.mp4"); err != nil {
		t.Fatal(err)
	}
	if err := StorageReadyError("/"); err != nil {
		t.Fatalf("virtual root blocked: %v", err)
	}
	if err := StorageReadyError(pending); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("pending error: %v", err)
	}
	cancel()
	if err := StorageReadyError(pending); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("expired init error: %v", err)
	}
}

func TestStorageReadinessLongestMountAndFailure(t *testing.T) {
	const root, child = "/readiness-parent", "/readiness-parent/child"
	defer removeStorageReadiness(root)
	defer removeStorageReadiness(child)
	PrepareStorageLoads([]model.Storage{{MountPath: root}, {MountPath: child}})
	readiness.Lock()
	readiness.mounts[child].pending = false
	readiness.mounts[root].pending = false
	readiness.mounts[root].err = context.DeadlineExceeded
	readiness.Unlock()
	if err := StorageReadyError(child + "/file"); err != nil {
		t.Fatal(err)
	}
	if err := StorageReadyError(root + "/file"); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("failed error: %v", err)
	}
}
