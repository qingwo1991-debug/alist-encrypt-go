package op

import (
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"testing"
)

func TestOwnedStorageGenerationResetRejectsOutsiderAndRemovesOldMount(t *testing.T) {
	owner, err := internalnet.AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	old := &deferredInitDriver{Storage: model.Storage{ID: 777, MountPath: "/generation-old", Status: WORK}}
	storagesMap.Store(old.MountPath, old)
	readiness.Lock()
	readiness.mounts[old.MountPath] = &storageReadiness{}
	readiness.Unlock()
	balanceMap.Store(old.MountPath, 2)
	if GetBalancedStorage(old.MountPath+"/file") == nil {
		t.Fatal("fixture old mount missing")
	}
	if err := ResetOwnedStorageGeneration(&internalnet.EmbeddedLease{}); err == nil {
		t.Fatal("outsider reset accepted")
	}
	if !HasStorage(old.MountPath) {
		t.Fatal("outsider removed old mount")
	}
	_ = owner.BeginStop()
	if err := ResetOwnedStorageGeneration(owner); err != nil {
		t.Fatal(err)
	}
	next, err := internalnet.AcquireEmbeddedLease()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.BeginStop(); _ = next.Release() }()
	if GetBalancedStorage(old.MountPath+"/file") != nil || HasStorage(old.MountPath) || len(GetAllStorages()) != 0 {
		t.Fatal("new generation exposes prior storage")
	}
	readiness.RLock()
	remaining := len(readiness.mounts)
	readiness.RUnlock()
	if remaining != 0 || balanceMap.Has(old.MountPath) {
		t.Fatal("readiness/balance retained old mount")
	}
}
