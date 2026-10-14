package bootstrap

import (
	"runtime"
	"testing"
)

func TestStorageLoadAdmissionSealedBeforeJoin(t *testing.T) {
	PrepareStorageLoadGeneration()
	storageLoadAdmission.Lock()
	storageLoadWG.Add(1)
	storageLoadAdmission.Unlock()
	joined := make(chan struct{})
	go func() { JoinStorageLoads(); close(joined) }()
	// Observe the seal through the same admission mutex. No new admission may
	// mutate the wait group after this point, even while an Init is still alive.
	sealed := false
	for !sealed {
		runtime.Gosched()
		storageLoadAdmission.Lock()
		sealed = storageLoadAdmission.sealed
		storageLoadAdmission.Unlock()
	}
	select {
	case <-joined:
		t.Fatal("joined before actual Init return")
	default:
	}
	// Sealed LoadStorages must return before DB access; no DB fixture required.
	LoadStorages()
	storageLoadWG.Done()
	<-joined
	PrepareStorageLoadGeneration()
	storageLoadAdmission.Lock()
	sealed = storageLoadAdmission.sealed
	storageLoadAdmission.Unlock()
	if sealed {
		t.Fatal("new joined generation did not reopen admission")
	}
}
