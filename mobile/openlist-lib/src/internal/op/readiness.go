package op

import (
	"context"
	"fmt"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

type storageReadiness struct {
	pending bool
	err     error
	ctx     context.Context
}

var readiness = struct {
	sync.RWMutex
	mounts map[string]*storageReadiness
}{mounts: make(map[string]*storageReadiness)}

// PrepareStorageLoads registers all mounts before any asynchronous Init starts.
// A request to a pending mount must not masquerade as an empty directory.
func PrepareStorageLoads(storages []model.Storage) {
	readiness.Lock()
	defer readiness.Unlock()
	for _, s := range storages {
		readiness.mounts[utils.FixAndCleanPath(s.MountPath)] = &storageReadiness{pending: true}
	}
}

func beginStorageLoad(ctx context.Context, mount string) *storageReadiness {
	readiness.Lock()
	defer readiness.Unlock()
	state := &storageReadiness{pending: true, ctx: ctx}
	readiness.mounts[mount] = state
	return state
}

// StorageReadyError reports the longest matching mount's initialization state.
// Virtual ancestors (including /) remain available while independent mounts load.
func StorageReadyError(path string) error {
	path = utils.FixAndCleanPath(path)
	readiness.RLock()
	defer readiness.RUnlock()
	var selected *storageReadiness
	longest := -1
	for mount, state := range readiness.mounts {
		actual := utils.GetActualMountPath(mount)
		if utils.IsSubPath(actual, path) && len(actual) > longest {
			longest, selected = len(actual), state
		}
	}
	if selected == nil {
		return nil
	}
	if selected.pending && selected.ctx != nil && selected.ctx.Err() != nil {
		return fmt.Errorf("%w: %s", errs.StorageNotInit, selected.ctx.Err())
	}
	if selected.pending {
		return fmt.Errorf("%w: storage is initializing", errs.StorageNotInit)
	}
	if selected.err != nil {
		return fmt.Errorf("%w: %s", errs.StorageNotInit, selected.err)
	}
	return nil
}

func removeStorageReadiness(mount string) {
	readiness.Lock()
	delete(readiness.mounts, utils.FixAndCleanPath(mount))
	readiness.Unlock()
}
