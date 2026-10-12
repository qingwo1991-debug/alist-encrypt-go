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
	selectedMount := ""
	longest := -1
	for mount, state := range readiness.mounts {
		actual := utils.GetActualMountPath(mount)
		if !utils.IsSubPath(actual, path) {
			continue
		}
		if len(actual) > longest {
			longest, selected, selectedMount = len(actual), state, mount
		} else if len(actual) == longest {
			// A ready sibling wins; otherwise choose a stable diagnostic rather
			// than allowing randomized map iteration to decide the response.
			if selected.pending || selected.err != nil {
				if (!state.pending && state.err == nil) || mount < selectedMount {
					selected, selectedMount = state, mount
				}
			}
		}
	}
	return storageStateError(selected)
}

func storageStateError(state *storageReadiness) error {
	if state == nil {
		return nil
	}
	if state.pending && state.ctx != nil && state.ctx.Err() != nil {
		return fmt.Errorf("%w: %s", errs.StorageNotInit, state.ctx.Err())
	}
	if state.pending {
		return fmt.Errorf("%w: storage is initializing", errs.StorageNotInit)
	}
	if state.err != nil {
		return fmt.Errorf("%w: %s", errs.StorageNotInit, state.err)
	}
	return nil
}

// storageMountReadyError checks an exact mount, not its balanced siblings.
func storageMountReadyError(mount string) error {
	readiness.RLock()
	defer readiness.RUnlock()
	return storageStateError(readiness.mounts[utils.FixAndCleanPath(mount)])
}

func removeStorageReadiness(mount string) {
	readiness.Lock()
	delete(readiness.mounts, utils.FixAndCleanPath(mount))
	readiness.Unlock()
}
