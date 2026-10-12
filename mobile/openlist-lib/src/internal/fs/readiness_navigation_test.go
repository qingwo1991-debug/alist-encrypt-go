package fs

import (
	"context"
	"fmt"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/internal/errs"
)

func TestUnavailableParentAllowsVirtualChildNavigation(t *testing.T) {
	unavailable := fmt.Errorf("%w: parent overseas initialization failed", errs.StorageNotInit)
	if failStorageListing(unavailable, 1) {
		t.Fatal("ready nested mount navigation was blocked by unavailable parent")
	}
	if !failStorageListing(unavailable, 0) {
		t.Fatal("unavailable ordinary path became an empty successful list")
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded} {
		if !failStorageListing(err, 1) {
			t.Fatalf("cancellation swallowed with virtual child: %v", err)
		}
	}
}
