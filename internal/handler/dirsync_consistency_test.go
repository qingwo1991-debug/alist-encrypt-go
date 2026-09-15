package handler

import (
	"context"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
)

func newTestBoltStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create bolt store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func mustUpsertSnapshot(t *testing.T, store *BoltDirSyncStore, snap DirListSnapshot) {
	t.Helper()
	if err := store.UpsertSnapshot(context.Background(), snap); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}
}

// TestSetSnapshotSyncingCasTransitions verifies the atomic sync-state
// transitions: a stale row flips to syncing; a syncing row completes to fresh;
// but a fresh row is never downgraded back to syncing by a lagging marker.
func TestSetSnapshotSyncingCasTransitions(t *testing.T) {
	store := NewBoltDirSyncStore(newTestBoltStore(t))
	ctx := context.Background()
	const scope = "/test/encrypt::deadbeefdeadbeef"

	mustUpsertSnapshot(t, store, DirListSnapshot{
		ScopeKey:    scope,
		SyncState:   "stale",
		ItemCount:   100,
		PayloadJSON: []byte(`{"code":200,"data":{"content":[{"name":"a"}]}}`),
	})

	// stale -> syncing must succeed.
	changed, err := store.SetSnapshotSyncing(ctx, scope, true, "")
	if err != nil {
		t.Fatalf("mark syncing: %v", err)
	}
	if !changed {
		t.Fatal("stale -> syncing should have applied")
	}
	snap, ok, _ := store.GetSnapshot(ctx, scope)
	if !ok || snap.SyncState != "syncing" || !snap.Stale {
		t.Fatalf("row should be syncing+stale, got %+v", snap)
	}

	// Completing from syncing must apply.
	changed, err = store.SetSnapshotSyncing(ctx, scope, false, "")
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !changed {
		t.Fatal("syncing -> fresh should have applied")
	}
	snap, ok, _ = store.GetSnapshot(ctx, scope)
	if !ok || snap.SyncState != "fresh" || snap.Stale {
		t.Fatalf("row should be fresh+clean, got %+v", snap)
	}

	// A lagging follower's syncing=true must NOT flip the fresh row back to
	// syncing (this is the stuck-syncing race the CAS is protecting against).
	changed, err = store.SetSnapshotSyncing(ctx, scope, true, "")
	if err != nil {
		t.Fatalf("lagging syncing marker: %v", err)
	}
	if changed {
		t.Fatal("a fresh row must not be downgraded back to syncing by a late marker")
	}
	snap, ok, _ = store.GetSnapshot(ctx, scope)
	if !ok || snap.SyncState != "fresh" {
		t.Fatalf("row should still be fresh, got %+v", snap)
	}
}

// TestSetSnapshotSyncingCompletionNoopFromState verifies completion only fires
// from the syncing state: a late completion on an already-fresh row is a no-op.
func TestSetSnapshotSyncingCompletionNoopFromState(t *testing.T) {
	store := NewBoltDirSyncStore(newTestBoltStore(t))
	ctx := context.Background()
	const scope = "/test::00ff00ff00ff00ff"

	mustUpsertSnapshot(t, store, DirListSnapshot{
		ScopeKey:   scope,
		SyncState:  "fresh",
		ItemCount:  1,
		LastSyncAt: time.Now(),
	})

	// Completion (syncing=false) against a fresh row must be a no-op change.
	changed, err := store.SetSnapshotSyncing(ctx, scope, false, "")
	if err != nil || changed {
		t.Fatalf("completing a non-syncing row should be no-op (changed=%v err=%v)", changed, err)
	}
	snap, ok, _ := store.GetSnapshot(ctx, scope)
	if !ok || snap.SyncState != "fresh" {
		t.Fatalf("state should remain fresh, got %+v", snap)
	}

	// Error completion also only applies from syncing.
	changed, err = store.SetSnapshotSyncing(ctx, scope, false, "boom")
	if err != nil || changed {
		t.Fatalf("error-completing a fresh row should be no-op (changed=%v err=%v)", changed, err)
	}
	snap, ok, _ = store.GetSnapshot(ctx, scope)
	if !ok || snap.SyncState != "fresh" || snap.LastError != "" {
		t.Fatalf("state should remain clean fresh, got %+v", snap)
	}
}

// TestSetSnapshotSyncingErrorTransition verifies failure completion sets the
// stale state + retry window only when coming from syncing.
func TestSetSnapshotSyncingErrorTransition(t *testing.T) {
	store := NewBoltDirSyncStore(newTestBoltStore(t))
	ctx := context.Background()
	const scope = "req::"

	mustUpsertSnapshot(t, store, DirListSnapshot{ScopeKey: scope, SyncState: "syncing", ItemCount: 0})
	if changed, _ := store.SetSnapshotSyncing(ctx, scope, false, "upstream timeout"); !changed {
		t.Fatal("syncing -> stale should apply")
	}
	snap, ok, _ := store.GetSnapshot(ctx, scope)
	if !ok {
		t.Fatal("row missing after transition")
	}
	if snap.SyncState != "stale" || !snap.Stale || snap.LastError != "upstream timeout" {
		t.Fatalf("expected stale+error, got %+v", snap)
	}
	if snap.NextRefreshAt.IsZero() || !time.Now().Before(snap.NextRefreshAt) {
		t.Fatal("stale row should have a near-future refresh window")
	}
}

var _ = storage.BucketDirSync
