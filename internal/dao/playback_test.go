package dao

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
)

func TestConfirmedPlaybackPersistsAndInvalidationFencesOldPublish(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := NewFileDAO(store)
	info := &FileInfo{Path: "/plain", EncryptedPath: "/raw", Size: 12, ContentVersion: 2, HeaderLen: 32, NonceField: make([]byte, 16), GeometryIdentity: "identity", GeometryConfirmedAt: time.Now()}
	epoch := d.PlaybackEpoch(info.Path)
	if !d.PublishConfirmedPlayback(info, epoch) {
		t.Fatal("publish")
	}
	d.Stop()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	d = NewFileDAO(store)
	defer func() { d.Stop(); store.Close() }()
	got, ok := d.GetConfirmedPlayback("identity")
	if !ok || got.Size != 12 {
		t.Fatalf("restart: %+v %v", got, ok)
	}
	got.NonceField[0] = 9
	again, _ := d.GetConfirmedPlayback("identity")
	if again.NonceField[0] != 0 {
		t.Fatal("mutable returned nonce")
	}
	d.InvalidateDisplayPath(info.Path)
	if _, ok := d.GetConfirmedPlayback("identity"); ok {
		t.Fatal("invalidated persisted result survived")
	}
	if d.PublishConfirmedPlayback(info, epoch) {
		t.Fatal("old epoch published")
	}
	if got, ok := d.Get(info.Path); ok && (got.ContentVersion != 0 || len(got.NonceField) != 0) {
		t.Fatalf("stale geometry: %+v", got)
	}
}

func TestPlaybackLoadsCoalesceCancelOneWaiterAndStopJoins(t *testing.T) {
	d := &FileDAO{}
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	load := func(ctx context.Context) (interface{}, error) {
		calls.Add(1)
		close(started)
		<-release
		return "complete", nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := d.DoPlaybackLoad(ctx, "same", load); first <- err }()
	<-started
	var wg sync.WaitGroup
	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := d.DoPlaybackLoad(context.Background(), "same", load)
			if err != nil || v != "complete" {
				t.Errorf("waiter %v %v", v, err)
			}
		}()
	}
	// Explicit waiter admission barrier, not a timing guess.
	deadline := time.After(time.Second)
	for {
		d.playback.mu.Lock()
		n := d.playback.flights["same"].waiters
		d.playback.mu.Unlock()
		if n == 16 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("waiters not admitted")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-first; err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("loads=%d", calls.Load())
	}
	d.stopPlayback()
	if _, err := d.DoPlaybackLoad(context.Background(), "after-stop", load); err == nil {
		t.Fatal("accepted after stop")
	}
}

func TestCanceledPlaybackFlightRetainsAdmissionUntilWorkerExits(t *testing.T) {
	d := &FileDAO{}
	started := make(chan struct{})
	release := make(chan struct{})
	canceled := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := d.DoPlaybackLoad(ctx, "key", func(work context.Context) (interface{}, error) {
			close(started)
			<-work.Done()
			close(canceled)
			<-release
			return nil, work.Err()
		})
		done <- err
	}()
	<-started
	cancel()
	<-done
	<-canceled
	d.playback.mu.Lock()
	_, present := d.playback.flights["key"]
	d.playback.mu.Unlock()
	if !present {
		t.Fatal("released before real exit")
	}
	stopped := make(chan struct{})
	go func() { d.stopPlayback(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop did not join worker")
	default:
	}
	close(release)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop failed to join")
	}
}

// One listing entry whose size moved must not revoke every other confirmation
// and must not move the fence that queued background probes were admitted
// under. The previous global invalidation made a probe wait out its queue slot
// and then fail as size_probe_invalidated without reading a single byte, so
// listings never accumulated confirmed geometry.
func TestInvalidateDisplayPathIsScopedToThatPath(t *testing.T) {
	d := newTestFileDAO(t)
	defer d.Stop()
	confirmedAt := time.Now().Add(-time.Minute)
	publish := func(path string) string {
		identity := "id:" + path
		info := &FileInfo{Path: path, EncryptedPath: "/raw" + path, Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, GeometryIdentity: identity, GeometryConfirmedAt: confirmedAt}
		if !d.PublishConfirmedPlayback(info, d.PlaybackEpoch(path)) {
			t.Fatalf("publish %s", path)
		}
		return identity
	}
	aID, bID := publish("/a"), publish("/b")
	admittedForB := d.PlaybackEpoch("/b")

	d.InvalidateDisplayPath("/a")

	if _, ok := d.GetConfirmedPlayback(aID); ok {
		t.Fatal("revoked path kept its confirmation")
	}
	if _, ok := d.GetConfirmedPlayback(bID); !ok {
		t.Fatal("unrelated path lost its confirmation")
	}
	if got := d.PlaybackEpoch("/b"); got != admittedForB {
		t.Fatalf("unrelated path fence moved: %d -> %d", admittedForB, got)
	}
	if got := d.PlaybackEpoch("/a"); got == admittedForB {
		t.Fatal("revoked path fence did not move")
	}
	// A probe admitted for /b before /a was revoked must still publish.
	late := &FileInfo{Path: "/b", EncryptedPath: "/raw/b", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, GeometryIdentity: "id:/b:late", GeometryConfirmedAt: time.Now()}
	if !d.PublishConfirmedPlayback(late, admittedForB) {
		t.Fatal("unrelated path publication rejected after another path was revoked")
	}
}
