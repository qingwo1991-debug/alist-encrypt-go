package encryption

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestV3AuthenticatedRecordEntryLimitIncludesEvictedPins(t *testing.T) {
	const entryLimit = 4096
	cipher := v3MemoryCipher(t)
	cache := NewV3AuthenticatedRecordCache(64<<20, time.Minute)
	key := recordTestKey(t)
	calls := 0
	loader := func(_ context.Context, index uint64) ([]byte, error) {
		calls++
		return cipher.Seal(index, make([]byte, 64))
	}
	leases := make([]*V3RecordLease, 0, entryLimit)
	defer func() {
		for _, l := range leases {
			l.Release()
		}
	}()
	for i := 0; i < entryLimit; i++ {
		l, err := cache.Load(context.Background(), key, uint64(i), cipher, 64, (entryLimit+1)*64, loader)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		leases = append(leases, l)
	}
	if s := cache.Stats(); s.OwnedEntries != entryLimit || s.Entries != entryLimit || s.ReservedEntries != 0 {
		t.Fatalf("initial ownership %+v", s)
	}
	// A rejected reservation may evict residents, but must keep counting pins.
	if _, err := cache.Load(context.Background(), key, entryLimit, cipher, 64, (entryLimit+1)*64, loader); !errors.Is(err, ErrV3RecordCacheFull) {
		t.Fatalf("entry limit bypass: %v", err)
	}
	if calls != entryLimit {
		t.Fatal("rejected entry called loader")
	}
	if s := cache.Stats(); s.OwnedEntries != entryLimit || s.Entries != 0 || s.PinnedEvictedBytes != entryLimit*64 {
		t.Fatalf("evicted pins lost accounting %+v", s)
	}
	leases[0].Release()
	if s := cache.Stats(); s.OwnedEntries != entryLimit-1 || s.OwnedBytes != (entryLimit-1)*64 {
		t.Fatalf("final release failed %+v", s)
	}
	replacement, err := cache.Load(context.Background(), key, entryLimit, cipher, 64, (entryLimit+1)*64, loader)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Release()
	for _, l := range leases {
		l.Release()
	}
	if s := cache.Stats(); s.OwnedEntries != 1 || s.Entries != 1 || s.ReservedEntries != 0 || s.PinnedEvictedBytes != 0 {
		t.Fatalf("ownership retirement %+v", s)
	}
}

func TestV3AuthenticatedRecordFailedLoadRetiresEntryReservation(t *testing.T) {
	cipher := v3MemoryCipher(t)
	cache := NewV3AuthenticatedRecordCache(64, time.Minute)
	key := recordTestKey(t)
	failure := errors.New("transport failure")
	_, err := cache.Load(context.Background(), key, 0, cipher, 64, 130, func(context.Context, uint64) ([]byte, error) {
		if s := cache.Stats(); s.OwnedEntries != 1 || s.ReservedEntries != 1 {
			t.Fatalf("reservation missing %+v", s)
		}
		return nil, failure
	})
	if err != failure {
		t.Fatal(err)
	}
	if s := cache.Stats(); s.OwnedEntries != 0 || s.ReservedEntries != 0 || s.OwnedBytes != 0 {
		t.Fatalf("failed reservation leaked %+v", s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	_, err = cache.Load(ctx, key, 0, cipher, 64, 130, func(context.Context, uint64) ([]byte, error) { cancel(); return cipher.Seal(0, make([]byte, 64)) })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s := cache.Stats(); s.OwnedEntries != 0 || s.ReservedEntries != 0 || s.OwnedBytes != 0 {
		t.Fatalf("canceled reservation leaked %+v", s)
	}
}
