package encryption

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestV3AuthenticatedRecordBudgetFullReaderFallsBack(t *testing.T) {
	c, want, _ := v3MemoryFixture(t, 64, 130)
	cache := NewV3AuthenticatedRecordCache(64, time.Minute)
	key := recordTestKey(t)
	calls := 0
	loader := recordLoader(t, c.Cipher, want, 64, &calls)
	pinned, err := cache.Load(context.Background(), key, 0, c.Cipher, 64, 130, loader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewV3RecordReader(context.Background(), c.Cipher, 64, 1, 3, -1, 130, cache, key, loader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil || !bytes.Equal(got, want[67:]) {
		t.Fatalf("fallback %x %v", got, err)
	}
	if calls != 3 || cache.Stats().OwnedBytes != 64 {
		t.Fatalf("fallback ownership/transport %+v calls %d", cache.Stats(), calls)
	}
	pinned.Release()
	if cache.Stats().OwnedBytes != 0 {
		t.Fatal("pin leaked")
	}
}
func TestV3AuthenticatedRecordReaderFailureStickyAndCancelRelease(t *testing.T) {
	c, want, _ := v3MemoryFixture(t, 64, 130)
	cache := NewV3AuthenticatedRecordCache(128, time.Minute)
	key := recordTestKey(t)
	calls := 0
	loader := recordLoader(t, c.Cipher, want, 64, &calls)
	ctx, cancel := context.WithCancel(context.Background())
	r, err := NewV3RecordReader(ctx, c.Cipher, 64, 0, 0, -1, 130, cache, key, loader)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 1)
	if _, err := r.Read(p); err != nil {
		t.Fatal(err)
	}
	cancel()
	if n, err := r.Read(p); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatal("cancel failed")
	}
	// Evict the former current record; cancellation must have released its pin.
	second, err := cache.Load(context.Background(), key, 1, c.Cipher, 64, 130, loader)
	if err != nil {
		t.Fatal(err)
	}
	second.Release()
	third, err := cache.Load(context.Background(), key, 2, c.Cipher, 64, 130, loader)
	if err != nil {
		t.Fatal(err)
	}
	third.Release()
	if cache.Stats().PinnedEvictedBytes != 0 {
		t.Fatal("cancel retained lease")
	}
	failure := errors.New("transport failed")
	r, err = NewV3RecordReader(context.Background(), c.Cipher, 64, 0, 0, 2, 130, cache, key, func(context.Context, uint64) ([]byte, error) { return nil, failure })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Read(p); err != failure {
		t.Fatal(err)
	}
	if _, err := r.Read(p); err != failure {
		t.Fatal("failure not sticky")
	}
	r.Close()
}
