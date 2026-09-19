package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFileRangeCompatStoreBatchesPersistsAndFlushes(t *testing.T) {
	orig := fileRangeCompatFlushInterval
	fileRangeCompatFlushInterval = 40 * time.Millisecond
	defer func() { fileRangeCompatFlushInterval = orig }()

	dir := t.TempDir()
	path := filepath.Join(dir, "range_compat.json")
	store, err := NewFileRangeCompatStore(path)
	if err != nil {
		t.Fatal(err)
	}
	fs := store.(*fileRangeCompatStore)

	// A store with nothing dirty must not write on Close (zero-disk-write path).
	if err := store.Close(); err != nil {
		t.Fatalf("close clean store: %v", err)
	}
	fs.mu.RLock()
	cleanCnt := fs.writeCnt
	fs.mu.RUnlock()
	if cleanCnt != 0 {
		t.Fatalf("clean store wrote to disk %d times", cleanCnt)
	}

	// Now a burst of N writes should be collapsed into far fewer file writes.
	store, err = NewFileRangeCompatStore(path)
	if err != nil {
		t.Fatal(err)
	}
	fs = store.(*fileRangeCompatStore)
	defer store.Close()

	const n = 500
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = store.Upsert(rangeKey(i), RangeCompatState{ConsecutiveSuccesses: i, UpdatedAt: time.Now()})
		}(i)
	}
	wg.Wait()

	// Reads are served from memory immediately, without waiting for disk.
	if st, ok, _ := store.Get(rangeKey(42)); !ok || st.ConsecutiveSuccesses != 42 {
		t.Fatalf("memory read after burst failed: %+v ok=%v", st, ok)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	fs.mu.RLock()
	writes := fs.writeCnt
	fs.mu.RUnlock()
	// The 750ms debounce (here 40ms) collapses this burst: previously each of
	// the 500 Upserts wrote the whole file. Budget a couple for timer races.
	if writes > 3 {
		t.Fatalf("burst of %d upserts caused %d file writes, want <=3", n, writes)
	}

	// After Close the durable file contains the entire learned map.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted file: %v", err)
	}
	var saved map[string]RangeCompatState
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatalf("persisted json invalid: %v", err)
	}
	if len(saved) != n {
		t.Fatalf("persisted %d entries, want %d", len(saved), n)
	}
}

func TestFileRangeCompatStoreCloseIsIdempotentAndDurable(t *testing.T) {
	orig := fileRangeCompatFlushInterval
	fileRangeCompatFlushInterval = 40 * time.Millisecond
	defer func() { fileRangeCompatFlushInterval = orig }()

	dir := t.TempDir()
	path := filepath.Join(dir, "range_compat.json")
	store, err := NewFileRangeCompatStore(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Upsert("flushed", RangeCompatState{ConsecutiveFailures: 7})
	if err := store.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Close must be repeatable (server shutdown paths call it defensively).
	if err := store.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// A new store seeds from the same file: the tail survived the flush.
	reopened, err := NewFileRangeCompatStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	st, ok, _ := reopened.Get("flushed")
	if !ok || st.ConsecutiveFailures != 7 {
		t.Fatalf("flushed state lost across restart: %+v ok=%v", st, ok)
	}
}

func rangeKey(i int) string { return fmt.Sprintf("range_key_%d", i) }
