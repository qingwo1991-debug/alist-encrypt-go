package dao

import (
	"sync"
	"testing"
	"time"
)

func TestPathCache_BasicOperations(t *testing.T) {
	cache := NewPathCache(4, 100)

	// Test Set and Get by encrypted path
	entry := &PathEntry{
		EncryptedPath: "/encrypt/O7Jo5VOWIUj2Ff4tcg435V+YO0--c.mp4",
		DisplayPath:   "/encrypt/4k2.com@jur-024.mp4",
		Name:          "4k2.com@jur-024.mp4",
		Size:          8623489024,
		IsDir:         false,
	}

	cache.Set(entry, time.Hour)

	// Should find by encrypted path
	got, ok := cache.GetByEncPath(entry.EncryptedPath)
	if !ok {
		t.Fatal("Expected to find entry by encrypted path")
	}
	if got.Size != entry.Size {
		t.Errorf("Size mismatch: got %d, want %d", got.Size, entry.Size)
	}

	// Should find by display path
	got, ok = cache.GetByDispPath(entry.DisplayPath)
	if !ok {
		t.Fatal("Expected to find entry by display path")
	}
	if got.Size != entry.Size {
		t.Errorf("Size mismatch: got %d, want %d", got.Size, entry.Size)
	}

	// Should find by either path using Get
	got, ok = cache.Get(entry.EncryptedPath)
	if !ok {
		t.Fatal("Get should find by encrypted path")
	}

	got, ok = cache.Get(entry.DisplayPath)
	if !ok {
		t.Fatal("Get should find by display path")
	}
}

func TestPathCache_GetEncPath(t *testing.T) {
	cache := NewPathCache(4, 100)

	entry := &PathEntry{
		EncryptedPath: "/enc/abc123.mp4",
		DisplayPath:   "/enc/movie.mp4",
		Name:          "movie.mp4",
		Size:          1000000,
	}

	cache.Set(entry, time.Hour)

	// GetEncPath should return encrypted path for display path
	encPath, ok := cache.GetEncPath("/enc/movie.mp4")
	if !ok {
		t.Fatal("Expected to find encrypted path")
	}
	if encPath != "/enc/abc123.mp4" {
		t.Errorf("Wrong encrypted path: got %s, want %s", encPath, "/enc/abc123.mp4")
	}
}

func TestPathCache_GetSize(t *testing.T) {
	cache := NewPathCache(4, 100)

	entry := &PathEntry{
		EncryptedPath: "/enc/file.mp4",
		DisplayPath:   "/enc/display.mp4",
		Size:          5000000,
	}

	cache.Set(entry, time.Hour)

	// Should get size by either path
	size, ok := cache.GetSize("/enc/file.mp4")
	if !ok || size != 5000000 {
		t.Errorf("GetSize by enc path failed: ok=%v, size=%d", ok, size)
	}

	size, ok = cache.GetSize("/enc/display.mp4")
	if !ok || size != 5000000 {
		t.Errorf("GetSize by display path failed: ok=%v, size=%d", ok, size)
	}
}

func TestPathCache_Expiration(t *testing.T) {
	cache := NewPathCache(4, 100)

	entry := &PathEntry{
		EncryptedPath: "/enc/expire.mp4",
		DisplayPath:   "/enc/expire_disp.mp4",
		Size:          1000,
	}

	// Set with very short TTL
	cache.Set(entry, 10*time.Millisecond)

	// Should find immediately
	_, ok := cache.Get(entry.EncryptedPath)
	if !ok {
		t.Fatal("Should find entry immediately after set")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should not find after expiration
	_, ok = cache.Get(entry.EncryptedPath)
	if ok {
		t.Fatal("Should not find expired entry")
	}
}

func TestPathCache_Delete(t *testing.T) {
	cache := NewPathCache(4, 100)

	entry := &PathEntry{
		EncryptedPath: "/enc/delete.mp4",
		DisplayPath:   "/enc/delete_disp.mp4",
		Size:          1000,
	}

	cache.Set(entry, time.Hour)

	// Verify it exists
	_, ok := cache.Get(entry.EncryptedPath)
	if !ok {
		t.Fatal("Entry should exist before delete")
	}

	// Delete
	cache.Delete(entry.EncryptedPath)

	// Should not find by encrypted path
	_, ok = cache.Get(entry.EncryptedPath)
	if ok {
		t.Fatal("Entry should not exist after delete")
	}

	// Should not find by display path either
	_, ok = cache.Get(entry.DisplayPath)
	if ok {
		t.Fatal("Display path index should be removed after delete")
	}
}

func TestPathCache_Concurrent(t *testing.T) {
	cache := NewPathCache(8, 100)

	var wg sync.WaitGroup
	numGoroutines := 100
	numOps := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				entry := &PathEntry{
					EncryptedPath: "/enc/file" + string(rune(id)) + string(rune(j)),
					DisplayPath:   "/disp/file" + string(rune(id)) + string(rune(j)),
					Size:          int64(id*1000 + j),
				}
				cache.Set(entry, time.Hour)
			}
		}(i)
	}

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				cache.Get("/enc/file" + string(rune(id)) + string(rune(j)))
				cache.Get("/disp/file" + string(rune(id)) + string(rune(j)))
			}
		}(i)
	}

	wg.Wait()

	// Check stats
	stats := cache.Stats()
	if stats["entries"].(int) == 0 {
		t.Error("Expected some entries after concurrent operations")
	}
}

func TestPathCache_Stats(t *testing.T) {
	cache := NewPathCache(4, 100)

	// Add some entries
	for i := 0; i < 10; i++ {
		entry := &PathEntry{
			EncryptedPath: "/enc/stats" + string(rune(i)),
			DisplayPath:   "/disp/stats" + string(rune(i)),
			Size:          int64(i * 1000),
		}
		cache.Set(entry, time.Hour)
	}

	// Do some lookups
	for i := 0; i < 5; i++ {
		cache.Get("/enc/stats" + string(rune(i)))
	}
	cache.Get("/nonexistent")

	stats := cache.Stats()

	if stats["entries"].(int) != 10 {
		t.Errorf("Expected 10 entries, got %d", stats["entries"].(int))
	}
	if stats["hits"].(uint64) != 5 {
		t.Errorf("Expected 5 hits, got %d", stats["hits"].(uint64))
	}
	if stats["misses"].(uint64) != 1 {
		t.Errorf("Expected 1 miss, got %d", stats["misses"].(uint64))
	}
}

func BenchmarkPathCache_Set(b *testing.B) {
	cache := NewPathCache(32, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		entry := &PathEntry{
			EncryptedPath: "/enc/bench" + string(rune(i%1000)),
			DisplayPath:   "/disp/bench" + string(rune(i%1000)),
			Size:          int64(i),
		}
		cache.Set(entry, time.Hour)
	}
}

func BenchmarkPathCache_Get(b *testing.B) {
	cache := NewPathCache(32, 1000)

	// Pre-populate
	for i := 0; i < 1000; i++ {
		entry := &PathEntry{
			EncryptedPath: "/enc/bench" + string(rune(i)),
			DisplayPath:   "/disp/bench" + string(rune(i)),
			Size:          int64(i),
		}
		cache.Set(entry, time.Hour)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get("/enc/bench" + string(rune(i%1000)))
	}
}

func BenchmarkPathCache_ConcurrentReadWrite(b *testing.B) {
	cache := NewPathCache(32, 1000)

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				entry := &PathEntry{
					EncryptedPath: "/enc/para" + string(rune(i%100)),
					DisplayPath:   "/disp/para" + string(rune(i%100)),
					Size:          int64(i),
				}
				cache.Set(entry, time.Hour)
			} else {
				cache.Get("/enc/para" + string(rune(i%100)))
			}
			i++
		}
	})
}

// TestPathCache_StaleBareEncEntryStopsShieldingFreshMeta is a regression test
// for the "clicked every time still slow" root cause: an initial Set with a
// bare EncryptedPath (== display path, e.g. before the real encrypted name is
// known) leaves a stale byEncPath mirror under the display key. A later Set
// with the true encrypted path wrote ContentVersion via byDispPath, but
// Get(displayPath) preferred the stale byEncPath mirror (ContentVersion=0),
// so fs/get never reused the freshly persisted V1/V2 meta and re-probed on
// every click. Set must drop that mirror when a real encrypted path is known.
func TestPathCache_StaleBareMirrorDoesNotShieldFreshMeta(t *testing.T) {
	cache := NewPathCache(4, 100)
	display := "/legacy/video.mp4"
	realEnc := "/legacy/video_enc.bin"

	// Stage 1: fetchRawURL caches with EncryptedPath unset => bare mirror.
	cache.Set(&PathEntry{
		EncryptedPath:  display,
		DisplayPath:    display,
		Size:           4096,
		ContentVersion: 0,
	}, time.Hour)

	// Stage 2: Inspector persists confirmed V1 meta with the real enc path.
	cache.Set(&PathEntry{
		EncryptedPath:  realEnc,
		DisplayPath:    display,
		Size:           4096,
		HeaderLen:      0,
		ContentVersion: 1,
	}, time.Hour)

	got, ok := cache.Get(display)
	if !ok {
		t.Fatal("expected Get(displayPath) to succeed")
	}
	if got.ContentVersion != 1 {
		t.Fatalf("Get(displayPath).ContentVersion=%d, want 1 (stale by-enc mirror must not shield fresh meta)", got.ContentVersion)
	}
}

// TestPathCache_ImmutableValue_MutationIsolated proves the immutable-value
// contract: a caller mutating a returned entry (struct fields or the nonce
// slice) can never corrupt the cached entry, because every read returns a
// defensive copy and every write stores a fresh value.
func TestPathCache_ImmutableValue_MutationIsolated(t *testing.T) {
	cache := NewPathCache(4, 100)
	cache.Set(&PathEntry{
		EncryptedPath:   "/e/victim.mp4",
		DisplayPath:     "/d/victim.mp4",
		Size:            1000,
		ContentVersion:  2,
		HeaderLen:       48,
		NonceField:      []byte{1, 2, 3, 4},
		RawURL:          "https://upstream/raw",
		RawURLAuthScope: "s1",
	}, time.Hour)

	// Corrupt the entire returned copy.
	got, ok := cache.Get("/e/victim.mp4")
	if !ok {
		t.Fatal("expected entry present")
	}
	got.Size = 42
	got.EncryptedPath = "/e/hacked"
	got.RawURL = ""
	got.NonceField[0] = 9
	got.NonceField = append(got.NonceField, 5)

	// The cache must be unaffected.
	fresh, ok := cache.Get("/e/victim.mp4")
	if !ok {
		t.Fatal("expected entry still present")
	}
	if fresh.Size != 1000 {
		t.Errorf("Size corrupted: got %d want 1000", fresh.Size)
	}
	if fresh.EncryptedPath != "/e/victim.mp4" {
		t.Errorf("EncryptedPath corrupted: got %q", fresh.EncryptedPath)
	}
	if fresh.RawURL != "https://upstream/raw" {
		t.Errorf("RawURL mutated via returned copy: %q", fresh.RawURL)
	}
	if len(fresh.NonceField) != 4 || fresh.NonceField[0] != 1 {
		t.Errorf("NonceField aliased: got %v want [1 2 3 4]", fresh.NonceField)
	}
}

// TestMapCache_IndexCopiesAreNotAliased confirms each index lookup returns its
// own slice clone, so mutating the copy from the encrypted-path lookup cannot
// affect the copy from the display-path lookup.
func TestPathCache_NonceCopiesNotAliasedBetweenIndexes(t *testing.T) {
	cache := NewPathCache(4, 100)
	nonce := []byte{1, 2, 3, 4}
	cache.Set(&PathEntry{
		EncryptedPath: "/e/b.mp4", DisplayPath: "/d/b.mp4",
		Size: 500, NonceField: nonce,
	}, time.Hour)

	viaEnc, _ := cache.GetByEncPath("/e/b.mp4")
	viaDisp, _ := cache.GetByDispPath("/d/b.mp4")

	viaEnc.NonceField[0] = 7
	// Mutating the enc copy must not leak into the disp copy's backing array.
	if viaDisp.NonceField[0] != 1 {
		t.Errorf("nonce slices are aliased across index copies: disp.Nonce[0]=%d want 1", viaDisp.NonceField[0])
	}
	// Nor into the stored value.
	again, _ := cache.GetByEncPath("/e/b.mp4")
	if again.NonceField[0] != 1 {
		t.Errorf("nonce leak into cache storage: %v", again.NonceField)
	}
}

// TestPathCache_GetMutateConcurrentExercises the full -race detector over many
// goroutines that each Get-and-mutate a returned copy. Under the old
// pointer-based cache this was a genuine data race (every caller received the
// very pointer the cache held); with value semantics it is race-free.
func TestPathCache_GetMutateConcurrent(t *testing.T) {
	cache := NewPathCache(8, 100)
	cache.Set(&PathEntry{
		EncryptedPath: "/e/race.mp4", DisplayPath: "/d/race.mp4",
		Size: 1234, ContentVersion: 1, NonceField: []byte{9, 9, 9},
	}, time.Hour)

	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 3000; i++ {
				if e, ok := cache.Get("/e/race.mp4"); ok {
					e.Size = int64(i)
					e.NonceField[0] = byte(i)
				}
			}
		}()
	}
	wg.Wait()
}

// TestPathCache_InPlaceMutateThenSetStillWorks ensures the documented
// read-modify-write pattern (mutate the returned copy, then Set it) remains
// functional for DAO mutation helpers.
func TestPathCache_InPlaceMutateThenSetStillWorks(t *testing.T) {
	cache := NewPathCache(4, 100)
	cache.Set(&PathEntry{EncryptedPath: "/e/m.mp4", DisplayPath: "/d/m.mp4", Size: 10}, time.Hour)

	e, ok := cache.Get("/e/m.mp4")
	if !ok {
		t.Fatal("missing")
	}
	e.Size = 2048
	e.RawURL = "https://x/y"
	cache.Set(&e, time.Hour)

	got, _ := cache.Get("/e/m.mp4")
	if got.Size != 2048 || got.RawURL != "https://x/y" {
		t.Fatalf("read-modify-write failed: %+v", got)
	}
}
