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
