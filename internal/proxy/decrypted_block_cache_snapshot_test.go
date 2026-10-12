package proxy

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestDecryptedBlockCacheSnapshotAliasIsolation(t *testing.T) {
	cache := newDecryptedBlockCache(16, 8)
	input := []byte("abcdefgh")
	cache.putBlock("file", 0, input)
	input[0] = 'X'
	cache.putBlock("file", 8, []byte("ijklmnop"))
	got, ok := cache.getRange("file", 2, 12)
	if !ok || string(got) != "cdefghijklmn" {
		t.Fatalf("unaligned multi-block range = %q, %v", got, ok)
	}
	got[0] = 'X'
	again, ok := cache.getRange("file", 2, 12)
	if !ok || string(again) != "cdefghijklmn" {
		t.Fatalf("caller mutation leaked into cache: %q, %v", again, ok)
	}
	cache.putBlock("file", 0, []byte("ABCDEFGH"))
	cache.putBlock("other", 0, []byte("12345678"))
	if string(again) != "cdefghijklmn" {
		t.Fatalf("replacement or eviction mutated returned snapshot: %q", again)
	}
	if _, ok := cache.getRange("file", 8, 8); ok {
		t.Fatal("expected oldest block eviction")
	}
}

func TestDecryptedBlockCacheSnapshotMissUnlocks(t *testing.T) {
	cache := newDecryptedBlockCache(16, 8)
	cache.putBlock("file", 0, []byte("abcd"))
	if got, ok := cache.getRange("file", 0, 8); ok || got != nil {
		t.Fatalf("short block should miss: %q, %v", got, ok)
	}
	cache.putBlock("file", 0, []byte("abcdefgh"))
	if got, ok := cache.getRange("file", 0, 16); ok || got != nil {
		t.Fatalf("missing second block should miss: %q, %v", got, ok)
	}
	cache.putBlock("file", 8, []byte("ijklmnop"))
	if got, ok := cache.getRange("file", 0, 16); !ok || string(got) != "abcdefghijklmnop" {
		t.Fatalf("range after misses = %q, %v", got, ok)
	}
	stats := cache.stats()
	if stats["miss_count"] != uint64(2) || stats["hit_count"] != uint64(1) {
		t.Fatalf("unexpected stats: %v", stats)
	}
}

func TestDecryptedBlockCacheConcurrentSnapshotReplaceEvict(t *testing.T) {
	const blockSize = 4096
	cache := newDecryptedBlockCache(2*blockSize, blockSize)
	a := bytes.Repeat([]byte{'a'}, blockSize)
	b := bytes.Repeat([]byte{'b'}, blockSize)
	cache.putBlock("file", 0, a)
	cache.putBlock("file", blockSize, a)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			cache.putBlock("file", 0, a)
			cache.putBlock("file", blockSize, b)
			cache.putBlock("other", 0, b) // Force eviction alongside replacement.
			cache.putBlock("file", 0, b)
			cache.putBlock("file", blockSize, a)
		}
	}()
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				got, ok := cache.getRange("file", 0, 2*blockSize)
				if !ok {
					continue // Concurrent eviction is a legitimate miss.
				}
				if len(got) != 2*blockSize {
					t.Errorf("snapshot length = %d", len(got))
					return
				}
				for _, block := range [][]byte{got[:blockSize], got[blockSize:]} {
					if !bytes.Equal(block, a) && !bytes.Equal(block, b) {
						t.Error("snapshot contains torn or caller-mutated block")
						return
					}
				}
				// Each reader must own its result, even while another reader
				// copies the same immutable cache block outside the mutex.
				for j := range got {
					got[j] = 'X'
				}
			}
		}()
	}
	wg.Wait()
	stats := cache.stats()
	if stats["used_bytes"].(int64) > stats["max_bytes"].(int64) {
		t.Fatalf("capacity exceeded: %v", stats)
	}
}

func BenchmarkDecryptedBlockCacheSnapshotRange(b *testing.B) {
	const blockSize = 256 * 1024
	for _, blocks := range []int{1, 4, 32} {
		b.Run(fmt.Sprintf("blocks=%d", blocks), func(b *testing.B) {
			length := int64(blocks * blockSize)
			cache := newDecryptedBlockCache(length, blockSize)
			data := bytes.Repeat([]byte{'a'}, blockSize)
			for i := 0; i < blocks; i++ {
				cache.putBlock("file", int64(i*blockSize), data)
			}
			b.ReportAllocs()
			b.SetBytes(length)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := cache.getRange("file", 0, length); !ok {
					b.Fatal("unexpected miss")
				}
			}
		})
	}
}

func BenchmarkDecryptedBlockCacheSnapshotParallel(b *testing.B) {
	const blockSize = 256 * 1024
	cache := newDecryptedBlockCache(4*blockSize, blockSize)
	data := bytes.Repeat([]byte{'a'}, blockSize)
	for i := 0; i < 4; i++ {
		cache.putBlock("file", int64(i*blockSize), data)
	}
	b.ReportAllocs()
	b.SetBytes(4 * blockSize)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := cache.getRange("file", 0, 4*blockSize); !ok {
				b.Error("unexpected miss")
			}
		}
	})
}
