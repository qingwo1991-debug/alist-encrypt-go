package proxy

import (
	"bytes"
	"io"
	"testing"
)

func TestDecryptedBlockCacheRangeHit(t *testing.T) {
	cache := newDecryptedBlockCache(1024, 256)
	cache.putBlock("file", 0, bytes.Repeat([]byte("a"), 256))
	cache.putBlock("file", 256, bytes.Repeat([]byte("b"), 128))

	got, ok := cache.getRange("file", 0, 384)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 384 {
		t.Fatalf("len=%d, want 384", len(got))
	}
	if !bytes.Equal(got[:256], bytes.Repeat([]byte("a"), 256)) {
		t.Fatal("first block mismatch")
	}
	if !bytes.Equal(got[256:], bytes.Repeat([]byte("b"), 128)) {
		t.Fatal("second block mismatch")
	}
}

func TestDecryptedBlockCacheSupportsUnalignedStart(t *testing.T) {
	cache := newDecryptedBlockCache(1024, 256)
	cache.putBlock("file", 0, []byte("abcdefgh"))
	got, ok := cache.getRange("file", 1, 4)
	if !ok {
		t.Fatal("expected unaligned range hit")
	}
	if string(got) != "bcde" {
		t.Fatalf("got %q, want bcde", got)
	}
}

func TestDecryptedBlockCacheEvictsLRU(t *testing.T) {
	cache := newDecryptedBlockCache(512, 256)
	cache.putBlock("file", 0, bytes.Repeat([]byte("a"), 256))
	cache.putBlock("file", 256, bytes.Repeat([]byte("b"), 256))
	cache.putBlock("file", 512, bytes.Repeat([]byte("c"), 256))
	if _, ok := cache.getRange("file", 0, 256); ok {
		t.Fatal("expected first block to be evicted")
	}
	if _, ok := cache.getRange("file", 256, 512); !ok {
		t.Fatal("expected latest two blocks to remain")
	}
}

func TestDecryptedCacheReaderCachesAlignedBlocks(t *testing.T) {
	cache := newDecryptedBlockCache(1024, 4)
	reader := newDecryptedCacheReader(bytes.NewReader([]byte("abcdefgh")), cache, "file", 0)
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("read: %v", err)
	}
	got, ok := cache.getRange("file", 0, 8)
	if !ok {
		t.Fatal("expected cached range")
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptedBlockCacheStats(t *testing.T) {
	cache := newDecryptedBlockCache(1024, 4)
	cache.putBlock("file", 0, []byte("abcd"))
	if _, ok := cache.getRange("file", 1, 2); !ok {
		t.Fatal("expected hit")
	}
	if _, ok := cache.getRange("file", 8, 2); ok {
		t.Fatal("expected miss")
	}
	stats := cache.stats()
	if stats["enabled"] != true {
		t.Fatalf("enabled=%v", stats["enabled"])
	}
	if stats["hit_count"] != uint64(1) {
		t.Fatalf("hit_count=%v", stats["hit_count"])
	}
	if stats["miss_count"] != uint64(1) {
		t.Fatalf("miss_count=%v", stats["miss_count"])
	}
}
