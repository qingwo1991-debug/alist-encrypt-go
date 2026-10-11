package encryption

import (
	"bytes"
	"testing"
	"time"
)

func resetV3KeyCacheForTest() {
	v3KeyCacheMu.Lock()
	v3KeyCache = make(map[string]*cacheEntry[[]byte])
	v3KeyCacheMu.Unlock()
}

func TestDeriveV3KeyCachesAndReturnsCopies(t *testing.T) {
	resetV3KeyCacheForTest()
	t.Cleanup(resetV3KeyCacheForTest)

	nonce := []byte("0123456789abcdef")
	first := DeriveV3Key("password", nonce, 1)
	if len(first) != 32 {
		t.Fatalf("key length=%d, want 32", len(first))
	}

	cacheKey := v3KeyCacheKey("password", nonce, 1)
	v3KeyCacheMu.Lock()
	entries := len(v3KeyCache)
	v3KeyCacheMu.Unlock()
	if entries != 1 {
		t.Fatalf("cache entries=%d, want 1", entries)
	}

	first[0] ^= 0xff
	second := DeriveV3Key("password", nonce, 1)
	if bytes.Equal(first, second) {
		t.Fatal("cached key was returned without defensive copy")
	}
	if cached, ok := loadCachedV3Key(cacheKey, time.Now()); !ok || !bytes.Equal(cached, second) {
		t.Fatal("cached key missing or changed after caller mutation")
	}
}

func TestDeriveV3KeySeparatesNonceAndIterations(t *testing.T) {
	resetV3KeyCacheForTest()
	t.Cleanup(resetV3KeyCacheForTest)

	keyA := DeriveV3Key("password", []byte("0123456789abcdef"), 1)
	keyB := DeriveV3Key("password", []byte("fedcba9876543210"), 1)
	keyC := DeriveV3Key("password", []byte("0123456789abcdef"), 2)
	if bytes.Equal(keyA, keyB) || bytes.Equal(keyA, keyC) {
		t.Fatal("V3 cache key did not separate nonce or iterations")
	}
}
