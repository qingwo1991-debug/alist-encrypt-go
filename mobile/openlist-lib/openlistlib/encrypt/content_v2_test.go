package encrypt

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func resetV2KeyCacheForTest(t *testing.T) {
	t.Helper()
	v2KeyCacheMu.Lock()
	v2KeyCache = make(map[string]v2KeyCacheEntry)
	v2KeyCacheMu.Unlock()
	t.Cleanup(func() {
		v2KeyCacheMu.Lock()
		v2KeyCache = make(map[string]v2KeyCacheEntry)
		v2KeyCacheMu.Unlock()
	})
}

func fastV2KeyDeriver(password, encType string, keyLen int) []byte {
	fill := byte(len(password) + len(encType))
	return bytes.Repeat([]byte{fill}, keyLen)
}

func TestAutoDecryptReaderSupportsV2AndLegacy(t *testing.T) {
	password := "test-password"
	plain := []byte("hello v2 content compatibility")

	for _, encType := range []EncryptionType{EncTypeAESCTR, EncTypeRC4, EncTypeChaCha20} {
		enc, err := NewLatestContentEncryptor(password, string(encType), int64(len(plain)))
		if err != nil {
			t.Fatalf("new latest encryptor %s: %v", encType, err)
		}
		reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
		if err != nil {
			t.Fatalf("encrypt reader %s: %v", encType, err)
		}
		ciphertext, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read ciphertext %s: %v", encType, err)
		}
		decReader, meta, err := AutoDecryptReader(password, encType, bytes.NewReader(ciphertext), int64(len(ciphertext)))
		if err != nil {
			t.Fatalf("auto decrypt %s: %v", encType, err)
		}
		got, err := io.ReadAll(decReader)
		if err != nil {
			t.Fatalf("read decrypted %s: %v", encType, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("plaintext mismatch %s: got=%q want=%q", encType, got, plain)
		}
		if !meta.IsV2() {
			t.Fatalf("expected v2 meta for %s", encType)
		}
	}

	legacy, err := NewFlowEncryptor(password, EncTypeAESCTR, int64(len(plain)))
	if err != nil {
		t.Fatalf("new legacy encryptor: %v", err)
	}
	legacyReader := NewEncryptReader(bytes.NewReader(plain), legacy)
	legacyCiphertext, err := io.ReadAll(legacyReader)
	if err != nil {
		t.Fatalf("read legacy ciphertext: %v", err)
	}
	decReader, meta, err := AutoDecryptReader(password, EncTypeAESCTR, bytes.NewReader(legacyCiphertext), int64(len(legacyCiphertext)))
	if err != nil {
		t.Fatalf("auto decrypt legacy: %v", err)
	}
	got, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("read legacy plaintext: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("legacy plaintext mismatch: got=%q want=%q", got, plain)
	}
	if meta.IsV2() {
		t.Fatalf("expected legacy meta")
	}
}

func TestV2PBKDF2CacheDoesNotSplitByNonce(t *testing.T) {
	resetV2KeyCacheForTest(t)

	nonceA := bytes.Repeat([]byte{0x01}, 16)
	nonceB := bytes.Repeat([]byte{0x02}, 16)
	if _, err := NewAESCTRV2("same-password", 1024, nonceA); err != nil {
		t.Fatalf("first cipher: %v", err)
	}
	if _, err := NewAESCTRV2("same-password", 1024, nonceB); err != nil {
		t.Fatalf("second cipher: %v", err)
	}

	v2KeyCacheMu.RLock()
	defer v2KeyCacheMu.RUnlock()
	if got := len(v2KeyCache); got != 1 {
		t.Fatalf("v2 key cache entries=%d, want 1", got)
	}
	for key := range v2KeyCache {
		if strings.Contains(key, "same-password") {
			t.Fatalf("v2 key cache key contains plaintext password: %q", key)
		}
	}
}

func TestV2PBKDF2CacheHitExtendsTTL(t *testing.T) {
	resetV2KeyCacheForTest(t)

	var derivations atomic.Int32
	derive := func(password, encType string, keyLen int) []byte {
		derivations.Add(1)
		return fastV2KeyDeriver(password, encType, keyLen)
	}
	cachedV2KeyWithDeriver("sliding-password", "AES-CTR-v2", 16, derive)

	var oldExpire time.Time
	v2KeyCacheMu.Lock()
	for key, entry := range v2KeyCache {
		entry.expireAt = time.Now().Add(time.Minute)
		oldExpire = entry.expireAt
		v2KeyCache[key] = entry
	}
	v2KeyCacheMu.Unlock()

	cachedV2KeyWithDeriver("sliding-password", "AES-CTR-v2", 16, derive)
	if got := derivations.Load(); got != 1 {
		t.Fatalf("cache hit re-derived key: derivations=%d, want 1", got)
	}

	v2KeyCacheMu.RLock()
	defer v2KeyCacheMu.RUnlock()
	for _, entry := range v2KeyCache {
		if !entry.expireAt.After(oldExpire.Add(23 * time.Hour)) {
			t.Fatalf("cache hit did not extend ttl enough: old=%s new=%s", oldExpire, entry.expireAt)
		}
	}
}

func TestV2PBKDF2CacheSingleflightSameKey(t *testing.T) {
	resetV2KeyCacheForTest(t)

	const workers = 32
	var derivations atomic.Int32
	derive := func(password, encType string, keyLen int) []byte {
		derivations.Add(1)
		time.Sleep(20 * time.Millisecond)
		return fastV2KeyDeriver(password, encType, keyLen)
	}

	start := make(chan struct{})
	results := make([][]byte, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index] = cachedV2KeyWithDeriver("shared-password", "AES-CTR-v2", 16, derive)
		}(i)
	}
	close(start)
	wg.Wait()

	if got := derivations.Load(); got != 1 {
		t.Fatalf("same-key derivations=%d, want 1", got)
	}
	for i := 1; i < len(results); i++ {
		if !bytes.Equal(results[0], results[i]) {
			t.Fatalf("worker %d received a different key", i)
		}
	}
	results[0][0] ^= 0xff
	if bytes.Equal(results[0], results[1]) {
		t.Fatal("singleflight callers received aliased key slices")
	}
}

func TestV2PBKDF2CacheBoundedAndPrunesExpired(t *testing.T) {
	resetV2KeyCacheForTest(t)

	for i := 0; i < v2KeyCacheMaxEntries+17; i++ {
		password := fmt.Sprintf("bounded-password-%d", i)
		cachedV2KeyWithDeriver(password, "AES-CTR-v2", 16, fastV2KeyDeriver)
	}

	v2KeyCacheMu.Lock()
	if got := len(v2KeyCache); got != v2KeyCacheMaxEntries {
		v2KeyCacheMu.Unlock()
		t.Fatalf("cache entries=%d, want %d", got, v2KeyCacheMaxEntries)
	}
	var expiredKey string
	for key, entry := range v2KeyCache {
		expiredKey = key
		entry.expireAt = time.Now().Add(-time.Second)
		v2KeyCache[key] = entry
		break
	}
	v2KeyCacheMu.Unlock()

	cachedV2KeyWithDeriver("bounded-password-new", "AES-CTR-v2", 16, fastV2KeyDeriver)
	v2KeyCacheMu.RLock()
	defer v2KeyCacheMu.RUnlock()
	if got := len(v2KeyCache); got != v2KeyCacheMaxEntries {
		t.Fatalf("cache entries after prune=%d, want %d", got, v2KeyCacheMaxEntries)
	}
	if _, ok := v2KeyCache[expiredKey]; ok {
		t.Fatal("expired key was not pruned when cache was full")
	}
	for key := range v2KeyCache {
		if strings.Contains(key, "bounded-password") {
			t.Fatalf("cache key contains plaintext password: %q", key)
		}
	}
}
