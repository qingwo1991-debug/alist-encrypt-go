package encrypt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func newRuntimeCacheTestServer() *ProxyServer {
	server := &ProxyServer{}
	server.ensureRuntimeCaches()
	return server
}

func TestRedirectCacheHonorsTTL(t *testing.T) {
	server := newRuntimeCacheTestServer()
	server.redirectCache.Set("expired", &CachedRedirectInfo{
		Info:     &RedirectInfo{RedirectURL: "https://expired.example/file"},
		ExpireAt: time.Now().Add(-time.Second),
	})

	if _, ok := server.loadRedirectCache("expired"); ok {
		t.Fatal("expired redirect cache entry was returned")
	}
	if _, ok := server.redirectCache.Get("expired"); ok {
		t.Fatal("expired redirect cache entry was not deleted")
	}
}

func TestRedirectCacheCapacityPrefersExpiredThenOldest(t *testing.T) {
	server := newRuntimeCacheTestServer()
	now := time.Now()
	server.redirectCache.Set("expired", &CachedRedirectInfo{
		Info:     &RedirectInfo{RedirectURL: "https://expired.example/file"},
		ExpireAt: now.Add(-time.Second),
	})
	server.redirectCache.Set("oldest-live", &CachedRedirectInfo{
		Info:     &RedirectInfo{RedirectURL: "https://oldest.example/file"},
		ExpireAt: now.Add(time.Minute),
	})
	for i := 2; i < redirectCacheMaxEntries; i++ {
		key := fmt.Sprintf("live-%04d", i)
		server.redirectCache.Set(key, &CachedRedirectInfo{
			Info:     &RedirectInfo{RedirectURL: "https://live.example/file"},
			ExpireAt: now.Add(2*time.Minute + time.Duration(i)*time.Nanosecond),
		})
	}

	server.storeRedirectCache("new-after-expired", &RedirectInfo{RedirectURL: "https://new.example/one"})
	if got := server.redirectCache.Len(); got != redirectCacheMaxEntries {
		t.Fatalf("redirect cache size after expired eviction = %d, want %d", got, redirectCacheMaxEntries)
	}
	if _, ok := server.redirectCache.Get("expired"); ok {
		t.Fatal("expired redirect entry survived capacity cleanup")
	}
	if _, ok := server.redirectCache.Get("oldest-live"); !ok {
		t.Fatal("live redirect entry was evicted while an expired entry existed")
	}

	server.storeRedirectCache("new-after-oldest", &RedirectInfo{RedirectURL: "https://new.example/two"})
	if got := server.redirectCache.Len(); got != redirectCacheMaxEntries {
		t.Fatalf("redirect cache size after oldest eviction = %d, want %d", got, redirectCacheMaxEntries)
	}
	if _, ok := server.redirectCache.Get("oldest-live"); ok {
		t.Fatal("oldest live redirect entry was not evicted at capacity")
	}
	if _, ok := server.redirectCache.Get("new-after-oldest"); !ok {
		t.Fatal("new redirect entry was not cached")
	}
}

func TestPrefetchRecentHonorsCooldownTTL(t *testing.T) {
	server := newRuntimeCacheTestServer()
	const key = "/encrypted/season"
	if !server.shouldSchedulePrefetch(key) {
		t.Fatal("first prefetch was not scheduled")
	}
	if server.shouldSchedulePrefetch(key) {
		t.Fatal("prefetch was scheduled again during its cooldown")
	}

	server.prefetchRecent.Set(key, time.Now().Add(-encryptedPrefetchCooldown-time.Second))
	if !server.shouldSchedulePrefetch(key) {
		t.Fatal("prefetch was not rescheduled after its cooldown expired")
	}
}

func TestPrefetchRecentCapacityPrefersExpiredThenOldest(t *testing.T) {
	server := newRuntimeCacheTestServer()
	now := time.Now()
	server.prefetchRecent.Set("expired", now.Add(-encryptedPrefetchCooldown-time.Second))
	server.prefetchRecent.Set("oldest-live", now.Add(-2*time.Second))
	for i := 2; i < prefetchRecentMaxEntries; i++ {
		key := fmt.Sprintf("live-%04d", i)
		server.prefetchRecent.Set(key, now.Add(-time.Second+time.Duration(i)*time.Nanosecond))
	}

	if !server.shouldSchedulePrefetch("new-after-expired") {
		t.Fatal("new prefetch was not scheduled")
	}
	if got := server.prefetchRecent.Len(); got != prefetchRecentMaxEntries {
		t.Fatalf("prefetch cache size after expired eviction = %d, want %d", got, prefetchRecentMaxEntries)
	}
	if _, ok := server.prefetchRecent.Get("expired"); ok {
		t.Fatal("expired prefetch record survived capacity cleanup")
	}
	if _, ok := server.prefetchRecent.Get("oldest-live"); !ok {
		t.Fatal("live prefetch record was evicted while an expired record existed")
	}

	if !server.shouldSchedulePrefetch("new-after-oldest") {
		t.Fatal("second new prefetch was not scheduled")
	}
	if got := server.prefetchRecent.Len(); got != prefetchRecentMaxEntries {
		t.Fatalf("prefetch cache size after oldest eviction = %d, want %d", got, prefetchRecentMaxEntries)
	}
	if _, ok := server.prefetchRecent.Get("oldest-live"); ok {
		t.Fatal("oldest live prefetch record was not evicted at capacity")
	}
	if _, ok := server.prefetchRecent.Get("new-after-oldest"); !ok {
		t.Fatal("new prefetch record was not cached")
	}
}

func TestRuntimeCacheCleanupRemovesExpiredEntries(t *testing.T) {
	server := newRuntimeCacheTestServer()
	now := time.Now()
	server.redirectCache.Set("redirect-expired", &CachedRedirectInfo{ExpireAt: now.Add(-time.Second)})
	server.redirectCache.Set("redirect-live", &CachedRedirectInfo{ExpireAt: now.Add(time.Minute)})
	server.prefetchRecent.Set("prefetch-expired", now.Add(-encryptedPrefetchCooldown-time.Second))
	server.prefetchRecent.Set("prefetch-live", now)

	server.cleanupExpiredCache()

	if _, ok := server.redirectCache.Get("redirect-expired"); ok {
		t.Fatal("periodic cleanup retained an expired redirect entry")
	}
	if _, ok := server.redirectCache.Get("redirect-live"); !ok {
		t.Fatal("periodic cleanup deleted a live redirect entry")
	}
	if _, ok := server.prefetchRecent.Get("prefetch-expired"); ok {
		t.Fatal("periodic cleanup retained an expired prefetch record")
	}
	if _, ok := server.prefetchRecent.Get("prefetch-live"); !ok {
		t.Fatal("periodic cleanup deleted a live prefetch record")
	}
}

func TestRuntimeCachesRemainBoundedUnderConcurrentWrites(t *testing.T) {
	server := newRuntimeCacheTestServer()
	now := time.Now()
	for i := 0; i < redirectCacheMaxEntries; i++ {
		server.redirectCache.Set(fmt.Sprintf("redirect-seed-%04d", i), &CachedRedirectInfo{
			ExpireAt: now.Add(time.Hour + time.Duration(i)*time.Nanosecond),
		})
	}
	for i := 0; i < prefetchRecentMaxEntries; i++ {
		server.prefetchRecent.Set(fmt.Sprintf("prefetch-seed-%04d", i), now.Add(time.Duration(i)*time.Nanosecond))
	}

	const workers = 8
	const writesPerWorker = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < writesPerWorker; i++ {
				redirectKey := fmt.Sprintf("redirect-worker-%d-%d", worker, i)
				server.storeRedirectCache(redirectKey, nil)
				server.loadRedirectCache(redirectKey)
				server.shouldSchedulePrefetch(fmt.Sprintf("prefetch-worker-%d-%d", worker, i))
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < writesPerWorker; i++ {
			server.cleanupExpiredCache()
		}
	}()
	close(start)
	wg.Wait()

	if got := server.redirectCache.Len(); got > redirectCacheMaxEntries {
		t.Fatalf("concurrent redirect cache size = %d, max %d", got, redirectCacheMaxEntries)
	}
	if got := server.prefetchRecent.Len(); got > prefetchRecentMaxEntries {
		t.Fatalf("concurrent prefetch cache size = %d, max %d", got, prefetchRecentMaxEntries)
	}
}

func BenchmarkRedirectCacheInsertAtCapacity(b *testing.B) {
	server := newRuntimeCacheTestServer()
	now := time.Now()
	for i := 0; i < redirectCacheMaxEntries; i++ {
		server.redirectCache.Set(fmt.Sprintf("seed-%04d", i), &CachedRedirectInfo{
			ExpireAt: now.Add(time.Hour + time.Duration(i)*time.Nanosecond),
		})
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.storeRedirectCache(fmt.Sprintf("new-%d", i), nil)
	}
}

func BenchmarkPrefetchRecentInsertAtCapacity(b *testing.B) {
	server := newRuntimeCacheTestServer()
	now := time.Now()
	for i := 0; i < prefetchRecentMaxEntries; i++ {
		server.prefetchRecent.Set(fmt.Sprintf("seed-%04d", i), now.Add(time.Duration(i)*time.Nanosecond))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.shouldSchedulePrefetch(fmt.Sprintf("new-%d", i))
	}
}
