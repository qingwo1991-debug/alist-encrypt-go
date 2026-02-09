package dao

import (
	"sync"
	"sync/atomic"
	"time"
)

// PathEntry stores all path-related information in one place
// Both encryptedPath and displayPath point to the same entry
type PathEntry struct {
	EncryptedPath string // Primary key (encrypted/real path)
	DisplayPath   string // Secondary index (decrypted/display path)
	Name          string // Display filename
	Size          int64  // File size
	IsDir         bool   // Is directory
	ExpiresAt     int64  // Unix nano timestamp for expiration
}

// IsExpired checks if the entry has expired
func (e *PathEntry) IsExpired() bool {
	return time.Now().UnixNano() > e.ExpiresAt
}

// pathCacheShard is a single shard of the cache with its own lock
type pathCacheShard struct {
	mu         sync.RWMutex
	byEncPath  map[string]*PathEntry // encryptedPath -> entry
	byDispPath map[string]*PathEntry // displayPath -> same entry
}

// PathCache provides high-performance dual-indexed path caching
// Uses sharding to reduce lock contention under high concurrency
type PathCache struct {
	shards     []*pathCacheShard
	shardCount uint32
	shardMask  uint32
	maxPerShard int

	// Stats
	hits   uint64
	misses uint64
}

// NewPathCache creates a new path cache with specified shard count
// shardCount should be power of 2 for optimal performance
func NewPathCache(shardCount, maxPerShard int) *PathCache {
	if shardCount <= 0 {
		shardCount = 32 // Default: 32 shards
	}
	// Round up to power of 2
	shardCount = nextPowerOf2(shardCount)

	if maxPerShard <= 0 {
		maxPerShard = 1000 // Default: 1000 entries per shard
	}

	shards := make([]*pathCacheShard, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = &pathCacheShard{
			byEncPath:  make(map[string]*PathEntry, maxPerShard),
			byDispPath: make(map[string]*PathEntry, maxPerShard),
		}
	}

	return &PathCache{
		shards:      shards,
		shardCount:  uint32(shardCount),
		shardMask:   uint32(shardCount - 1),
		maxPerShard: maxPerShard,
	}
}

// getShard returns the shard for a given path using FNV-1a hash
func (c *PathCache) getShard(path string) *pathCacheShard {
	hash := fnv1a(path)
	return c.shards[hash&c.shardMask]
}

// Set stores a path entry with dual indexing
// Both encryptedPath and displayPath will point to the same entry
func (c *PathCache) Set(entry *PathEntry, ttl time.Duration) {
	if entry.EncryptedPath == "" {
		return
	}

	entry.ExpiresAt = time.Now().Add(ttl).UnixNano()

	// Store in encrypted path's shard
	encShard := c.getShard(entry.EncryptedPath)
	encShard.mu.Lock()

	// Check capacity and evict if needed
	if len(encShard.byEncPath) >= c.maxPerShard {
		c.evictOldest(encShard)
	}

	encShard.byEncPath[entry.EncryptedPath] = entry
	encShard.mu.Unlock()

	// Also index by display path if different
	if entry.DisplayPath != "" && entry.DisplayPath != entry.EncryptedPath {
		dispShard := c.getShard(entry.DisplayPath)
		dispShard.mu.Lock()
		dispShard.byDispPath[entry.DisplayPath] = entry
		dispShard.mu.Unlock()
	}
}

// Get retrieves entry by any path (encrypted or display)
// Returns entry and true if found and not expired
func (c *PathCache) Get(path string) (*PathEntry, bool) {
	shard := c.getShard(path)
	shard.mu.RLock()

	// Try encrypted path first
	if entry, ok := shard.byEncPath[path]; ok {
		shard.mu.RUnlock()
		if !entry.IsExpired() {
			atomic.AddUint64(&c.hits, 1)
			return entry, true
		}
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	// Try display path
	if entry, ok := shard.byDispPath[path]; ok {
		shard.mu.RUnlock()
		if !entry.IsExpired() {
			atomic.AddUint64(&c.hits, 1)
			return entry, true
		}
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	shard.mu.RUnlock()
	atomic.AddUint64(&c.misses, 1)
	return nil, false
}

// GetByEncPath retrieves entry specifically by encrypted path
func (c *PathCache) GetByEncPath(encPath string) (*PathEntry, bool) {
	shard := c.getShard(encPath)
	shard.mu.RLock()
	entry, ok := shard.byEncPath[encPath]
	shard.mu.RUnlock()

	if ok && !entry.IsExpired() {
		atomic.AddUint64(&c.hits, 1)
		return entry, true
	}
	atomic.AddUint64(&c.misses, 1)
	return nil, false
}

// GetByDispPath retrieves entry specifically by display path
func (c *PathCache) GetByDispPath(dispPath string) (*PathEntry, bool) {
	shard := c.getShard(dispPath)
	shard.mu.RLock()
	entry, ok := shard.byDispPath[dispPath]
	shard.mu.RUnlock()

	if ok && !entry.IsExpired() {
		atomic.AddUint64(&c.hits, 1)
		return entry, true
	}
	atomic.AddUint64(&c.misses, 1)
	return nil, false
}

// GetEncPath returns encrypted path for a display path
func (c *PathCache) GetEncPath(displayPath string) (string, bool) {
	entry, ok := c.GetByDispPath(displayPath)
	if ok {
		return entry.EncryptedPath, true
	}
	return "", false
}

// GetSize returns file size for any path
func (c *PathCache) GetSize(path string) (int64, bool) {
	entry, ok := c.Get(path)
	if ok && entry.Size > 0 {
		return entry.Size, true
	}
	return 0, false
}

// Delete removes entry by encrypted path
func (c *PathCache) Delete(encPath string) {
	shard := c.getShard(encPath)
	shard.mu.Lock()

	if entry, ok := shard.byEncPath[encPath]; ok {
		delete(shard.byEncPath, encPath)

		// Also remove display path index
		if entry.DisplayPath != "" && entry.DisplayPath != encPath {
			dispShard := c.getShard(entry.DisplayPath)
			if dispShard != shard {
				shard.mu.Unlock()
				dispShard.mu.Lock()
				delete(dispShard.byDispPath, entry.DisplayPath)
				dispShard.mu.Unlock()
				return
			}
			delete(shard.byDispPath, entry.DisplayPath)
		}
	}

	shard.mu.Unlock()
}

// evictOldest removes expired entries, or oldest 10% if no expired
func (c *PathCache) evictOldest(shard *pathCacheShard) {
	now := time.Now().UnixNano()
	evicted := 0
	target := len(shard.byEncPath) / 10
	if target < 10 {
		target = 10
	}

	// First pass: remove expired
	for path, entry := range shard.byEncPath {
		if now > entry.ExpiresAt {
			delete(shard.byEncPath, path)
			if entry.DisplayPath != "" {
				delete(shard.byDispPath, entry.DisplayPath)
			}
			evicted++
		}
	}

	// If not enough evicted, remove oldest by expiration
	if evicted < target {
		var oldest *PathEntry
		var oldestPath string
		for path, entry := range shard.byEncPath {
			if oldest == nil || entry.ExpiresAt < oldest.ExpiresAt {
				oldest = entry
				oldestPath = path
			}
		}
		if oldest != nil {
			delete(shard.byEncPath, oldestPath)
			if oldest.DisplayPath != "" {
				delete(shard.byDispPath, oldest.DisplayPath)
			}
		}
	}
}

// CleanExpired removes all expired entries across all shards
func (c *PathCache) CleanExpired() int {
	now := time.Now().UnixNano()
	removed := 0

	for _, shard := range c.shards {
		shard.mu.Lock()
		for path, entry := range shard.byEncPath {
			if now > entry.ExpiresAt {
				delete(shard.byEncPath, path)
				if entry.DisplayPath != "" {
					delete(shard.byDispPath, entry.DisplayPath)
				}
				removed++
			}
		}
		shard.mu.Unlock()
	}

	return removed
}

// Stats returns cache statistics
func (c *PathCache) Stats() map[string]interface{} {
	totalEntries := 0
	for _, shard := range c.shards {
		shard.mu.RLock()
		totalEntries += len(shard.byEncPath)
		shard.mu.RUnlock()
	}

	hits := atomic.LoadUint64(&c.hits)
	misses := atomic.LoadUint64(&c.misses)
	total := hits + misses
	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"entries":     totalEntries,
		"shards":      c.shardCount,
		"maxPerShard": c.maxPerShard,
		"capacity":    int(c.shardCount) * c.maxPerShard,
		"hits":        hits,
		"misses":      misses,
		"hitRate":     hitRate,
	}
}

// fnv1a implements FNV-1a hash for string
func fnv1a(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	hash := uint32(offset32)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime32
	}
	return hash
}

// nextPowerOf2 returns the next power of 2 >= n
func nextPowerOf2(n int) int {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}
