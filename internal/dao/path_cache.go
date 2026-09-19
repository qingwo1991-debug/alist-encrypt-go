package dao

import (
	"sync"
	"sync/atomic"
	"time"
)

// PathEntry stores all path-related information in one place.
// Both EncryptedPath and DisplayPath index the same immutable value.
//
// Value semantics: the cache stores struct copies, never exposes internal
// pointers, and never stores a caller-owned pointer. Every public read returns
// a defensive copy (with the nonce slice cloned) and every write stores a
// deep copy, so callers that mutate a returned entry can only corrupt their
// own copy — there is no shared mutable state and no data race on the entry.
type PathEntry struct {
	EncryptedPath     string // Primary key (encrypted/real path)
	DisplayPath       string // Secondary index (decrypted/display path)
	Name              string // Display filename
	Size              int64  // File size
	CiphertextSize    int64  // Upstream ciphertext size
	ContentVersion    int    // 1 legacy, 2 header-based
	HeaderLen         int64  // Header bytes for v2
	NonceField        []byte // V2 nonce field for direct decrypt reuse
	IsDir             bool   // Is directory
	RawURL            string // Cached upstream direct URL
	RawURLAuthScope   string // Irreversible Authorization+Cookie scope for RawURL
	Sign              string // Cached upstream sign
	ExpiresAt         int64  // Unix nano timestamp for TTL expiration
	UpstreamFetchedAt int64  // Unix nano timestamp when upstream metadata was last fetched
}

// IsExpired checks if the entry has expired.
func (p PathEntry) IsExpired() bool {
	return time.Now().UnixNano() > p.ExpiresAt
}

// clone deep-copies the nonce slice so the copy cannot alias internal storage.
func (p PathEntry) clone() PathEntry {
	if len(p.NonceField) > 0 {
		p.NonceField = append([]byte(nil), p.NonceField...)
	}
	return p
}

// pathCacheShard is a single shard of the cache with its own lock.
// Both maps store PathEntry VALUES — no pointer aliasing between the two
// indexes (each key gets its own copy), so mutating one cannot corrupt the
// other.
type pathCacheShard struct {
	mu         sync.RWMutex
	byEncPath  map[string]PathEntry // encryptedPath -> entry
	byDispPath map[string]PathEntry // displayPath -> entry
}

// PathCache provides a high-performance dual-indexed path cache with
// immutable-value semantics. It uses sharding to reduce lock contention.
type PathCache struct {
	shards      []*pathCacheShard
	shardCount  uint32
	shardMask   uint32
	maxPerShard int

	// Stats
	hits   uint64
	misses uint64
}

// NewPathCache creates a new path cache with specified shard count.
// shardCount should be power of 2 for optimal performance.
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
			byEncPath:  make(map[string]PathEntry, maxPerShard),
			byDispPath: make(map[string]PathEntry, maxPerShard),
		}
	}

	return &PathCache{
		shards:      shards,
		shardCount:  uint32(shardCount),
		shardMask:   uint32(shardCount - 1),
		maxPerShard: maxPerShard,
	}
}

// getShard returns the shard for a given path using FNV-1a hash.
func (c *PathCache) getShard(path string) *pathCacheShard {
	hash := fnv1a(path)
	return c.shards[hash&c.shardMask]
}

// Set stores a copy of the entry under the encrypted path, and under the
// display path too when it is a distinct value. The caller's pointer is never
// retained or mutated, so the cache cannot be corrupted from outside.
func (c *PathCache) Set(entry *PathEntry, ttl time.Duration) {
	if entry == nil || entry.EncryptedPath == "" {
		return
	}

	// Deep-copy into a canonical value owned by the cache.
	canon := entry.clone()
	canon.ExpiresAt = time.Now().Add(ttl).UnixNano()

	// Store under the encrypted path's shard.
	encShard := c.getShard(canon.EncryptedPath)
	encShard.mu.Lock()
	if len(encShard.byEncPath) >= c.maxPerShard {
		c.evictOldest(encShard)
	}
	encShard.byEncPath[canon.EncryptedPath] = canon
	encShard.mu.Unlock()

	// Also index by display path if different.
	if canon.DisplayPath != "" && canon.DisplayPath != canon.EncryptedPath {
		dispShard := c.getShard(canon.DisplayPath)
		dispShard.mu.Lock()
		// A bare entry that was initially cached under its own display path (no
		// real encrypted name known yet) leaves a stale byEncPath mirror under
		// the display key. Once a real distinct encrypted path is stored, drop
		// that stale mirror so Get(displayPath) cannot resolve an old
		// ContentVersion (e.g. 0) ahead of this fresher entry.
		if stale, present := dispShard.byEncPath[canon.DisplayPath]; present && stale.EncryptedPath == canon.DisplayPath {
			delete(dispShard.byEncPath, canon.DisplayPath)
		}
		dispShard.byDispPath[canon.DisplayPath] = canon
		dispShard.mu.Unlock()
	}
}

// Get retrieves a copy of the entry by either path (encrypted or display).
// Returns ok = false when absent or expired.
func (c *PathCache) Get(path string) (PathEntry, bool) {
	shard := c.getShard(path)
	shard.mu.RLock()

	if entry, ok := shard.byEncPath[path]; ok {
		shard.mu.RUnlock()
		if !entry.IsExpired() {
			atomic.AddUint64(&c.hits, 1)
			return entry.clone(), true
		}
		atomic.AddUint64(&c.misses, 1)
		return PathEntry{}, false
	}

	if entry, ok := shard.byDispPath[path]; ok {
		shard.mu.RUnlock()
		if !entry.IsExpired() {
			atomic.AddUint64(&c.hits, 1)
			return entry.clone(), true
		}
		atomic.AddUint64(&c.misses, 1)
		return PathEntry{}, false
	}

	shard.mu.RUnlock()
	atomic.AddUint64(&c.misses, 1)
	return PathEntry{}, false
}

// GetByPath is an alias for Get (either index).
func (c *PathCache) GetByPath(path string) (PathEntry, bool) {
	return c.Get(path)
}

// GetByEncPath retrieves a copy of the entry specifically by encrypted path.
func (c *PathCache) GetByEncPath(encPath string) (PathEntry, bool) {
	shard := c.getShard(encPath)
	shard.mu.RLock()
	entry, ok := shard.byEncPath[encPath]
	shard.mu.RUnlock()

	if ok && !entry.IsExpired() {
		atomic.AddUint64(&c.hits, 1)
		return entry.clone(), true
	}
	atomic.AddUint64(&c.misses, 1)
	return PathEntry{}, false
}

// GetByDispPath retrieves a copy of the entry specifically by display path.
func (c *PathCache) GetByDispPath(dispPath string) (PathEntry, bool) {
	shard := c.getShard(dispPath)
	shard.mu.RLock()
	entry, ok := shard.byDispPath[dispPath]
	shard.mu.RUnlock()

	if ok && !entry.IsExpired() {
		atomic.AddUint64(&c.hits, 1)
		return entry.clone(), true
	}
	atomic.AddUint64(&c.misses, 1)
	return PathEntry{}, false
}

// GetEncPath returns the encrypted path for a display path.
func (c *PathCache) GetEncPath(displayPath string) (string, bool) {
	entry, ok := c.GetByDispPath(displayPath)
	if ok {
		return entry.EncryptedPath, true
	}
	return "", false
}

// GetSize returns the file size for either path.
func (c *PathCache) GetSize(path string) (int64, bool) {
	entry, ok := c.Get(path)
	if ok && entry.Size > 0 {
		return entry.Size, true
	}
	return 0, false
}

// Delete removes an entry by encrypted path (and its display-path index).
func (c *PathCache) Delete(encPath string) {
	shard := c.getShard(encPath)
	shard.mu.Lock()

	if entry, ok := shard.byEncPath[encPath]; ok {
		delete(shard.byEncPath, encPath)

		// Also remove the display-path index.
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

// evictOldest removes expired entries, or the oldest 10% if none expired.
// Called with the shard's write lock already held; it only touches the same
// shard's indexes (cross-shard stale copies are left to expire, which is
// harmless because values are independent copies).
func (c *PathCache) evictOldest(shard *pathCacheShard) {
	now := time.Now().UnixNano()
	removed := 0
	target := len(shard.byEncPath) / 10
	if target < 10 {
		target = 10
	}

	// First pass: remove expired entries (from both indexes of this shard).
	for path, entry := range shard.byEncPath {
		if now > entry.ExpiresAt {
			delete(shard.byEncPath, path)
			if entry.DisplayPath != "" && entry.DisplayPath != entry.EncryptedPath {
				if cur, present := shard.byDispPath[entry.DisplayPath]; present && cur.EncryptedPath == path {
					delete(shard.byDispPath, entry.DisplayPath)
				}
			}
			removed++
		}
	}

	// If not enough were removed, remove the single oldest entry.
	if removed < target {
		var oldestKey string
		var oldestAt int64
		found := false
		for path, entry := range shard.byEncPath {
			if !found || entry.ExpiresAt < oldestAt {
				oldestAt = entry.ExpiresAt
				oldestKey = path
				found = true
			}
		}
		if found {
			entry := shard.byEncPath[oldestKey]
			delete(shard.byEncPath, oldestKey)
			if entry.DisplayPath != "" && entry.DisplayPath != entry.EncryptedPath {
				if cur, present := shard.byDispPath[entry.DisplayPath]; present && cur.EncryptedPath == oldestKey {
					delete(shard.byDispPath, entry.DisplayPath)
				}
			}
		}
	}
}

// CleanExpired removes all expired entries across all shards.
func (c *PathCache) CleanExpired() int {
	removed := 0
	for _, shard := range c.shards {
		shard.mu.Lock()
		for path, entry := range shard.byEncPath {
			if time.Now().UnixNano() > entry.ExpiresAt {
				delete(shard.byEncPath, path)
				if entry.DisplayPath != "" && entry.DisplayPath != entry.EncryptedPath {
					// Only remove the matching same-shard display index entry.
					if cur, present := shard.byDispPath[entry.DisplayPath]; present && cur.EncryptedPath == path {
						delete(shard.byDispPath, entry.DisplayPath)
					}
				}
				removed++
			}
		}
		shard.mu.Unlock()
	}
	return removed
}

// Stats returns cache statistics.
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

// fnv1a implements FNV-1a hash for strings.
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

// nextPowerOf2 returns the next power of 2 >= n.
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
