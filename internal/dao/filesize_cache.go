package dao

import (
	"sync"
	"time"
)

// MinFileSizeForCache is the minimum file size to cache (1KB)
// This prevents caching error responses which are typically very small
const MinFileSizeForCache = 1024

// FileSizeCache provides high-performance file size caching
// File sizes rarely change, so we can cache them for extended periods
type FileSizeCache struct {
	mu      sync.RWMutex
	entries map[string]*fileSizeCacheEntry
	// LRU eviction
	lruList []string
	maxSize int
}

type fileSizeCacheEntry struct {
	Size      int64
	CachedAt  time.Time
	ExpiresAt time.Time
}

// NewFileSizeCache creates a new file size cache
func NewFileSizeCache(maxSize int) *FileSizeCache {
	if maxSize <= 0 {
		maxSize = 10000 // Default: cache up to 10k file sizes
	}
	return &FileSizeCache{
		entries: make(map[string]*fileSizeCacheEntry),
		lruList: make([]string, 0, maxSize),
		maxSize: maxSize,
	}
}

// Get retrieves cached file size with validation
func (c *FileSizeCache) Get(path string) (int64, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[path]
	if !ok {
		return 0, false
	}

	// Check expiration
	if time.Now().After(entry.ExpiresAt) {
		return 0, false
	}

	// Validate cached size is reasonable (prevent using corrupted cache entries)
	if entry.Size < MinFileSizeForCache {
		// Cached value is suspiciously small, invalidate it
		return 0, false
	}

	return entry.Size, true
}

// Set stores file size with TTL
func (c *FileSizeCache) Set(path string, size int64, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Update existing entry
	if entry, exists := c.entries[path]; exists {
		entry.Size = size
		entry.CachedAt = now
		entry.ExpiresAt = now.Add(ttl)
		return
	}

	// Add new entry
	c.entries[path] = &fileSizeCacheEntry{
		Size:      size,
		CachedAt:  now,
		ExpiresAt: now.Add(ttl),
	}

	// LRU management
	c.lruList = append(c.lruList, path)

	// Evict oldest if over capacity
	if len(c.lruList) > c.maxSize {
		oldestPath := c.lruList[0]
		c.lruList = c.lruList[1:]
		delete(c.entries, oldestPath)
	}
}

// Delete removes a cached entry
func (c *FileSizeCache) Delete(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, path)
}

// CleanExpired removes expired entries (call periodically)
func (c *FileSizeCache) CleanExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for path, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, path)
			removed++
		}
	}

	// Rebuild LRU list
	if removed > 0 {
		newList := make([]string, 0, len(c.entries))
		for _, path := range c.lruList {
			if _, exists := c.entries[path]; exists {
				newList = append(newList, path)
			}
		}
		c.lruList = newList
	}

	return removed
}

// ClearSuspiciousEntries removes cache entries with unrealistic file sizes
func (c *FileSizeCache) ClearSuspiciousEntries(minSize int64) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	for path, entry := range c.entries {
		if entry.Size < minSize {
			delete(c.entries, path)
			removed++
		}
	}

	// Rebuild LRU list
	if removed > 0 {
		newList := make([]string, 0, len(c.entries))
		for _, path := range c.lruList {
			if _, exists := c.entries[path]; exists {
				newList = append(newList, path)
			}
		}
		c.lruList = newList
	}

	return removed
}

// Stats returns cache statistics
func (c *FileSizeCache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"entries":  len(c.entries),
		"capacity": c.maxSize,
		"usage":    float64(len(c.entries)) / float64(c.maxSize) * 100,
	}
}
