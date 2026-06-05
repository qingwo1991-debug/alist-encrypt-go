package storage

import (
	"sync"
	"time"
)

// CacheItem represents a cached item with expiration
type CacheItem struct {
	Value      interface{}
	Expiration int64
}

// Cache provides in-memory caching with TTL
type Cache struct {
	items    map[string]CacheItem
	mu       sync.RWMutex
	ttl      time.Duration
	maxSize  int
	stopCh   chan struct{}
	stopped  bool
}

// NewCache creates a new cache with default TTL
func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		items:  make(map[string]CacheItem),
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}
	go c.cleanup()
	return c
}

// NewCacheWithLimit creates a new cache with default TTL and a maximum item count.
// When the cache is at capacity, Set() evicts the oldest expired item, or a
// random item if no expired entries exist.
func NewCacheWithLimit(ttl time.Duration, maxSize int) *Cache {
	c := &Cache{
		items:   make(map[string]CacheItem),
		ttl:     ttl,
		maxSize: maxSize,
		stopCh:  make(chan struct{}),
	}
	go c.cleanup()
	return c
}

// Stop terminates the background cleanup goroutine.
// After calling Stop, no further cleanup will occur.
func (c *Cache) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stopped {
		c.stopped = true
		close(c.stopCh)
	}
}

// Get retrieves a value from cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, found := c.items[key]
	if !found {
		return nil, false
	}
	if item.Expiration > 0 && time.Now().UnixNano() > item.Expiration {
		return nil, false
	}
	return item.Value, true
}

// Set stores a value in cache with default TTL
func (c *Cache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, c.ttl)
}

// SetWithTTL stores a value with custom TTL
func (c *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity and key is new (not an update)
	if c.maxSize > 0 {
		if _, exists := c.items[key]; !exists && len(c.items) >= c.maxSize {
			c.evictLocked()
		}
	}

	var expiration int64
	if ttl > 0 {
		expiration = time.Now().Add(ttl).UnixNano()
	}
	c.items[key] = CacheItem{
		Value:      value,
		Expiration: expiration,
	}
}

// evictLocked removes one item to make room for a new entry.
// It prefers the oldest expired item; if none are expired it removes a random item.
// Caller must hold c.mu.
func (c *Cache) evictLocked() {
	now := time.Now().UnixNano()

	// Try to find the oldest expired item
	var oldestKey string
	var oldestExp int64
	for k, item := range c.items {
		if item.Expiration > 0 && now > item.Expiration {
			if oldestKey == "" || item.Expiration < oldestExp {
				oldestKey = k
				oldestExp = item.Expiration
			}
		}
	}
	if oldestKey != "" {
		delete(c.items, oldestKey)
		return
	}

	// No expired items; remove a random item
	for k := range c.items {
		delete(c.items, k)
		return
	}
}

// Delete removes a value from cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}

// Clear removes all items from cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]CacheItem)
}

// cleanup periodically removes expired items
func (c *Cache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now().UnixNano()
			for key, item := range c.items {
				if item.Expiration > 0 && now > item.Expiration {
					delete(c.items, key)
				}
			}
			c.mu.Unlock()
		}
	}
}
