package cache

import (
	"sync"
	"time"
)

// CacheItem represents a cached item with expiration
type CacheItem struct {
	Value      interface{}
	Expiration int64
}

// IsExpired checks if the item has expired
func (item CacheItem) IsExpired() bool {
	if item.Expiration == 0 {
		return false
	}
	return time.Now().UnixNano() > item.Expiration
}

// Cache is a simple in-memory cache with TTL support
type Cache struct {
	items       map[string]CacheItem
	mu          sync.RWMutex
	defaultTTL  time.Duration
	maxSize     int
	singleFlight *SingleFlight
}

// NewCache creates a new cache instance
func NewCache(defaultTTL time.Duration, maxSize int) *Cache {
	c := &Cache{
		items:       make(map[string]CacheItem),
		defaultTTL:  defaultTTL,
		maxSize:     maxSize,
		singleFlight: NewSingleFlight(),
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// Get retrieves an item from the cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, found := c.items[key]
	c.mu.RUnlock()

	if !found {
		return nil, false
	}

	if item.IsExpired() {
		c.Delete(key)
		return nil, false
	}

	return item.Value, true
}

// Set stores an item in the cache with default TTL
func (c *Cache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, c.defaultTTL)
}

// SetWithTTL stores an item with custom TTL
func (c *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	var expiration int64
	if ttl > 0 {
		expiration = time.Now().Add(ttl).UnixNano()
	}

	c.mu.Lock()
	// Evict if at capacity
	if len(c.items) >= c.maxSize {
		c.evictOne()
	}
	c.items[key] = CacheItem{
		Value:      value,
		Expiration: expiration,
	}
	c.mu.Unlock()
}

// Delete removes an item from the cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
	c.singleFlight.Forget(key)
}

// GetOrLoad gets from cache or loads using the provided function
// Uses singleflight to prevent cache stampede
func (c *Cache) GetOrLoad(key string, loader func() (interface{}, error)) (interface{}, error) {
	// Check cache first
	if val, found := c.Get(key); found {
		return val, nil
	}

	// Use singleflight to deduplicate concurrent loads
	val, err, _ := c.singleFlight.Do(key, func() (interface{}, error) {
		// Double-check cache after acquiring the lock
		if val, found := c.Get(key); found {
			return val, nil
		}

		// Load from source
		result, err := loader()
		if err != nil {
			return nil, err
		}

		// Store in cache
		c.Set(key, result)
		return result, nil
	})

	return val, err
}

// evictOne removes one expired or oldest item
func (c *Cache) evictOne() {
	var oldestKey string
	var oldestTime int64 = time.Now().UnixNano()

	for key, item := range c.items {
		if item.IsExpired() {
			delete(c.items, key)
			return
		}
		if item.Expiration < oldestTime && item.Expiration > 0 {
			oldestTime = item.Expiration
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}

// cleanup periodically removes expired items
func (c *Cache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		c.mu.Lock()
		for key, item := range c.items {
			if item.IsExpired() {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

// Size returns the number of items in the cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.items)
}

// Clear removes all items from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	c.items = make(map[string]CacheItem)
	c.mu.Unlock()
}
