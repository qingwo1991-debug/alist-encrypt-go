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
	items map[string]CacheItem
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewCache creates a new cache with default TTL
func NewCache(ttl time.Duration) *Cache {
	c := &Cache{
		items: make(map[string]CacheItem),
		ttl:   ttl,
	}
	go c.cleanup()
	return c
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

	var expiration int64
	if ttl > 0 {
		expiration = time.Now().Add(ttl).UnixNano()
	}
	c.items[key] = CacheItem{
		Value:      value,
		Expiration: expiration,
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
	for range ticker.C {
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
