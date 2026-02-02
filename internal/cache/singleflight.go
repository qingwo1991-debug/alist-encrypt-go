package cache

import (
	"sync"
)

// call represents an in-flight or completed request
type call struct {
	wg    sync.WaitGroup
	val   interface{}
	err   error
	dups  int
}

// SingleFlight provides deduplication of concurrent requests
// Prevents cache stampede when multiple goroutines request the same key
type SingleFlight struct {
	mu sync.Mutex
	m  map[string]*call
}

// NewSingleFlight creates a new SingleFlight instance
func NewSingleFlight() *SingleFlight {
	return &SingleFlight{
		m: make(map[string]*call),
	}
}

// Do executes the function only once for concurrent calls with the same key
// Returns the result and whether this call was shared with others
func (g *SingleFlight) Do(key string, fn func() (interface{}, error)) (interface{}, error, bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = make(map[string]*call)
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err, true
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()

	return c.val, c.err, c.dups > 0
}

// Forget removes a key from the in-flight map (for invalidation)
func (g *SingleFlight) Forget(key string) {
	g.mu.Lock()
	delete(g.m, key)
	g.mu.Unlock()
}
