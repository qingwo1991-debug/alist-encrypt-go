package handler

import (
	"sync"
	"time"
)

// StrategyType represents the type of file size retrieval strategy
type StrategyType string

const (
	StrategyFileInfoCache StrategyType = "file_info_cache" // File info cache (fastest)
	StrategyFileSizeCache StrategyType = "file_size_cache" // File size cache (fast)
	StrategyHEADRequest   StrategyType = "head_request"    // HEAD request (slow)
	StrategyPROPFIND      StrategyType = "propfind"        // PROPFIND request (slowest)
)

// PathStrategy records the successful strategy for a directory path
type PathStrategy struct {
	Strategy     StrategyType
	SuccessCount int
	FailCount    int
	LastSuccess  time.Time
	LastUpdate   time.Time
	TTL          time.Duration
}

// StrategyCache provides path-level strategy learning and caching
// After 3 consecutive successes, the strategy is considered reliable
type StrategyCache struct {
	mu         sync.RWMutex
	strategies map[string]*PathStrategy // dirPath -> strategy
	maxEntries int
}

// NewStrategyCache creates a new strategy cache
func NewStrategyCache(maxEntries int) *StrategyCache {
	if maxEntries <= 0 {
		maxEntries = 1000 // Default: cache strategies for 1000 directories
	}
	return &StrategyCache{
		strategies: make(map[string]*PathStrategy),
		maxEntries: maxEntries,
	}
}

// GetStrategy retrieves the learned strategy for a directory path
// Returns the strategy only if it has succeeded at least 3 times consecutively
func (sc *StrategyCache) GetStrategy(dirPath string) (*PathStrategy, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	strategy, ok := sc.strategies[dirPath]
	if !ok {
		return nil, false
	}

	// Check if expired
	if time.Since(strategy.LastSuccess) > strategy.TTL {
		return nil, false
	}

	// Require at least 3 consecutive successes to consider reliable
	if strategy.SuccessCount < 3 {
		return nil, false
	}

	return strategy, true
}

// RecordSuccess records a successful file size retrieval using a specific strategy
func (sc *StrategyCache) RecordSuccess(dirPath string, strategyType StrategyType) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	strategy, exists := sc.strategies[dirPath]

	if !exists {
		// New path, create strategy record
		sc.strategies[dirPath] = &PathStrategy{
			Strategy:     strategyType,
			SuccessCount: 1,
			FailCount:    0,
			LastSuccess:  time.Now(),
			LastUpdate:   time.Now(),
			TTL:          1 * time.Hour, // Default 1 hour TTL
		}

		// Cleanup if exceeds max entries
		if len(sc.strategies) > sc.maxEntries {
			sc.evictOldest()
		}
		return
	}

	now := time.Now()

	if strategy.Strategy == strategyType {
		// Consecutive success with same strategy
		strategy.SuccessCount++
		strategy.FailCount = 0 // Reset fail count
		strategy.LastSuccess = now
		strategy.LastUpdate = now
	} else {
		// Strategy changed, reset counters
		strategy.Strategy = strategyType
		strategy.SuccessCount = 1
		strategy.FailCount = 0
		strategy.LastSuccess = now
		strategy.LastUpdate = now
	}
}

// RecordFailure records a failure for the current strategy
func (sc *StrategyCache) RecordFailure(dirPath string, strategyType StrategyType) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	strategy, exists := sc.strategies[dirPath]
	if !exists {
		return
	}

	if strategy.Strategy == strategyType {
		strategy.FailCount++
		strategy.LastUpdate = time.Now()

		// If failed 3 times consecutively, invalidate the strategy
		if strategy.FailCount >= 3 {
			delete(sc.strategies, dirPath)
		}
	}
}

// Invalidate removes the strategy for a directory path
func (sc *StrategyCache) Invalidate(dirPath string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	delete(sc.strategies, dirPath)
}

// evictOldest removes the oldest strategy entry (LRU)
func (sc *StrategyCache) evictOldest() {
	var oldestPath string
	var oldestTime time.Time

	for path, strategy := range sc.strategies {
		if oldestPath == "" || strategy.LastUpdate.Before(oldestTime) {
			oldestPath = path
			oldestTime = strategy.LastUpdate
		}
	}

	if oldestPath != "" {
		delete(sc.strategies, oldestPath)
	}
}

// Stats returns strategy cache statistics
func (sc *StrategyCache) Stats() map[string]interface{} {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	strategyCount := make(map[StrategyType]int)
	learnedCount := 0

	for _, strategy := range sc.strategies {
		strategyCount[strategy.Strategy]++
		if strategy.SuccessCount >= 3 {
			learnedCount++
		}
	}

	return map[string]interface{}{
		"total_paths":       len(sc.strategies),
		"learned_paths":     learnedCount,
		"learning_paths":    len(sc.strategies) - learnedCount,
		"strategy_breakdown": strategyCount,
		"capacity":          sc.maxEntries,
		"usage_percent":     float64(len(sc.strategies)) / float64(sc.maxEntries) * 100,
	}
}

// Clear removes all cached strategies
func (sc *StrategyCache) Clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.strategies = make(map[string]*PathStrategy)
}
