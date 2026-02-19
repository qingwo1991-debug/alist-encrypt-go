package proxy

import (
	"sync"
	"time"
)

// RangeCompatState tracks learned upstream range compatibility state.
type RangeCompatState struct {
	Incompatible         bool
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	NextProbeAt          time.Time
	LastReason           string
	LastCheckedAt        time.Time
	LastAccessed         time.Time
	UpdatedAt            time.Time
}

// RangeCompatStore persists range compatibility learning state.
type RangeCompatStore interface {
	Get(key string) (RangeCompatState, bool, error)
	Upsert(key string, state RangeCompatState) error
}

type memoryRangeCompatStore struct {
	mu    sync.RWMutex
	items map[string]RangeCompatState
}

func NewMemoryRangeCompatStore() RangeCompatStore {
	return &memoryRangeCompatStore{
		items: make(map[string]RangeCompatState),
	}
}

func (s *memoryRangeCompatStore) Get(key string) (RangeCompatState, bool, error) {
	if key == "" {
		return RangeCompatState{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.items[key]
	return state, ok, nil
}

func (s *memoryRangeCompatStore) Upsert(key string, state RangeCompatState) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = now
	}
	state.LastAccessed = now
	s.items[key] = state
	return nil
}

func (s *memoryRangeCompatStore) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"entries": len(s.items),
		"mode":    "memory",
	}
}
