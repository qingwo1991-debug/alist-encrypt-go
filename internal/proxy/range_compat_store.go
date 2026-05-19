package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// fileRangeCompatStore persists range compatibility to a JSON file.
// Survives restarts so that range learning accumulates over time.
type fileRangeCompatStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]RangeCompatState
}

func NewFileRangeCompatStore(path string) (RangeCompatStore, error) {
	if path == "" {
		return NewMemoryRangeCompatStore(), nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}
	s := &fileRangeCompatStore{
		path:  path,
		items: make(map[string]RangeCompatState),
	}
	s.load()
	return s, nil
}

func (s *fileRangeCompatStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	json.Unmarshal(data, &s.items)
	// Purge entries older than 30 days
	cutoff := time.Now().Add(-30 * 24 * time.Hour)
	for k, v := range s.items {
		if v.LastAccessed.Before(cutoff) {
			delete(s.items, k)
		}
	}
}

func (s *fileRangeCompatStore) save() {
	data, err := json.Marshal(s.items)
	if err != nil {
		return
	}
	tmpPath := s.path + ".tmp"
	os.WriteFile(tmpPath, data, 0644)
	os.Rename(tmpPath, s.path)
}

func (s *fileRangeCompatStore) Get(key string) (RangeCompatState, bool, error) {
	if key == "" {
		return RangeCompatState{}, false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.items[key]
	return state, ok, nil
}

func (s *fileRangeCompatStore) Upsert(key string, state RangeCompatState) error {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now()
	}
	state.LastAccessed = time.Now()
	s.items[key] = state
	s.save()
	return nil
}

func (s *fileRangeCompatStore) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"entries": len(s.items),
		"mode":    "file",
		"path":    s.path,
	}
}
