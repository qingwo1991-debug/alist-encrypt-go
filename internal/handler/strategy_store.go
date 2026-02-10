package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/proxy"
)

type strategyStoreFile struct {
	Version   int                               `json:"version"`
	Providers map[string]*ProviderStrategyState `json:"providers"`
}

type StrategyStore interface {
	Get(provider string) (*ProviderStrategyState, bool)
	Set(provider string, state *ProviderStrategyState) error
	List() map[string]*ProviderStrategyState
}

type JSONStrategyStore struct {
	mu    sync.RWMutex
	path  string
	state map[string]*ProviderStrategyState
}

func NewJSONStrategyStore(path string) (*JSONStrategyStore, error) {
	if path == "" {
		return nil, fmt.Errorf("strategy store path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create strategy store dir: %w", err)
	}

	store := &JSONStrategyStore{
		path:  path,
		state: make(map[string]*ProviderStrategyState),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *JSONStrategyStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read strategy store: %w", err)
	}

	var file strategyStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("decode strategy store: %w", err)
	}

	if file.Providers != nil {
		s.state = file.Providers
	}
	return nil
}

func (s *JSONStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.state[provider]
	if !ok {
		return nil, false
	}
	return cloneProviderState(state), true
}

func (s *JSONStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdate = time.Now()
	s.state[provider] = cloneProviderState(state)
	return s.saveLocked()
}

func (s *JSONStrategyStore) List() map[string]*ProviderStrategyState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]*ProviderStrategyState, len(s.state))
	for key, value := range s.state {
		out[key] = cloneProviderState(value)
	}
	return out
}

func (s *JSONStrategyStore) saveLocked() error {
	file := strategyStoreFile{
		Version:   1,
		Providers: s.state,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode strategy store: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write strategy store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("commit strategy store: %w", err)
	}
	return nil
}

// LoadStrategyStoreFile reads a JSON strategy store file into memory.
func LoadStrategyStoreFile(path string) (map[string]*ProviderStrategyState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var file strategyStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}

	if file.Providers == nil {
		return map[string]*ProviderStrategyState{}, nil
	}
	return file.Providers, nil
}

type MemoryStrategyStore struct {
	mu    sync.RWMutex
	state map[string]*ProviderStrategyState
}

func NewMemoryStrategyStore() *MemoryStrategyStore {
	return &MemoryStrategyStore{state: make(map[string]*ProviderStrategyState)}
}

func (s *MemoryStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.state[provider]
	if !ok {
		return nil, false
	}
	return cloneProviderState(state), true
}

func (s *MemoryStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdate = time.Now()
	s.state[provider] = cloneProviderState(state)
	return nil
}

func (s *MemoryStrategyStore) List() map[string]*ProviderStrategyState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]*ProviderStrategyState, len(s.state))
	for key, value := range s.state {
		out[key] = cloneProviderState(value)
	}
	return out
}

func cloneProviderState(state *ProviderStrategyState) *ProviderStrategyState {
	if state == nil {
		return nil
	}

	copyState := *state
	if state.Failures != nil {
		copyState.Failures = make(map[proxy.StreamStrategy]int, len(state.Failures))
		for key, value := range state.Failures {
			copyState.Failures[key] = value
		}
	}
	return &copyState
}
