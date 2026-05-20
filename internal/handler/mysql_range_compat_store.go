package handler

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type MySQLRangeCompatStore struct {
	store      *mysqlstore.Store
	mu         sync.Mutex
	lastStates map[string]proxy.RangeCompatState
}

func NewMySQLRangeCompatStore(store *mysqlstore.Store) *MySQLRangeCompatStore {
	if store == nil {
		return nil
	}
	return &MySQLRangeCompatStore{store: store, lastStates: make(map[string]proxy.RangeCompatState)}
}

func (s *MySQLRangeCompatStore) Get(key string) (proxy.RangeCompatState, bool, error) {
	providerHost, storageKey := splitRangeCompatKey(key)
	if providerHost == "" || storageKey == "" {
		return proxy.RangeCompatState{}, false, nil
	}

	record, ok, err := s.store.GetRangeCompat(context.Background(), providerHost, storageKey)
	if err != nil || !ok {
		return proxy.RangeCompatState{}, false, err
	}

	return proxy.RangeCompatState{
		Incompatible:         record.Incompatible,
		ConsecutiveFailures:  record.ConsecutiveFailures,
		ConsecutiveSuccesses: record.ConsecutiveSuccesses,
		NextProbeAt:          record.NextProbeAt,
		LastReason:           record.LastReason,
		LastCheckedAt:        record.LastCheckedAt,
		LastAccessed:         record.LastAccessed,
		UpdatedAt:            record.UpdatedAt,
	}, true, nil
}

func (s *MySQLRangeCompatStore) Upsert(key string, state proxy.RangeCompatState) error {
	providerHost, storageKey := splitRangeCompatKey(key)
	if providerHost == "" || storageKey == "" {
		return nil
	}

	s.mu.Lock()
	if last, ok := s.lastStates[key]; ok && rangeCompatStateEqual(last, state) {
		s.mu.Unlock()
		return nil
	}
	s.lastStates[key] = state
	s.mu.Unlock()

	record := mysqlstore.RangeCompatRecord{
		KeyHash:              mysqlstore.RangeCompatKeyHash(providerHost, storageKey),
		ProviderHost:         providerHost,
		StorageKey:           storageKey,
		Incompatible:         state.Incompatible,
		ConsecutiveFailures:  state.ConsecutiveFailures,
		ConsecutiveSuccesses: state.ConsecutiveSuccesses,
		NextProbeAt:          state.NextProbeAt,
		LastReason:           state.LastReason,
		LastCheckedAt:        state.LastCheckedAt,
		LastAccessed:         time.Now(),
		UpdatedAt:            time.Now(),
		Active:               true,
	}
	return s.store.UpsertRangeCompat(context.Background(), record)
}

func (s *MySQLRangeCompatStore) Stats() map[string]interface{} {
	entries, err := s.store.CountRangeCompatActive(context.Background())
	if err != nil {
		entries = -1
	}
	return map[string]interface{}{
		"mode":    "mysql",
		"entries": entries,
	}
}

func rangeCompatStateEqual(a, b proxy.RangeCompatState) bool {
	return a.Incompatible == b.Incompatible &&
		a.ConsecutiveFailures == b.ConsecutiveFailures &&
		a.ConsecutiveSuccesses == b.ConsecutiveSuccesses &&
		a.NextProbeAt.Equal(b.NextProbeAt) &&
		a.LastReason == b.LastReason &&
		a.LastCheckedAt.Equal(b.LastCheckedAt)
}

func splitRangeCompatKey(key string) (string, string) {
	parts := strings.SplitN(key, "::", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}
