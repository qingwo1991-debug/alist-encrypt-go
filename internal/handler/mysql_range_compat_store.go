package handler

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
	"golang.org/x/sync/singleflight"
)

type mysqlRangeCompatPersistence interface {
	GetRangeCompat(context.Context, string, string) (*mysqlstore.RangeCompatRecord, bool, error)
	UpsertRangeCompat(context.Context, mysqlstore.RangeCompatRecord) error
	CountRangeCompatActive(context.Context) (int64, error)
}

type mysqlRangeCompatCacheEntry struct {
	state      proxy.RangeCompatState
	found      bool
	persisted  bool
	generation uint64
	cachedAt   time.Time
	expiresAt  time.Time
}

type mysqlRangeCompatLoadResult struct {
	state proxy.RangeCompatState
	found bool
}

type MySQLRangeCompatStore struct {
	store mysqlRangeCompatPersistence

	mu             sync.RWMutex
	cache          map[string]mysqlRangeCompatCacheEntry
	loads          singleflight.Group
	generations    map[string]uint64
	activeLoads    map[string]int
	nextGeneration uint64

	queryTimeout time.Duration
	positiveTTL  time.Duration
	negativeTTL  time.Duration
	failureTTL   time.Duration
	maxEntries   int
	now          func() time.Time
}

func NewMySQLRangeCompatStore(store *mysqlstore.Store) *MySQLRangeCompatStore {
	if store == nil {
		return nil
	}
	return newMySQLRangeCompatStore(store)
}

func newMySQLRangeCompatStore(store mysqlRangeCompatPersistence) *MySQLRangeCompatStore {
	if store == nil {
		return nil
	}
	return &MySQLRangeCompatStore{
		store:        store,
		cache:        make(map[string]mysqlRangeCompatCacheEntry),
		generations:  make(map[string]uint64),
		activeLoads:  make(map[string]int),
		queryTimeout: mysqlHotReadTimeout,
		positiveTTL:  mysqlHotPositiveCacheTTL,
		negativeTTL:  mysqlHotNegativeCacheTTL,
		failureTTL:   mysqlHotFailureCacheTTL,
		maxEntries:   mysqlHotCacheMaxEntries,
		now:          time.Now,
	}
}

func (s *MySQLRangeCompatStore) Get(key string) (proxy.RangeCompatState, bool, error) {
	if s == nil || s.store == nil {
		return proxy.RangeCompatState{}, false, nil
	}
	providerHost, storageKey := splitRangeCompatKey(key)
	if providerHost == "" || storageKey == "" {
		return proxy.RangeCompatState{}, false, nil
	}
	key = providerHost + "::" + storageKey
	if state, found, _, hit := s.getCached(key); hit {
		return state, found, nil
	}

	loaded, err, _ := s.loads.Do(key, func() (interface{}, error) {
		generation := s.beginLoad(key)
		defer s.finishLoad(key)
		if state, found, _, hit := s.getCached(key); hit {
			return mysqlRangeCompatLoadResult{state: state, found: found}, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.queryTimeout)
		defer cancel()
		record, found, err := s.store.GetRangeCompat(ctx, providerHost, storageKey)
		if err != nil {
			if state, cachedFound, existed := s.putLoadedCached(key, proxy.RangeCompatState{}, false, s.failureTTL, generation); existed {
				return mysqlRangeCompatLoadResult{state: state, found: cachedFound}, nil
			}
			return mysqlRangeCompatLoadResult{}, err
		}
		if !found {
			state, cachedFound, _ := s.putLoadedCached(key, proxy.RangeCompatState{}, false, s.negativeTTL, generation)
			return mysqlRangeCompatLoadResult{state: state, found: cachedFound}, nil
		}

		state := rangeCompatStateFromRecord(record)
		state, cachedFound, _ := s.putLoadedCached(key, state, true, s.positiveTTL, generation)
		return mysqlRangeCompatLoadResult{state: state, found: cachedFound}, nil
	})
	if err != nil {
		return proxy.RangeCompatState{}, false, err
	}
	result := loaded.(mysqlRangeCompatLoadResult)
	return result.state, result.found, nil
}

func rangeCompatStateFromRecord(record *mysqlstore.RangeCompatRecord) proxy.RangeCompatState {
	if record == nil {
		return proxy.RangeCompatState{}
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
	}
}

func (s *MySQLRangeCompatStore) Upsert(key string, state proxy.RangeCompatState) error {
	if s == nil || s.store == nil {
		return nil
	}
	providerHost, storageKey := splitRangeCompatKey(key)
	if providerHost == "" || storageKey == "" {
		return nil
	}
	key = providerHost + "::" + storageKey

	if last, found, persisted, hit := s.getCached(key); hit && found && persisted && rangeCompatStateEqual(last, state) {
		s.refreshCached(key)
		return nil
	}

	now := s.now()
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = now
	}
	state.LastAccessed = now
	// Keep playback reads consistent immediately; MySQL persistence is buffered.
	generation := s.putWriteCached(key, state)

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
		LastAccessed:         now,
		UpdatedAt:            state.UpdatedAt,
		Active:               true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.queryTimeout)
	defer cancel()
	err := s.store.UpsertRangeCompat(ctx, record)
	if err == nil {
		s.markPersisted(key, generation)
	}
	return err
}

func (s *MySQLRangeCompatStore) getCached(key string) (proxy.RangeCompatState, bool, bool, bool) {
	now := s.now()
	s.mu.RLock()
	entry, ok := s.cache[key]
	s.mu.RUnlock()
	if !ok {
		return proxy.RangeCompatState{}, false, false, false
	}
	if !now.Before(entry.expiresAt) {
		s.mu.Lock()
		if current, exists := s.cache[key]; exists && !now.Before(current.expiresAt) {
			s.deleteCacheEntryLocked(key)
		}
		s.mu.Unlock()
		return proxy.RangeCompatState{}, false, false, false
	}
	return entry.state, entry.found, entry.persisted, true
}

func (s *MySQLRangeCompatStore) putWriteCached(key string, state proxy.RangeCompatState) uint64 {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextGeneration++
	generation := s.nextGeneration
	s.generations[key] = generation
	if _, exists := s.cache[key]; !exists && s.maxEntries > 0 && len(s.cache) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.cache[key] = mysqlRangeCompatCacheEntry{
		state:      state,
		found:      true,
		persisted:  false,
		generation: generation,
		cachedAt:   now,
		expiresAt:  now.Add(s.positiveTTL),
	}
	return generation
}

// putLoadedCached never lets an in-flight DB read overwrite a newer Upsert.
func (s *MySQLRangeCompatStore) putLoadedCached(key string, state proxy.RangeCompatState, found bool, ttl time.Duration, expectedGeneration uint64) (proxy.RangeCompatState, bool, bool) {
	now := s.now()
	entry := mysqlRangeCompatCacheEntry{
		state:      state,
		found:      found,
		persisted:  true,
		generation: expectedGeneration,
		cachedAt:   now,
		expiresAt:  now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.cache[key]; exists && now.Before(current.expiresAt) {
		return current.state, current.found, true
	}
	if s.generations[key] != expectedGeneration {
		return proxy.RangeCompatState{}, false, true
	}
	if _, exists := s.cache[key]; !exists && s.maxEntries > 0 && len(s.cache) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.cache[key] = entry
	return entry.state, entry.found, false
}

func (s *MySQLRangeCompatStore) beginLoad(key string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeLoads[key]++
	return s.generations[key]
}

func (s *MySQLRangeCompatStore) finishLoad(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeLoads[key] <= 1 {
		delete(s.activeLoads, key)
		if _, cached := s.cache[key]; !cached {
			delete(s.generations, key)
		}
		return
	}
	s.activeLoads[key]--
}

func (s *MySQLRangeCompatStore) markPersisted(key string, generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok || entry.generation != generation || s.generations[key] != generation {
		return
	}
	entry.persisted = true
	s.cache[key] = entry
}

func (s *MySQLRangeCompatStore) refreshCached(key string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok || !now.Before(entry.expiresAt) {
		return
	}
	entry.cachedAt = now
	entry.expiresAt = now.Add(s.positiveTTL)
	s.cache[key] = entry
}

func (s *MySQLRangeCompatStore) deleteCacheEntryLocked(key string) {
	delete(s.cache, key)
	if s.activeLoads[key] == 0 {
		delete(s.generations, key)
	}
}

func (s *MySQLRangeCompatStore) evictOldestLocked() {
	var oldestKey string
	var oldestAt time.Time
	for key, entry := range s.cache {
		if oldestKey == "" || entry.cachedAt.Before(oldestAt) {
			oldestKey = key
			oldestAt = entry.cachedAt
		}
	}
	if oldestKey != "" {
		s.deleteCacheEntryLocked(oldestKey)
	}
}

func (s *MySQLRangeCompatStore) Stats() map[string]interface{} {
	if s == nil || s.store == nil {
		return map[string]interface{}{"mode": "mysql", "entries": 0}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.queryTimeout)
	defer cancel()
	entries, err := s.store.CountRangeCompatActive(ctx)
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
	idx := strings.Index(key, "::/")
	if idx < 0 {
		return "", ""
	}
	return strings.TrimSpace(key[:idx]), strings.TrimSpace(key[idx+2:])
}
