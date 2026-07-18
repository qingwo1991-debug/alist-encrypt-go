package handler

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
	"golang.org/x/sync/singleflight"
)

const (
	mysqlHotReadTimeout      = 200 * time.Millisecond
	mysqlHotPositiveCacheTTL = 30 * time.Minute
	mysqlHotNegativeCacheTTL = 2 * time.Second
	mysqlHotFailureCacheTTL  = time.Second
	mysqlHotCacheMaxEntries  = 2048
)

type mysqlStrategyPersistence interface {
	GetStrategy(context.Context, string) (*mysqlstore.StrategyRecord, bool, error)
	GetLatestStrategyByProvider(context.Context, string) (*mysqlstore.StrategyRecord, bool, error)
	UpsertStrategy(context.Context, mysqlstore.StrategyRecord) error
}

type mysqlStrategyCacheEntry struct {
	state      *ProviderStrategyState
	found      bool
	persisted  bool
	learned    bool
	generation uint64
	cachedAt   time.Time
	expiresAt  time.Time
}

type mysqlStrategyLoadResult struct {
	state *ProviderStrategyState
	found bool
}

type MySQLStrategyStore struct {
	store mysqlStrategyPersistence

	mu             sync.RWMutex
	cache          map[string]mysqlStrategyCacheEntry
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

func NewMySQLStrategyStore(store *mysqlstore.Store) *MySQLStrategyStore {
	if store == nil {
		return nil
	}
	return newMySQLStrategyStore(store)
}

func newMySQLStrategyStore(store mysqlStrategyPersistence) *MySQLStrategyStore {
	if store == nil {
		return nil
	}
	return &MySQLStrategyStore{
		store:        store,
		cache:        make(map[string]mysqlStrategyCacheEntry),
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

func (s *MySQLStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	if s == nil || s.store == nil {
		return nil, false
	}
	provider = normalizeStrategyProviderKey(provider)
	if state, found, _, hit := s.getCached(provider); hit {
		return state, found
	}

	loaded, err, _ := s.loads.Do(provider, func() (interface{}, error) {
		generation := s.beginLoad(provider)
		defer s.finishLoad(provider)
		if state, found, _, hit := s.getCached(provider); hit {
			return mysqlStrategyLoadResult{state: state, found: found}, nil
		}

		ctx, cancel := context.WithTimeout(context.Background(), s.queryTimeout)
		defer cancel()

		record, found, err := s.store.GetStrategy(ctx, provider)
		if err != nil {
			state := s.putFailureFallback(provider, generation)
			return mysqlStrategyLoadResult{state: state, found: true}, nil
		}
		if !found {
			// Older releases persisted one record per path. Query only this
			// provider's latest legacy row instead of listing the whole table.
			record, found, err = s.store.GetLatestStrategyByProvider(ctx, provider)
			if err != nil {
				state := s.putFailureFallback(provider, generation)
				return mysqlStrategyLoadResult{state: state, found: true}, nil
			}
		}
		if !found {
			state, cachedFound, _ := s.putLoadedCached(provider, nil, false, s.negativeTTL, generation)
			return mysqlStrategyLoadResult{state: state, found: cachedFound}, nil
		}

		state := strategyStateFromRecord(provider, record)
		state, cachedFound, _ := s.putLoadedCached(provider, state, true, s.positiveTTL, generation)
		return mysqlStrategyLoadResult{state: state, found: cachedFound}, nil
	})
	if err != nil {
		return nil, false
	}
	result := loaded.(mysqlStrategyLoadResult)
	return cloneStrategyState(result.state), result.found
}

func strategyStateFromRecord(provider string, record *mysqlstore.StrategyRecord) *ProviderStrategyState {
	if record == nil {
		return nil
	}
	failures := make(map[proxy.StreamStrategy]int)
	for key, value := range mysqlstore.DecodeFailures(record.FailuresJSON) {
		failures[proxy.StreamStrategy(key)] = value
	}
	return &ProviderStrategyState{
		Provider:       provider,
		Preferred:      proxy.StreamStrategy(record.Preferred),
		Failures:       failures,
		SuccessStreak:  record.SuccessStreak,
		CooldownUntil:  record.CooldownUntil,
		LastDowngrade:  record.LastDowngrade,
		LastUpdate:     record.UpdatedAt,
		LastFailure:    record.LastFailure,
		LastStrategy:   proxy.StreamStrategy(record.LastStrategy),
		TotalFailures:  record.TotalFailures,
		TotalSuccesses: record.TotalSuccesses,
	}
}

func (s *MySQLStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	if s == nil || s.store == nil || state == nil {
		return nil
	}
	provider = normalizeStrategyProviderKey(provider)

	if last, found, persisted, hit := s.getCached(provider); hit && found && persisted && strategyStateEqual(last, state) {
		s.refreshCached(provider)
		return nil
	}

	cached := cloneStrategyState(state)
	cached.Provider = provider
	cached.LastUpdate = s.now()
	// Publish the write synchronously. Reads never wait for MySQL's async
	// persistence buffer and remain consistent with a successful caller write.
	generation := s.putWriteCached(provider, cached)

	providerHost, originalPath := mysqlstore.SplitProviderKey(provider)

	stringFailures := make(map[string]int)
	for key, value := range state.Failures {
		stringFailures[string(key)] = value
	}

	now := s.now()
	record := mysqlstore.StrategyRecord{
		KeyHash:        mysqlstore.KeyHash(providerHost, originalPath),
		ProviderHost:   providerHost,
		OriginalPath:   originalPath,
		Preferred:      string(state.Preferred),
		FailuresJSON:   mysqlstore.EncodeFailures(stringFailures),
		SuccessStreak:  state.SuccessStreak,
		TotalFailures:  state.TotalFailures,
		TotalSuccesses: state.TotalSuccesses,
		CooldownUntil:  state.CooldownUntil,
		LastDowngrade:  state.LastDowngrade,
		LastFailure:    state.LastFailure,
		LastStrategy:   string(state.LastStrategy),
		UpdatedAt:      now,
		LastAccessed:   now,
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.queryTimeout)
	defer cancel()
	err := s.store.UpsertStrategy(ctx, record)
	if err == nil {
		s.markPersisted(provider, generation)
	}
	return err
}

func (s *MySQLStrategyStore) getCached(provider string) (*ProviderStrategyState, bool, bool, bool) {
	now := s.now()
	s.mu.RLock()
	entry, ok := s.cache[provider]
	s.mu.RUnlock()
	if !ok {
		return nil, false, false, false
	}
	if !now.Before(entry.expiresAt) {
		// Keep the expired entry available as stale-if-error data. A successful
		// load, authoritative miss, or bounded-cache eviction will replace it.
		return nil, false, false, false
	}
	return cloneStrategyState(entry.state), entry.found, entry.persisted, true
}

func (s *MySQLStrategyStore) putWriteCached(provider string, state *ProviderStrategyState) uint64 {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextGeneration++
	generation := s.nextGeneration
	s.generations[provider] = generation
	if _, exists := s.cache[provider]; !exists && s.maxEntries > 0 && len(s.cache) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.cache[provider] = mysqlStrategyCacheEntry{
		state:      cloneStrategyState(state),
		found:      true,
		persisted:  false,
		learned:    true,
		generation: generation,
		cachedAt:   now,
		expiresAt:  now.Add(s.positiveTTL),
	}
	return generation
}

// putLoadedCached commits a DB load only if no Set happened after the load
// started. This prevents a slow read from replacing a newer write-through value.
func (s *MySQLStrategyStore) putLoadedCached(provider string, state *ProviderStrategyState, found bool, ttl time.Duration, expectedGeneration uint64) (*ProviderStrategyState, bool, bool) {
	now := s.now()
	entry := mysqlStrategyCacheEntry{
		state:      cloneStrategyState(state),
		found:      found,
		persisted:  true,
		learned:    found,
		generation: expectedGeneration,
		cachedAt:   now,
		expiresAt:  now.Add(ttl),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.cache[provider]; exists && now.Before(current.expiresAt) {
		return cloneStrategyState(current.state), current.found, true
	}
	if s.generations[provider] != expectedGeneration {
		return nil, false, true
	}
	if _, exists := s.cache[provider]; !exists && s.maxEntries > 0 && len(s.cache) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.cache[provider] = entry
	return cloneStrategyState(entry.state), entry.found, false
}

// putFailureFallback turns a transient storage failure into a short-lived,
// non-authoritative value. StrategySelector can safely select its normal
// default without treating the failure as a real miss and persisting a blank
// strategy. If a learned value just expired, it is preferred as stale data.
func (s *MySQLStrategyStore) putFailureFallback(provider string, expectedGeneration uint64) *ProviderStrategyState {
	now := s.now()
	placeholder := &ProviderStrategyState{
		Provider: provider,
		Failures: make(map[proxy.StreamStrategy]int),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if current, exists := s.cache[provider]; exists && now.Before(current.expiresAt) {
		return cloneStrategyState(current.state)
	}
	if s.generations[provider] != expectedGeneration {
		if current, exists := s.cache[provider]; exists && current.found {
			return cloneStrategyState(current.state)
		}
		return placeholder
	}

	state := placeholder
	persisted := false
	learned := false
	if current, exists := s.cache[provider]; exists && current.found && current.learned {
		state = cloneStrategyState(current.state)
		persisted = current.persisted
		learned = true
	}
	if _, exists := s.cache[provider]; !exists && s.maxEntries > 0 && len(s.cache) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.cache[provider] = mysqlStrategyCacheEntry{
		state:      cloneStrategyState(state),
		found:      true,
		persisted:  persisted,
		learned:    learned,
		generation: expectedGeneration,
		cachedAt:   now,
		expiresAt:  now.Add(s.failureTTL),
	}
	return cloneStrategyState(state)
}

func (s *MySQLStrategyStore) beginLoad(provider string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeLoads[provider]++
	return s.generations[provider]
}

func (s *MySQLStrategyStore) finishLoad(provider string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activeLoads[provider] <= 1 {
		delete(s.activeLoads, provider)
		if _, cached := s.cache[provider]; !cached {
			delete(s.generations, provider)
		}
		return
	}
	s.activeLoads[provider]--
}

func (s *MySQLStrategyStore) markPersisted(provider string, generation uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[provider]
	if !ok || entry.generation != generation || s.generations[provider] != generation {
		return
	}
	entry.persisted = true
	s.cache[provider] = entry
}

func (s *MySQLStrategyStore) refreshCached(provider string) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[provider]
	if !ok || !now.Before(entry.expiresAt) {
		return
	}
	entry.cachedAt = now
	entry.expiresAt = now.Add(s.positiveTTL)
	s.cache[provider] = entry
}

func (s *MySQLStrategyStore) deleteCacheEntryLocked(provider string) {
	delete(s.cache, provider)
	if s.activeLoads[provider] == 0 {
		delete(s.generations, provider)
	}
}

func (s *MySQLStrategyStore) evictOldestLocked() {
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

func strategyStateEqual(a, b *ProviderStrategyState) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Preferred != b.Preferred || a.CapabilityFailCount != b.CapabilityFailCount || !a.LastValidatedAt.Equal(b.LastValidatedAt) || a.SuccessStreak != b.SuccessStreak || a.CooldownUntil != b.CooldownUntil || a.LastDowngrade != b.LastDowngrade || a.LastFailure != b.LastFailure || a.LastStrategy != b.LastStrategy || a.TotalFailures != b.TotalFailures || a.TotalSuccesses != b.TotalSuccesses {
		return false
	}
	if len(a.Failures) != len(b.Failures) {
		return false
	}
	for key, value := range a.Failures {
		if b.Failures[key] != value {
			return false
		}
	}
	return true
}

func cloneStrategyState(src *ProviderStrategyState) *ProviderStrategyState {
	if src == nil {
		return nil
	}
	copyState := *src
	failures := make(map[proxy.StreamStrategy]int, len(src.Failures))
	for key, value := range src.Failures {
		failures[key] = value
	}
	copyState.Failures = failures
	return &copyState
}

type MySQLFileMetaStore struct {
	store     *mysqlstore.Store
	mu        sync.Mutex
	lastMetas map[string]FileMeta
}

func NewMySQLFileMetaStore(store *mysqlstore.Store) *MySQLFileMetaStore {
	if store == nil {
		return nil
	}
	return &MySQLFileMetaStore{store: store, lastMetas: make(map[string]FileMeta)}
}

func (s *MySQLFileMetaStore) Get(ctx context.Context, providerKey, originalPath string) (FileMeta, bool, error) {
	record, ok, err := s.store.GetFileMeta(ctx, providerKey, originalPath)
	if err != nil || !ok {
		return FileMeta{}, false, err
	}

	return FileMeta{
		ProviderKey:  providerKey,
		OriginalPath: record.OriginalPath,
		Size:         record.Size,
		ETag:         record.ETag,
		ContentType:  record.ContentType,
		StatusCode:   record.StatusCode,
		UpdatedAt:    record.UpdatedAt,
		LastAccessed: record.LastAccessed,
	}, true, nil
}

func preserveV2FileMetaRecord(existing *mysqlstore.FileMetaRecord, incoming *mysqlstore.FileMetaRecord) {
	if existing == nil || incoming == nil || existing.ContentVersion != encryption.ContentVersionV2 {
		return
	}
	if incoming.ContentVersion <= 0 {
		incoming.ContentVersion = existing.ContentVersion
	}
	if incoming.CiphertextSize <= 0 {
		incoming.CiphertextSize = existing.CiphertextSize
	}
	if incoming.HeaderLen <= 0 {
		incoming.HeaderLen = existing.HeaderLen
	}
	if len(incoming.NonceField) == 0 && len(existing.NonceField) > 0 {
		incoming.NonceField = append([]byte(nil), existing.NonceField...)
	}
	if incoming.Size == existing.CiphertextSize && existing.Size > 0 {
		incoming.Size = existing.Size
	}
	if incoming.EncryptedPath == "" {
		incoming.EncryptedPath = existing.EncryptedPath
	}
	if incoming.Name == "" {
		incoming.Name = existing.Name
	}
	if incoming.RawURL == "" {
		incoming.RawURL = existing.RawURL
		incoming.RawURLAuthScope = existing.RawURLAuthScope
	}
	if incoming.Sign == "" {
		incoming.Sign = existing.Sign
	}
	if incoming.UpstreamFetchedAt.IsZero() {
		incoming.UpstreamFetchedAt = existing.UpstreamFetchedAt
	}
}

func (s *MySQLFileMetaStore) Upsert(ctx context.Context, meta FileMeta) error {
	if meta.Size <= 0 {
		return nil
	}
	contentType := strings.ToLower(meta.ContentType)
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		return nil
	}
	if meta.StatusCode != 0 && meta.StatusCode != 200 && meta.StatusCode != 206 {
		return nil
	}

	key := meta.ProviderKey + "::" + meta.OriginalPath
	s.mu.Lock()
	if last, ok := s.lastMetas[key]; ok && fileMetaEqual(last, meta) {
		s.mu.Unlock()
		return nil
	}
	s.lastMetas[key] = meta
	s.mu.Unlock()

	providerHost, _ := mysqlstore.SplitProviderKey(meta.ProviderKey)
	record := mysqlstore.FileMetaRecord{
		KeyHash:      mysqlstore.KeyHash(providerHost, meta.OriginalPath),
		ProviderHost: providerHost,
		OriginalPath: meta.OriginalPath,
		Size:         meta.Size,
		ETag:         meta.ETag,
		ContentType:  meta.ContentType,
		StatusCode:   meta.StatusCode,
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
		Active:       true,
	}
	if existing, ok, err := s.store.GetFileMeta(ctx, meta.ProviderKey, meta.OriginalPath); err == nil && ok {
		preserveV2FileMetaRecord(existing, &record)
	}
	return s.store.UpsertFileMeta(ctx, record)
}

func fileMetaEqual(a, b FileMeta) bool {
	return a.Size == b.Size && a.ETag == b.ETag && a.ContentType == b.ContentType && a.StatusCode == b.StatusCode
}

func (s *MySQLFileMetaStore) Cleanup(ctx context.Context, cutoff time.Time) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.CleanupFileMeta(ctx, cutoff)
}

func (s *MySQLStrategyStore) List() map[string]*ProviderStrategyState {
	if s == nil {
		return map[string]*ProviderStrategyState{}
	}
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ProviderStrategyState)
	for key, entry := range s.cache {
		if entry.found && now.Before(entry.expiresAt) {
			out[key] = cloneStrategyState(entry.state)
		}
	}
	return out
}
