package handler

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type MySQLStrategyStore struct {
	store      *mysqlstore.Store
	mu         sync.RWMutex
	lastStates map[string]*ProviderStrategyState
}

func NewMySQLStrategyStore(store *mysqlstore.Store) *MySQLStrategyStore {
	if store == nil {
		return nil
	}
	return &MySQLStrategyStore{store: store, lastStates: make(map[string]*ProviderStrategyState)}
}

func (s *MySQLStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	provider = normalizeStrategyProviderKey(provider)
	record, ok, err := s.store.GetStrategy(context.Background(), provider)
	if err != nil || !ok {
		return s.getLegacyAggregated(provider)
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
	}, true
}

func (s *MySQLStrategyStore) getLegacyAggregated(provider string) (*ProviderStrategyState, bool) {
	records, err := s.store.ListStrategies(context.Background())
	if err != nil || len(records) == 0 {
		return nil, false
	}
	var best *mysqlstore.StrategyRecord
	for i := range records {
		record := records[i]
		if normalizeStrategyProviderKey(record.ProviderHost) != provider {
			continue
		}
		if best == nil || record.UpdatedAt.After(best.UpdatedAt) {
			copyRecord := record
			best = &copyRecord
		}
	}
	if best == nil {
		return nil, false
	}
	failures := make(map[proxy.StreamStrategy]int)
	for key, value := range mysqlstore.DecodeFailures(best.FailuresJSON) {
		failures[proxy.StreamStrategy(key)] = value
	}
	return &ProviderStrategyState{
		Provider:       provider,
		Preferred:      proxy.StreamStrategy(best.Preferred),
		Failures:       failures,
		SuccessStreak:  best.SuccessStreak,
		CooldownUntil:  best.CooldownUntil,
		LastDowngrade:  best.LastDowngrade,
		LastUpdate:     best.UpdatedAt,
		LastFailure:    best.LastFailure,
		LastStrategy:   proxy.StreamStrategy(best.LastStrategy),
		TotalFailures:  best.TotalFailures,
		TotalSuccesses: best.TotalSuccesses,
	}, true
}

func (s *MySQLStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	if state == nil {
		return nil
	}
	provider = normalizeStrategyProviderKey(provider)

	s.mu.Lock()
	if last, ok := s.lastStates[provider]; ok && strategyStateEqual(last, state) {
		s.mu.Unlock()
		return nil
	}
	s.lastStates[provider] = cloneStrategyState(state)
	s.mu.Unlock()

	providerHost, originalPath := mysqlstore.SplitProviderKey(provider)

	stringFailures := make(map[string]int)
	for key, value := range state.Failures {
		stringFailures[string(key)] = value
	}

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
		UpdatedAt:      time.Now(),
		LastAccessed:   time.Now(),
	}
	return s.store.UpsertStrategy(context.Background(), record)
}

func strategyStateEqual(a, b *ProviderStrategyState) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Preferred != b.Preferred || a.SuccessStreak != b.SuccessStreak || a.CooldownUntil != b.CooldownUntil || a.LastDowngrade != b.LastDowngrade || a.LastFailure != b.LastFailure || a.LastStrategy != b.LastStrategy || a.TotalFailures != b.TotalFailures || a.TotalSuccesses != b.TotalSuccesses {
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
	failures := make(map[proxy.StreamStrategy]int, len(src.Failures))
	for key, value := range src.Failures {
		failures[key] = value
	}
	return &ProviderStrategyState{
		Provider:       src.Provider,
		Preferred:      src.Preferred,
		Failures:       failures,
		SuccessStreak:  src.SuccessStreak,
		CooldownUntil:  src.CooldownUntil,
		LastDowngrade:  src.LastDowngrade,
		LastUpdate:     src.LastUpdate,
		LastFailure:    src.LastFailure,
		LastStrategy:   src.LastStrategy,
		TotalFailures:  src.TotalFailures,
		TotalSuccesses: src.TotalSuccesses,
	}
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ProviderStrategyState)
	for k, v := range s.lastStates {
		out[k] = cloneProviderState(v)
	}
	return out
}
