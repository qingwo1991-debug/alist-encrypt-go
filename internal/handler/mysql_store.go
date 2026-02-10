package handler

import (
	"context"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

type MySQLStrategyStore struct {
	store *mysqlstore.Store
}

func NewMySQLStrategyStore(store *mysqlstore.Store) *MySQLStrategyStore {
	if store == nil {
		return nil
	}
	return &MySQLStrategyStore{store: store}
}

func (s *MySQLStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	record, ok, err := s.store.GetStrategy(context.Background(), provider)
	if err != nil || !ok {
		return nil, false
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

func (s *MySQLStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	if state == nil {
		return nil
	}
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

func (s *MySQLStrategyStore) List() map[string]*ProviderStrategyState {
	records, err := s.store.ListStrategies(context.Background())
	if err != nil {
		return map[string]*ProviderStrategyState{}
	}

	out := make(map[string]*ProviderStrategyState, len(records))
	for _, record := range records {
		provider := record.ProviderHost + "::" + record.OriginalPath
		failures := make(map[proxy.StreamStrategy]int)
		for key, value := range mysqlstore.DecodeFailures(record.FailuresJSON) {
			failures[proxy.StreamStrategy(key)] = value
		}
		out[provider] = &ProviderStrategyState{
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
	return out
}

type MySQLFileMetaStore struct {
	store *mysqlstore.Store
}

func NewMySQLFileMetaStore(store *mysqlstore.Store) *MySQLFileMetaStore {
	if store == nil {
		return nil
	}
	return &MySQLFileMetaStore{store: store}
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
	return s.store.UpsertFileMeta(ctx, record)
}

func (s *MySQLFileMetaStore) Cleanup(ctx context.Context, cutoff time.Time) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.CleanupFileMeta(ctx, cutoff)
}
