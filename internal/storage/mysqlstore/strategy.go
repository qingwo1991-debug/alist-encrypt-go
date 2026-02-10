package mysqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

func (s *Store) GetStrategy(ctx context.Context, providerKey string) (*StrategyRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	providerHost, originalPath := SplitProviderKey(providerKey)
	keyHash := KeyHash(providerHost, originalPath)

	query := "SELECT key_hash, provider_host, original_path, preferred_strategy, failures_json, success_streak, total_failures, total_successes, cooldown_until, last_downgrade, last_failure, last_strategy, updated_at, last_accessed, is_active FROM " + TableName("strategy") + " WHERE key_hash = ? AND is_active=1"
	row := s.db.QueryRowContext(ctx, query, keyHash)

	var record StrategyRecord
	var cooldownUntil sql.NullTime
	var lastDowngrade sql.NullTime
	var isActive int
	if err := row.Scan(
		&record.KeyHash,
		&record.ProviderHost,
		&record.OriginalPath,
		&record.Preferred,
		&record.FailuresJSON,
		&record.SuccessStreak,
		&record.TotalFailures,
		&record.TotalSuccesses,
		&cooldownUntil,
		&lastDowngrade,
		&record.LastFailure,
		&record.LastStrategy,
		&record.UpdatedAt,
		&record.LastAccessed,
		&isActive,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	if cooldownUntil.Valid {
		record.CooldownUntil = cooldownUntil.Time
	}
	if lastDowngrade.Valid {
		record.LastDowngrade = lastDowngrade.Time
	}
	return &record, true, nil
}

func (s *Store) UpsertStrategy(ctx context.Context, record StrategyRecord) error {
	if s == nil {
		return nil
	}
	if record.KeyHash == "" {
		record.KeyHash = KeyHash(record.ProviderHost, record.OriginalPath)
	}

	record.UpdatedAt = time.Now()
	record.LastAccessed = time.Now()
	s.strategyBuffer.upsert(record)
	return nil
}

func (s *Store) ListStrategies(ctx context.Context) ([]StrategyRecord, error) {
	if s == nil {
		return nil, nil
	}
	query := "SELECT key_hash, provider_host, original_path, preferred_strategy, failures_json, success_streak, total_failures, total_successes, cooldown_until, last_downgrade, last_failure, last_strategy, updated_at, last_accessed FROM " + TableName("strategy") + " WHERE is_active=1"
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []StrategyRecord
	for rows.Next() {
		var record StrategyRecord
		var cooldownUntil sql.NullTime
		var lastDowngrade sql.NullTime
		if err := rows.Scan(
			&record.KeyHash,
			&record.ProviderHost,
			&record.OriginalPath,
			&record.Preferred,
			&record.FailuresJSON,
			&record.SuccessStreak,
			&record.TotalFailures,
			&record.TotalSuccesses,
			&cooldownUntil,
			&lastDowngrade,
			&record.LastFailure,
			&record.LastStrategy,
			&record.UpdatedAt,
			&record.LastAccessed,
		); err != nil {
			return nil, err
		}
		if cooldownUntil.Valid {
			record.CooldownUntil = cooldownUntil.Time
		}
		if lastDowngrade.Valid {
			record.LastDowngrade = lastDowngrade.Time
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func EncodeFailures(failures map[string]int) string {
	if failures == nil {
		return ""
	}
	data, _ := json.Marshal(failures)
	return string(data)
}

func DecodeFailures(raw string) map[string]int {
	if raw == "" {
		return nil
	}
	var result map[string]int
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil
	}
	return result
}
