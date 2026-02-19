package mysqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func RangeCompatKeyHash(providerHost, storageKey string) string {
	return KeyHash(providerHost, storageKey)
}

func (s *Store) GetRangeCompat(ctx context.Context, providerHost, storageKey string) (*RangeCompatRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	keyHash := RangeCompatKeyHash(providerHost, storageKey)

	query := "SELECT key_hash, provider_host, storage_key, incompatible, consecutive_failures, consecutive_successes, next_probe_at, last_reason, last_checked_at, updated_at, last_accessed, is_active FROM " + TableName("range_compat") + " WHERE key_hash = ? AND is_active=1"
	row := s.db.QueryRowContext(ctx, query, keyHash)

	var record RangeCompatRecord
	var incompatible int
	var isActive int
	var nextProbeAt sql.NullTime
	var lastCheckedAt sql.NullTime
	if err := row.Scan(
		&record.KeyHash,
		&record.ProviderHost,
		&record.StorageKey,
		&incompatible,
		&record.ConsecutiveFailures,
		&record.ConsecutiveSuccesses,
		&nextProbeAt,
		&record.LastReason,
		&lastCheckedAt,
		&record.UpdatedAt,
		&record.LastAccessed,
		&isActive,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	record.Incompatible = incompatible == 1
	record.Active = isActive == 1
	if nextProbeAt.Valid {
		record.NextProbeAt = nextProbeAt.Time
	}
	if lastCheckedAt.Valid {
		record.LastCheckedAt = lastCheckedAt.Time
	}
	return &record, true, nil
}

func (s *Store) UpsertRangeCompat(ctx context.Context, record RangeCompatRecord) error {
	if s == nil {
		return nil
	}
	if record.KeyHash == "" {
		record.KeyHash = RangeCompatKeyHash(record.ProviderHost, record.StorageKey)
	}
	if !record.Active {
		record.Active = true
	}
	record.UpdatedAt = time.Now()
	record.LastAccessed = time.Now()
	s.rangeCompatBuffer.upsert(record)
	return nil
}

func (s *Store) CountRangeCompatActive(ctx context.Context) (int64, error) {
	if s == nil {
		return 0, nil
	}
	query := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE is_active=1", TableName("range_compat"))
	var count int64
	if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
