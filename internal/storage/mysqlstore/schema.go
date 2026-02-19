package mysqlstore

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (s *Store) ensureSchema(ctx context.Context) error {
	strategyTable := TableName("strategy")
	fileMetaTable := TableName("file_meta")
	rangeCompatTable := TableName("range_compat")

	strategySQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  key_hash CHAR(32) NOT NULL,
  provider_host VARCHAR(255) NOT NULL,
  original_path TEXT NOT NULL,
  preferred_strategy VARCHAR(16) NOT NULL,
  failures_json TEXT NULL,
  success_streak INT NOT NULL DEFAULT 0,
  total_failures INT NOT NULL DEFAULT 0,
  total_successes INT NOT NULL DEFAULT 0,
  cooldown_until DATETIME NULL,
  last_downgrade DATETIME NULL,
  last_failure VARCHAR(64) NULL,
  last_strategy VARCHAR(16) NULL,
  last_accessed DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  is_active TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`, strategyTable)

	fileMetaSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  key_hash CHAR(32) NOT NULL,
  provider_host VARCHAR(255) NOT NULL,
  original_path TEXT NOT NULL,
  size BIGINT NOT NULL,
  etag VARCHAR(255) NULL,
  content_type VARCHAR(128) NULL,
  status_code INT NOT NULL,
  last_accessed DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  is_active TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`, fileMetaTable)

	rangeCompatSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  key_hash CHAR(32) NOT NULL,
  provider_host VARCHAR(255) NOT NULL,
  storage_key VARCHAR(512) NOT NULL,
  incompatible TINYINT NOT NULL DEFAULT 0,
  consecutive_failures INT NOT NULL DEFAULT 0,
  consecutive_successes INT NOT NULL DEFAULT 0,
  next_probe_at DATETIME NULL,
  last_reason VARCHAR(64) NULL,
  last_checked_at DATETIME NULL,
  last_accessed DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  is_active TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`, rangeCompatTable)

	if _, err := s.db.ExecContext(ctx, strategySQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, fileMetaSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, rangeCompatSQL); err != nil {
		return err
	}
	return nil
}

func (s *Store) upsertStrategies(ctx context.Context, records []StrategyRecord) error {
	if len(records) == 0 {
		return nil
	}
	query := fmt.Sprintf(`INSERT INTO %s
  (key_hash, provider_host, original_path, preferred_strategy, failures_json, success_streak, total_failures, total_successes, cooldown_until, last_downgrade, last_failure, last_strategy, last_accessed, updated_at, is_active)
  VALUES %s
  ON DUPLICATE KEY UPDATE
    preferred_strategy=VALUES(preferred_strategy),
    failures_json=VALUES(failures_json),
    success_streak=VALUES(success_streak),
    total_failures=VALUES(total_failures),
    total_successes=VALUES(total_successes),
    cooldown_until=VALUES(cooldown_until),
    last_downgrade=VALUES(last_downgrade),
    last_failure=VALUES(last_failure),
    last_strategy=VALUES(last_strategy),
    last_accessed=VALUES(last_accessed),
    updated_at=VALUES(updated_at),
    is_active=VALUES(is_active)`, TableName("strategy"), buildPlaceholders(15, len(records)))

	args := make([]interface{}, 0, len(records)*15)
	now := time.Now()
	for _, record := range records {
		lastAccessed := record.LastAccessed
		if lastAccessed.IsZero() {
			lastAccessed = now
		}
		updatedAt := record.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = now
		}
		args = append(args,
			record.KeyHash,
			record.ProviderHost,
			record.OriginalPath,
			record.Preferred,
			record.FailuresJSON,
			record.SuccessStreak,
			record.TotalFailures,
			record.TotalSuccesses,
			nullableTime(record.CooldownUntil),
			nullableTime(record.LastDowngrade),
			record.LastFailure,
			record.LastStrategy,
			lastAccessed,
			updatedAt,
			1,
		)
	}

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Store) upsertFileMeta(ctx context.Context, records []FileMetaRecord) error {
	if len(records) == 0 {
		return nil
	}
	query := fmt.Sprintf(`INSERT INTO %s
  (key_hash, provider_host, original_path, size, etag, content_type, status_code, last_accessed, updated_at, is_active)
  VALUES %s
  ON DUPLICATE KEY UPDATE
    size=VALUES(size),
    etag=VALUES(etag),
    content_type=VALUES(content_type),
    status_code=VALUES(status_code),
    last_accessed=VALUES(last_accessed),
    updated_at=VALUES(updated_at),
    is_active=VALUES(is_active)`, TableName("file_meta"), buildPlaceholders(10, len(records)))

	args := make([]interface{}, 0, len(records)*10)
	now := time.Now()
	for _, record := range records {
		lastAccessed := record.LastAccessed
		if lastAccessed.IsZero() {
			lastAccessed = now
		}
		updatedAt := record.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = now
		}
		args = append(args,
			record.KeyHash,
			record.ProviderHost,
			record.OriginalPath,
			record.Size,
			record.ETag,
			record.ContentType,
			record.StatusCode,
			lastAccessed,
			updatedAt,
			boolToInt(record.Active),
		)
	}

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Store) upsertRangeCompats(ctx context.Context, records []RangeCompatRecord) error {
	if len(records) == 0 {
		return nil
	}
	query := fmt.Sprintf(`INSERT INTO %s
  (key_hash, provider_host, storage_key, incompatible, consecutive_failures, consecutive_successes, next_probe_at, last_reason, last_checked_at, last_accessed, updated_at, is_active)
  VALUES %s
  ON DUPLICATE KEY UPDATE
    incompatible=VALUES(incompatible),
    consecutive_failures=VALUES(consecutive_failures),
    consecutive_successes=VALUES(consecutive_successes),
    next_probe_at=VALUES(next_probe_at),
    last_reason=VALUES(last_reason),
    last_checked_at=VALUES(last_checked_at),
    last_accessed=VALUES(last_accessed),
    updated_at=VALUES(updated_at),
    is_active=VALUES(is_active)`, TableName("range_compat"), buildPlaceholders(12, len(records)))

	args := make([]interface{}, 0, len(records)*12)
	now := time.Now()
	for _, record := range records {
		lastAccessed := record.LastAccessed
		if lastAccessed.IsZero() {
			lastAccessed = now
		}
		updatedAt := record.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = now
		}
		args = append(args,
			record.KeyHash,
			record.ProviderHost,
			record.StorageKey,
			boolToInt(record.Incompatible),
			record.ConsecutiveFailures,
			record.ConsecutiveSuccesses,
			nullableTime(record.NextProbeAt),
			record.LastReason,
			nullableTime(record.LastCheckedAt),
			lastAccessed,
			updatedAt,
			boolToInt(record.Active),
		)
	}

	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Store) markStrategyExpired(ctx context.Context, cutoff time.Time) error {
	query := fmt.Sprintf("UPDATE %s SET is_active=0 WHERE last_accessed < ?", TableName("strategy"))
	_, err := s.db.ExecContext(ctx, query, cutoff)
	return err
}

func (s *Store) markFileMetaExpired(ctx context.Context, cutoff time.Time) error {
	query := fmt.Sprintf("UPDATE %s SET is_active=0 WHERE last_accessed < ?", TableName("file_meta"))
	_, err := s.db.ExecContext(ctx, query, cutoff)
	return err
}

func (s *Store) markRangeCompatExpired(ctx context.Context, cutoff time.Time) error {
	query := fmt.Sprintf("UPDATE %s SET is_active=0 WHERE last_accessed < ?", TableName("range_compat"))
	_, err := s.db.ExecContext(ctx, query, cutoff)
	return err
}

func buildPlaceholders(columnCount, rows int) string {
	if rows <= 0 {
		return ""
	}
	row := "(" + strings.TrimRight(strings.Repeat("?,", columnCount), ",") + ")"
	return strings.TrimRight(strings.Repeat(row+",", rows), ",")
}

func nullableTime(value time.Time) interface{} {
	if value.IsZero() {
		return nil
	}
	return value
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
