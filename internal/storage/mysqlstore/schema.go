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
	dirSnapshotTable := TableName("dir_snapshot")
	dirSyncStatusTable := TableName("dir_sync_status")

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
  encrypted_path TEXT NULL,
  name VARCHAR(512) NULL,
  size BIGINT NOT NULL,
  ciphertext_size BIGINT NOT NULL DEFAULT 0,
  content_version INT NOT NULL DEFAULT 0,
  header_len BIGINT NOT NULL DEFAULT 0,
  nonce_field VARBINARY(64) NULL,
  etag VARCHAR(255) NULL,
  content_type VARCHAR(128) NULL,
  status_code INT NOT NULL,
  last_accessed DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  is_active TINYINT NOT NULL DEFAULT 1,
  upstream_fetched_at DATETIME NULL,
  raw_url VARCHAR(2048) NULL,
  sign VARCHAR(512) NULL,
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

	dirSnapshotSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  key_hash CHAR(32) NOT NULL,
  scope_key VARCHAR(512) NOT NULL,
  provider_host VARCHAR(255) NOT NULL,
  display_path TEXT NOT NULL,
  auth_scope_hash VARCHAR(64) NOT NULL,
  rule_version VARCHAR(64) NOT NULL,
  item_count INT NOT NULL DEFAULT 0,
  stale TINYINT NOT NULL DEFAULT 0,
  sync_state VARCHAR(32) NOT NULL DEFAULT 'fresh',
  last_sync_at DATETIME NULL,
  last_success_at DATETIME NULL,
  next_refresh_at DATETIME NULL,
  last_error TEXT NULL,
  source_mode VARCHAR(32) NOT NULL DEFAULT 'request_fill',
  payload_json MEDIUMTEXT NOT NULL,
  last_accessed DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  is_active TINYINT NOT NULL DEFAULT 1,
  PRIMARY KEY (key_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`, dirSnapshotTable)

	dirSyncStatusSQL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
  name VARCHAR(64) NOT NULL,
  job_id VARCHAR(64) NOT NULL,
  job_type VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  mode VARCHAR(32) NOT NULL,
  scan_configured TINYINT NOT NULL DEFAULT 0,
  total_dirs_estimate INT NOT NULL DEFAULT 0,
  total_dirs_discovered INT NOT NULL DEFAULT 0,
  dirs_scanned INT NOT NULL DEFAULT 0,
  dirs_succeeded INT NOT NULL DEFAULT 0,
  dirs_failed INT NOT NULL DEFAULT 0,
  dirs_skipped INT NOT NULL DEFAULT 0,
  items_synced INT NOT NULL DEFAULT 0,
  started_at DATETIME NULL,
  updated_at DATETIME NOT NULL,
  finished_at DATETIME NULL,
  next_run_at DATETIME NULL,
  last_error TEXT NULL,
  last_success_at DATETIME NULL,
  PRIMARY KEY (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`, dirSyncStatusTable)

	if _, err := s.db.ExecContext(ctx, strategySQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, fileMetaSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, rangeCompatSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, dirSnapshotSQL); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, dirSyncStatusSQL); err != nil {
		return err
	}
	return s.migrateSchema(ctx)
}

func (s *Store) migrateSchema(ctx context.Context) error {
	migrations := []string{
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN upstream_fetched_at DATETIME NULL", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN raw_url VARCHAR(2048) NULL", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN sign VARCHAR(512) NULL", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN encrypted_path TEXT NULL", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN name VARCHAR(512) NULL", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN ciphertext_size BIGINT NOT NULL DEFAULT 0", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN content_version INT NOT NULL DEFAULT 0", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN header_len BIGINT NOT NULL DEFAULT 0", TableName("file_meta")),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN nonce_field VARBINARY(64) NULL", TableName("file_meta")),
	}
	for _, m := range migrations {
		if _, err := s.db.ExecContext(ctx, m); err != nil {
			if strings.Contains(err.Error(), "Duplicate column") || strings.Contains(err.Error(), "1060") {
				continue
			}
			return err
		}
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
  (key_hash, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, etag, content_type, status_code, raw_url, sign, last_accessed, updated_at, upstream_fetched_at, is_active)
  VALUES %s
  ON DUPLICATE KEY UPDATE
    encrypted_path=VALUES(encrypted_path),
    name=VALUES(name),
    size=VALUES(size),
    ciphertext_size=VALUES(ciphertext_size),
    content_version=VALUES(content_version),
    header_len=VALUES(header_len),
    nonce_field=VALUES(nonce_field),
    etag=VALUES(etag),
    content_type=VALUES(content_type),
    status_code=VALUES(status_code),
    raw_url=VALUES(raw_url),
    sign=VALUES(sign),
    last_accessed=VALUES(last_accessed),
    updated_at=VALUES(updated_at),
    upstream_fetched_at=VALUES(upstream_fetched_at),
    is_active=VALUES(is_active)`, TableName("file_meta"), buildPlaceholders(19, len(records)))

	args := make([]interface{}, 0, len(records)*19)
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
		upstreamFetchedAt := record.UpstreamFetchedAt
		if upstreamFetchedAt.IsZero() {
			upstreamFetchedAt = now
		}
		args = append(args,
			record.KeyHash,
			record.ProviderHost,
			record.OriginalPath,
			record.EncryptedPath,
			record.Name,
			record.Size,
			record.CiphertextSize,
			record.ContentVersion,
			record.HeaderLen,
			record.NonceField,
			record.ETag,
			record.ContentType,
			record.StatusCode,
			record.RawURL,
			record.Sign,
			lastAccessed,
			updatedAt,
			upstreamFetchedAt,
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
