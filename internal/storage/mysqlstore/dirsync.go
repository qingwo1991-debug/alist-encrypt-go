package mysqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func DirSnapshotKeyHash(scopeKey string) string {
	return KeyHash("dirsync", scopeKey)
}

func (s *Store) GetDirSnapshot(ctx context.Context, scopeKey string) (*DirSnapshotRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	return s.getAnySnapshotWhere(ctx, "key_hash=? AND is_active=1", DirSnapshotKeyHash(scopeKey))
}

// GetRequestFilledDirSnapshotByDisplay returns the most recently synced
// request_fill snapshot for a display path regardless of auth scope. Callers
// use it to serve a warm cache to a different/rotated session of the same
// directory, avoiding a full rebuild per new token. Only source_mode
// 'request_fill' rows are eligible (they carry the caller's own view, unlike
// background scan snapshots which may use a privileged scan account).
func (s *Store) GetRequestFilledDirSnapshotByDisplay(ctx context.Context, displayPath string) (*DirSnapshotRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	return s.getAnySnapshotWhere(ctx, "display_path=? AND is_active=1 AND source_mode='request_fill' AND item_count>0 ORDER BY last_sync_at DESC, updated_at DESC LIMIT 1", displayPath)
}

func (s *Store) getAnySnapshotWhere(ctx context.Context, where string, args ...interface{}) (*DirSnapshotRecord, bool, error) {
	query := "SELECT key_hash, scope_key, provider_host, display_path, auth_scope_hash, rule_version, item_count, stale, sync_state, last_sync_at, last_success_at, next_refresh_at, last_error, source_mode, payload_json, updated_at, last_accessed, is_active FROM " + TableName("dir_snapshot") + " WHERE " + where
	row := s.db.QueryRowContext(ctx, query, args...)
	var rec DirSnapshotRecord
	var stale, active int
	var lastSyncAt, lastSuccessAt, nextRefreshAt sql.NullTime
	if err := row.Scan(
		&rec.KeyHash,
		&rec.ScopeKey,
		&rec.ProviderHost,
		&rec.DisplayPath,
		&rec.AuthScopeHash,
		&rec.RuleVersion,
		&rec.ItemCount,
		&stale,
		&rec.SyncState,
		&lastSyncAt,
		&lastSuccessAt,
		&nextRefreshAt,
		&rec.LastError,
		&rec.SourceMode,
		&rec.PayloadJSON,
		&rec.UpdatedAt,
		&rec.LastAccessed,
		&active,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	rec.Stale = stale == 1
	rec.Active = active == 1
	if lastSyncAt.Valid {
		rec.LastSyncAt = lastSyncAt.Time
	}
	if lastSuccessAt.Valid {
		rec.LastSuccessAt = lastSuccessAt.Time
	}
	if nextRefreshAt.Valid {
		rec.NextRefreshAt = nextRefreshAt.Time
	}
	return &rec, true, nil
}

func (s *Store) UpsertDirSnapshot(ctx context.Context, rec DirSnapshotRecord) error {
	if s == nil {
		return nil
	}
	if rec.KeyHash == "" {
		rec.KeyHash = DirSnapshotKeyHash(rec.ScopeKey)
	}
	now := time.Now()
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = now
	}
	if rec.LastAccessed.IsZero() {
		rec.LastAccessed = rec.UpdatedAt
	}
	query := `INSERT INTO ` + TableName("dir_snapshot") + `
	(key_hash, scope_key, provider_host, display_path, auth_scope_hash, rule_version, item_count, stale, sync_state, last_sync_at, last_success_at, next_refresh_at, last_error, source_mode, payload_json, last_accessed, updated_at, is_active)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
	ON DUPLICATE KEY UPDATE
	  provider_host=VALUES(provider_host),
	  display_path=VALUES(display_path),
	  auth_scope_hash=VALUES(auth_scope_hash),
	  rule_version=VALUES(rule_version),
	  item_count=VALUES(item_count),
	  stale=VALUES(stale),
	  sync_state=VALUES(sync_state),
	  last_sync_at=VALUES(last_sync_at),
	  last_success_at=VALUES(last_success_at),
	  next_refresh_at=VALUES(next_refresh_at),
	  last_error=VALUES(last_error),
	  source_mode=VALUES(source_mode),
	  payload_json=VALUES(payload_json),
	  last_accessed=VALUES(last_accessed),
	  updated_at=VALUES(updated_at),
	  is_active=1`
	_, err := s.db.ExecContext(ctx, query,
		rec.KeyHash,
		rec.ScopeKey,
		rec.ProviderHost,
		rec.DisplayPath,
		rec.AuthScopeHash,
		rec.RuleVersion,
		rec.ItemCount,
		boolToInt(rec.Stale),
		rec.SyncState,
		nullableTime(rec.LastSyncAt),
		nullableTime(rec.LastSuccessAt),
		nullableTime(rec.NextRefreshAt),
		rec.LastError,
		rec.SourceMode,
		rec.PayloadJSON,
		rec.LastAccessed,
		rec.UpdatedAt,
	)
	return err
}

func (s *Store) CountDirSnapshots(ctx context.Context) (total, fresh, stale, syncing int64, err error) {
	if s == nil {
		return 0, 0, 0, 0, nil
	}
	query := fmt.Sprintf(`SELECT 
	COUNT(*),
	SUM(CASE WHEN stale=0 AND sync_state='fresh' THEN 1 ELSE 0 END),
	SUM(CASE WHEN stale=1 THEN 1 ELSE 0 END),
	SUM(CASE WHEN sync_state='syncing' THEN 1 ELSE 0 END)
	FROM %s WHERE is_active=1`, TableName("dir_snapshot"))
	var freshNull, staleNull, syncingNull sql.NullInt64
	if err = s.db.QueryRowContext(ctx, query).Scan(&total, &freshNull, &staleNull, &syncingNull); err != nil {
		return
	}
	if freshNull.Valid {
		fresh = freshNull.Int64
	}
	if staleNull.Valid {
		stale = staleNull.Int64
	}
	if syncingNull.Valid {
		syncing = syncingNull.Int64
	}
	return
}

func (s *Store) GetDirSyncStatus(ctx context.Context, name string) (*DirSyncStatusRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	row := s.db.QueryRowContext(ctx, "SELECT name, job_id, job_type, status, mode, scan_configured, total_dirs_estimate, total_dirs_discovered, dirs_scanned, dirs_succeeded, dirs_failed, dirs_skipped, items_synced, started_at, updated_at, finished_at, next_run_at, last_error, last_success_at FROM "+TableName("dir_sync_status")+" WHERE name=?", name)
	var rec DirSyncStatusRecord
	var scanConfigured int
	var startedAt, finishedAt, nextRunAt, lastSuccessAt sql.NullTime
	if err := row.Scan(
		&rec.Name,
		&rec.JobID,
		&rec.JobType,
		&rec.Status,
		&rec.Mode,
		&scanConfigured,
		&rec.TotalDirsEstimate,
		&rec.TotalDirsDiscovered,
		&rec.DirsScanned,
		&rec.DirsSucceeded,
		&rec.DirsFailed,
		&rec.DirsSkipped,
		&rec.ItemsSynced,
		&startedAt,
		&rec.UpdatedAt,
		&finishedAt,
		&nextRunAt,
		&rec.LastError,
		&lastSuccessAt,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	rec.ScanConfigured = scanConfigured == 1
	if startedAt.Valid {
		rec.StartedAt = startedAt.Time
	}
	if finishedAt.Valid {
		rec.FinishedAt = finishedAt.Time
	}
	if nextRunAt.Valid {
		rec.NextRunAt = nextRunAt.Time
	}
	if lastSuccessAt.Valid {
		rec.LastSuccessAt = lastSuccessAt.Time
	}
	return &rec, true, nil
}

func (s *Store) UpsertDirSyncStatus(ctx context.Context, rec DirSyncStatusRecord) error {
	if s == nil {
		return nil
	}
	if rec.Name == "" {
		rec.Name = "primary"
	}
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = time.Now()
	}
	query := `INSERT INTO ` + TableName("dir_sync_status") + `
	(name, job_id, job_type, status, mode, scan_configured, total_dirs_estimate, total_dirs_discovered, dirs_scanned, dirs_succeeded, dirs_failed, dirs_skipped, items_synced, started_at, updated_at, finished_at, next_run_at, last_error, last_success_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE
	  job_id=VALUES(job_id),
	  job_type=VALUES(job_type),
	  status=VALUES(status),
	  mode=VALUES(mode),
	  scan_configured=VALUES(scan_configured),
	  total_dirs_estimate=VALUES(total_dirs_estimate),
	  total_dirs_discovered=VALUES(total_dirs_discovered),
	  dirs_scanned=VALUES(dirs_scanned),
	  dirs_succeeded=VALUES(dirs_succeeded),
	  dirs_failed=VALUES(dirs_failed),
	  dirs_skipped=VALUES(dirs_skipped),
	  items_synced=VALUES(items_synced),
	  started_at=VALUES(started_at),
	  updated_at=VALUES(updated_at),
	  finished_at=VALUES(finished_at),
	  next_run_at=VALUES(next_run_at),
	  last_error=VALUES(last_error),
	  last_success_at=VALUES(last_success_at)`
	_, err := s.db.ExecContext(ctx, query,
		rec.Name,
		rec.JobID,
		rec.JobType,
		rec.Status,
		rec.Mode,
		boolToInt(rec.ScanConfigured),
		rec.TotalDirsEstimate,
		rec.TotalDirsDiscovered,
		rec.DirsScanned,
		rec.DirsSucceeded,
		rec.DirsFailed,
		rec.DirsSkipped,
		rec.ItemsSynced,
		nullableTime(rec.StartedAt),
		rec.UpdatedAt,
		nullableTime(rec.FinishedAt),
		nullableTime(rec.NextRunAt),
		rec.LastError,
		nullableTime(rec.LastSuccessAt),
	)
	return err
}

// deleteExpiredDirSnapshots 物理删除早于 cutoff 未再同步的目录快照。
// dir_snapshot 是纯缓存(命中后按需重建),这里必须用 DELETE 才能真正回收磁盘,
// 与 file_meta/strategy 等仅软删(is_active=0)的元数据表不同。
func (s *Store) deleteExpiredDirSnapshots(ctx context.Context, cutoff time.Time) error {
	if s == nil {
		return nil
	}
	query := fmt.Sprintf("DELETE FROM %s WHERE last_sync_at IS NULL OR last_sync_at < ?", TableName("dir_snapshot"))
	if _, err := s.db.ExecContext(ctx, query, cutoff); err != nil {
		return err
	}
	return nil
}

// dedupeDirSnapshots 将目录快照收敛为每个目录最多两条:
// scan/background_scan 一条 + 最近一次普通请求快照一条。
// 同一个目录会因不同会话/用户(scope_key 带 auth_scope_hash)产生大量内容几乎相同的副本,
// 这是磁盘膨胀的大头(单人使用时同目录可达上百份)。收敛后:
//   - scan/background_scan 行始终保留(scan 账号权限/内容可能与普通用户不同);
//   - 每个目录保留 last_sync_at 最新的一条普通请求快照(用户实际打开目录命中的内容);
//   - 同目录其余旧会话副本物理删除(命中时按需重建,不影响功能/播放)。
//
// 分区键包含 source_mode 折叠,避免把 scan 的"缩略/预览列表"误当成普通请求副本删除。
func (s *Store) dedupeDirSnapshots(ctx context.Context) error {
	if s == nil {
		return nil
	}
	query := fmt.Sprintf(`DELETE FROM %[1]s WHERE key_hash IN (
  SELECT key_hash FROM (
    SELECT key_hash,
           ROW_NUMBER() OVER (
             PARTITION BY provider_host, display_path,
               CASE WHEN source_mode IN ('scan','background_scan') THEN 0 ELSE 1 END
             ORDER BY last_sync_at DESC
           ) AS rn
    FROM %[1]s
    WHERE is_active = 1
  ) ranked
  WHERE rn > 1
)`, TableName("dir_snapshot"))
	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return err
	}
	return nil
}
