package mysqlstore

import (
	"context"
	"database/sql"
	"time"
)

type FileMetaFilter struct {
	ProviderHost string
	OriginalPath string
	PathPrefix   string
	UpdatedAfter time.Time
	CursorKey    string
	Limit        int
	Offset       int
}

func (s *Store) GetFileMeta(ctx context.Context, providerKey, originalPath string) (*FileMetaRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	providerHost, _ := SplitProviderKey(providerKey)
	keyHash := KeyHash(providerHost, originalPath)

	query := "SELECT key_hash, provider_host, original_path, size, etag, content_type, status_code, updated_at, last_accessed, is_active FROM " + TableName("file_meta") + " WHERE key_hash = ? AND is_active=1"
	row := s.db.QueryRowContext(ctx, query, keyHash)

	var record FileMetaRecord
	var isActive int
	if err := row.Scan(
		&record.KeyHash,
		&record.ProviderHost,
		&record.OriginalPath,
		&record.Size,
		&record.ETag,
		&record.ContentType,
		&record.StatusCode,
		&record.UpdatedAt,
		&record.LastAccessed,
		&isActive,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	record.Active = isActive == 1
	return &record, true, nil
}

func (s *Store) UpsertFileMeta(ctx context.Context, record FileMetaRecord) error {
	if s == nil {
		return nil
	}
	if record.KeyHash == "" {
		record.KeyHash = KeyHash(record.ProviderHost, record.OriginalPath)
	}

	record.UpdatedAt = time.Now()
	record.LastAccessed = time.Now()
	s.fileMetaBuffer.upsert(record)
	return nil
}

func (s *Store) CleanupFileMeta(ctx context.Context, cutoff time.Time) error {
	if s == nil {
		return nil
	}
	return s.markFileMetaExpired(ctx, cutoff)
}

func (s *Store) ListFileMeta(ctx context.Context, filter FileMetaFilter) ([]FileMetaRecord, error) {
	if s == nil {
		return nil, nil
	}

	query := "SELECT key_hash, provider_host, original_path, size, etag, content_type, status_code, updated_at, last_accessed, is_active FROM " + TableName("file_meta") + " WHERE is_active=1"
	args := []interface{}{}

	if filter.ProviderHost != "" {
		query += " AND provider_host = ?"
		args = append(args, filter.ProviderHost)
	}
	if filter.OriginalPath != "" {
		query += " AND original_path = ?"
		args = append(args, filter.OriginalPath)
	}
	if filter.PathPrefix != "" {
		query += " AND original_path LIKE ?"
		args = append(args, filter.PathPrefix+"%")
	}
	if !filter.UpdatedAfter.IsZero() {
		query += " AND updated_at >= ?"
		args = append(args, filter.UpdatedAfter)
	}
	if filter.CursorKey != "" && !filter.UpdatedAfter.IsZero() {
		query += " AND (updated_at > ? OR (updated_at = ? AND key_hash > ?))"
		args = append(args, filter.UpdatedAfter, filter.UpdatedAfter, filter.CursorKey)
	}
	query += " ORDER BY updated_at ASC, key_hash ASC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []FileMetaRecord
	for rows.Next() {
		var record FileMetaRecord
		var isActive int
		if err := rows.Scan(
			&record.KeyHash,
			&record.ProviderHost,
			&record.OriginalPath,
			&record.Size,
			&record.ETag,
			&record.ContentType,
			&record.StatusCode,
			&record.UpdatedAt,
			&record.LastAccessed,
			&isActive,
		); err != nil {
			return nil, err
		}
		record.Active = isActive == 1
		records = append(records, record)
	}
	return records, rows.Err()
}
