package mysqlstore

import (
	"context"
	"database/sql"
	"time"
)

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
