package mysqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type FileMetaFilter struct {
	ProviderHost  string
	OriginalPath  string
	PathPrefix    string
	UpdatedAfter  time.Time // Inclusive lower bound, independent of the cursor.
	CursorKey     string
	CursorTime    time.Time // Exclusive (CursorTime, CursorKey) lower bound.
	LegacySeconds bool      // Compare and order timestamps at whole-second precision.
	Limit         int       // Explicit fetch count; callers include any lookahead row.
	Offset        int
}

func (s *Store) GetFileMeta(ctx context.Context, providerKey, originalPath string) (*FileMetaRecord, bool, error) {
	if s == nil {
		return nil, false, nil
	}
	providerHost, _ := SplitProviderKey(providerKey)
	keyHash := KeyHash(providerHost, originalPath)

	query := "SELECT key_hash, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, chunk_size, kdf_iterations, etag, content_type, raw_url, raw_url_auth_scope, sign, status_code, updated_at, last_accessed, upstream_fetched_at, is_active FROM " + TableName("file_meta") + " WHERE key_hash = ? AND is_active=1"
	row := s.db.QueryRowContext(ctx, query, keyHash)

	var record FileMetaRecord
	var isActive int
	var upstreamFetchedAt sql.NullTime
	var encryptedPath, name, etag, contentType, rawURL, rawURLAuthScope, sign sql.NullString
	if err := row.Scan(
		&record.KeyHash,
		&record.ProviderHost,
		&record.OriginalPath,
		&encryptedPath,
		&name,
		&record.Size,
		&record.CiphertextSize,
		&record.ContentVersion,
		&record.HeaderLen,
		&record.NonceField,
		&record.ChunkSize,
		&record.KDFIterations,
		&etag,
		&contentType,
		&rawURL,
		&rawURLAuthScope,
		&sign,
		&record.StatusCode,
		&record.UpdatedAt,
		&record.LastAccessed,
		&upstreamFetchedAt,
		&isActive,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	record.EncryptedPath = encryptedPath.String
	record.Name = name.String
	record.ETag = etag.String
	record.ContentType = contentType.String
	record.RawURL = rawURL.String
	record.RawURLAuthScope = rawURLAuthScope.String
	record.Sign = sign.String
	record.Active = isActive == 1
	if upstreamFetchedAt.Valid {
		record.UpstreamFetchedAt = upstreamFetchedAt.Time
	}
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
	if record.UpstreamFetchedAt.IsZero() {
		record.UpstreamFetchedAt = record.UpdatedAt
	}
	// Merge while holding the buffer lock: a size-only update arriving before
	// flush must not replace the only copy of freshly probed V3 metadata.
	b := s.fileMetaBuffer
	b.mu.Lock()
	if existing, ok := b.items[record.KeyHash]; ok {
		sameContainer := (len(record.NonceField) == 0 || bytes.Equal(record.NonceField, existing.NonceField)) &&
			(record.ContentVersion <= 0 || record.ContentVersion == existing.ContentVersion)
		if sameContainer {
			if record.ContentVersion <= 0 && ((existing.ContentVersion == 3 && existing.CiphertextSize > 0 && record.Size == existing.CiphertextSize) ||
				(existing.ContentVersion == 2 && existing.HeaderLen > 0 && (record.Size == existing.CiphertextSize || record.Size == existing.Size+existing.HeaderLen))) {
				record.Size = existing.Size
			}
			if record.ContentVersion <= 0 {
				record.ContentVersion = existing.ContentVersion
			}
			if record.CiphertextSize <= 0 {
				record.CiphertextSize = existing.CiphertextSize
			}
			if record.HeaderLen <= 0 {
				record.HeaderLen = existing.HeaderLen
			}
			if len(record.NonceField) == 0 {
				record.NonceField = append([]byte(nil), existing.NonceField...)
			}
			if record.ChunkSize == 0 {
				record.ChunkSize = existing.ChunkSize
			}
			if record.KDFIterations == 0 {
				record.KDFIterations = existing.KDFIterations
			}
		}
	}
	record.NonceField = append([]byte(nil), record.NonceField...)
	b.items[record.KeyHash] = record
	b.mu.Unlock()
	return nil
}

func (s *Store) CleanupFileMeta(ctx context.Context, cutoff time.Time) error {
	if s == nil {
		return nil
	}
	return s.markFileMetaExpired(ctx, cutoff)
}

func (s *Store) ListFileMeta(ctx context.Context, filter FileMetaFilter) ([]FileMetaRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("mysqlstore: file metadata store is unavailable")
	}

	cursorTime := filter.CursorTime
	if filter.LegacySeconds && cursorTime.IsZero() {
		cursorTime = filter.UpdatedAfter
	}
	if filter.CursorKey != "" && cursorTime.IsZero() {
		return nil, errors.New("mysqlstore: file metadata cursor key requires a cursor timestamp")
	}

	// DATE_FORMAT floors fractional seconds, unlike casts to DATETIME(0),
	// which may round. Use the same expression for every legacy predicate and
	// ordering term so rows within one second are ordered only by their key.
	timeColumn := "updated_at"
	timePlaceholder := "?"
	timeArg := func(t time.Time) interface{} { return t }
	if filter.LegacySeconds {
		timeColumn = "DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s')"
		timePlaceholder = "DATE_FORMAT(?, '%Y-%m-%d %H:%i:%s')"
		// Keep time.Time arguments so the driver applies its configured Loc.
		timeArg = func(t time.Time) interface{} { return t.Truncate(time.Second) }
	}

	query := "SELECT key_hash, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, chunk_size, kdf_iterations, etag, content_type, raw_url, raw_url_auth_scope, sign, status_code, updated_at, last_accessed, upstream_fetched_at, is_active FROM " + TableName("file_meta") + " WHERE is_active=1"
	args := []interface{}{}

	if filter.ProviderHost != "" {
		query += " AND BINARY provider_host = BINARY ?"
		args = append(args, filter.ProviderHost)
	}
	if filter.OriginalPath != "" {
		query += " AND BINARY original_path = BINARY ?"
		args = append(args, filter.OriginalPath)
	}
	if filter.PathPrefix != "" {
		query += " AND BINARY original_path LIKE BINARY ? ESCAPE '='"
		prefix := strings.NewReplacer("=", "==", "%", "=%", "_", "=_").Replace(filter.PathPrefix)
		args = append(args, prefix+"%")
	}
	if !filter.UpdatedAfter.IsZero() {
		query += " AND " + timeColumn + " >= " + timePlaceholder
		args = append(args, timeArg(filter.UpdatedAfter))
	}
	if filter.CursorKey != "" {
		query += " AND (" + timeColumn + " > " + timePlaceholder + " OR (" + timeColumn + " = " + timePlaceholder + " AND BINARY key_hash > BINARY ?))"
		args = append(args, timeArg(cursorTime), timeArg(cursorTime), filter.CursorKey)
	}
	query += " ORDER BY " + timeColumn + " ASC, BINARY key_hash ASC"

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
		var upstreamFetchedAt sql.NullTime
		// Several columns are NULL-able in the schema (encrypted_path, name,
		// nonce_field, etag, content_type, raw_url, sign). Scanning NULL into a
		// plain string/[]byte fails, so use Null wrappers and coerce to empty.
		var encryptedPath, name, etag, contentType, rawURL, rawURLAuthScope, sign sql.NullString
		var nonceField []byte
		if err := rows.Scan(
			&record.KeyHash,
			&record.ProviderHost,
			&record.OriginalPath,
			&encryptedPath,
			&name,
			&record.Size,
			&record.CiphertextSize,
			&record.ContentVersion,
			&record.HeaderLen,
			&nonceField,
			&record.ChunkSize,
			&record.KDFIterations,
			&etag,
			&contentType,
			&rawURL,
			&rawURLAuthScope,
			&sign,
			&record.StatusCode,
			&record.UpdatedAt,
			&record.LastAccessed,
			&upstreamFetchedAt,
			&isActive,
		); err != nil {
			return nil, err
		}
		record.EncryptedPath = encryptedPath.String
		record.Name = name.String
		record.ETag = etag.String
		record.ContentType = contentType.String
		record.RawURL = rawURL.String
		record.RawURLAuthScope = rawURLAuthScope.String
		record.Sign = sign.String
		record.NonceField = nonceField
		record.Active = isActive == 1
		if upstreamFetchedAt.Valid {
			record.UpstreamFetchedAt = upstreamFetchedAt.Time
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
