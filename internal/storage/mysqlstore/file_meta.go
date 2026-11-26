package mysqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// fileMetaPathChunk is the number of original_path values folded into one
// IN (...) predicate by the batch lookups. ~200 keeps the statement well
// below max_allowed_packet while still collapsing a 500-entry directory into
// three queries instead of five hundred.
const fileMetaPathChunk = 200

// fileMetaByPathPredicates narrows a path-only lookup to rows whose
// original_path equals ? under the table collation AND bytewise. The plain
// equality is sargable (it can use idx_file_meta_path); the BINARY recheck
// keeps the match exact for case and accents, which utf8mb4_0900_ai_ci would
// otherwise fold. Both placeholders receive the same value.
const fileMetaByPathPredicates = " AND original_path = ? AND BINARY original_path = BINARY ?"

// escapeLikePattern escapes LIKE metacharacters for use with ESCAPE '='.
func escapeLikePattern(prefix string) string {
	return strings.NewReplacer("=", "==", "%", "=%", "_", "=_").Replace(prefix)
}

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

// GetFileMetaByPath returns the best active record for a display path that
// carries confirmed content metadata, preferring rows that also hold a raw
// URL (signed URLs expire, so the freshest fetch wins) and falling back to
// content-meta-only rows. The file_meta key embeds the provider
// host observed when the row was written, which is not stable across raw-url
// providers, so path-only lookups cannot use KeyHash. Content metadata
// (version/nonce/geometry) is file-intrinsic and safe to share across scopes.
//
// The predicate pairs a plain collation equality (sargable through
// idx_file_meta_path) with a BINARY recheck so the match stays exact even
// though the table collation is case/accent-insensitive.
func (s *Store) GetFileMetaByPath(ctx context.Context, originalPath string) (*FileMetaRecord, bool, error) {
	if s == nil || s.db == nil || originalPath == "" {
		return nil, false, nil
	}
	query := "SELECT key_hash, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, chunk_size, kdf_iterations, etag, content_type, raw_url, raw_url_auth_scope, sign, status_code, updated_at, last_accessed, upstream_fetched_at, is_active FROM " + TableName("file_meta") + " WHERE is_active=1 AND content_version > 0" + fileMetaByPathPredicates + " ORDER BY (raw_url IS NOT NULL AND raw_url <> '') DESC, upstream_fetched_at DESC LIMIT 1"
	row := s.db.QueryRowContext(ctx, query, originalPath, originalPath)

	record, err := scanFileMetaRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	return record, true, nil
}

// GetFileMetaByPaths resolves many display paths in a handful of IN (...)
// queries instead of one full scan per path. For every requested path that has
// at least one qualifying row, the returned record is the same one
// GetFileMetaByPath would select (raw URL present first, then the newest
// upstream_fetched_at; only is_active=1 AND content_version>0 rows qualify).
// Paths with no qualifying row are simply absent from the map. Rows whose
// path differs only by case or accent are rejected by a bytewise comparison in
// Go, mirroring the BINARY recheck of the single-path query.
func (s *Store) GetFileMetaByPaths(ctx context.Context, paths []string) (map[string]*FileMetaRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	result := make(map[string]*FileMetaRecord)
	seen := make(map[string]struct{}, len(paths))
	unique := make([]string, 0, len(paths))
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		unique = append(unique, p)
	}
	for start := 0; start < len(unique); start += fileMetaPathChunk {
		end := start + fileMetaPathChunk
		if end > len(unique) {
			end = len(unique)
		}
		chunk := unique[start:end]
		if err := s.getFileMetaByPathsChunk(ctx, chunk, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// betterFileMetaCandidate reports whether candidate should replace best as the
// row returned for one path. It mirrors the ORDER BY of GetFileMetaByPath:
// a raw URL wins, then the newer upstream_fetched_at. Ties keep the first row
// seen (the single-path query has no tiebreaker beyond the index order).
func betterFileMetaCandidate(candidate, best *FileMetaRecord) bool {
	if best == nil {
		return true
	}
	cHasRaw := candidate.RawURL != ""
	bHasRaw := best.RawURL != ""
	if cHasRaw != bHasRaw {
		return cHasRaw
	}
	return candidate.UpstreamFetchedAt.After(best.UpstreamFetchedAt)
}

func (s *Store) getFileMetaByPathsChunk(ctx context.Context, paths []string, out map[string]*FileMetaRecord) error {
	var qb strings.Builder
	qb.WriteString("SELECT key_hash, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, chunk_size, kdf_iterations, etag, content_type, raw_url, raw_url_auth_scope, sign, status_code, updated_at, last_accessed, upstream_fetched_at, is_active FROM ")
	qb.WriteString(TableName("file_meta"))
	qb.WriteString(" WHERE is_active=1 AND content_version > 0 AND original_path IN (")
	args := make([]interface{}, 0, len(paths)*3)
	for i, p := range paths {
		if i > 0 {
			qb.WriteString(",")
		}
		qb.WriteString("?")
		args = append(args, p)
	}
	qb.WriteString(")")
	// The IN list narrows through idx_file_meta_path under the collation; the
	// per-row BINARY comparison below keeps the match exact without wrapping
	// the column itself in BINARY (which would defeat the index).
	qb.WriteString(" AND (")
	for i, p := range paths {
		if i > 0 {
			qb.WriteString(" OR ")
		}
		qb.WriteString("(original_path = ? AND BINARY original_path = BINARY ?)")
		args = append(args, p, p)
	}
	qb.WriteString(")")

	rows, err := s.db.QueryContext(ctx, qb.String(), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		record, err := scanFileMetaRows(rows)
		if err != nil {
			return err
		}
		// Exact match in Go: rows that the collation folded together (case or
		// accent differences) must never answer for another path.
		if _, requested := seenPath(paths, record.OriginalPath); !requested {
			continue
		}
		if betterFileMetaCandidate(record, out[record.OriginalPath]) {
			out[record.OriginalPath] = record
		}
	}
	return rows.Err()
}

// seenPath reports whether exact matches one of the chunk's requested paths bytewise.
func seenPath(paths []string, exact string) (int, bool) {
	// Paths are short and chunks bounded (~200); a linear scan is cheaper than
	// allocating a map per chunk.
	for i, p := range paths {
		if p == exact {
			return i, true
		}
	}
	return 0, false
}

// fileMetaScanner is satisfied by both *sql.Row and *sql.Rows.
type fileMetaScanner interface {
	Scan(dest ...interface{}) error
}

// scanFileMetaRow reads a single file_meta row into a record.
func scanFileMetaRow(row fileMetaScanner) (*FileMetaRecord, error) {
	var record FileMetaRecord
	if err := scanFileMetaInto(row, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// scanFileMetaRows reads the current *sql.Rows row into a record.
func scanFileMetaRows(rows *sql.Rows) (*FileMetaRecord, error) {
	var record FileMetaRecord
	if err := scanFileMetaInto(rows, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

func scanFileMetaInto(row fileMetaScanner, record *FileMetaRecord) error {
	var isActive int
	var upstreamFetchedAt sql.NullTime
	var encryptedPath, name, etag, contentType, rawURL, rawURLAuthScope, sign sql.NullString
	var nonceField []byte
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
		return err
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
	return nil
}

func (s *Store) UpsertFileMeta(ctx context.Context, record FileMetaRecord) error {
	if s == nil {
		return nil
	}
	// One row per path: every new write lands on the stable key regardless of
	// which provider host the caller observed. provider_host is kept as the
	// stable host too so the row is self-consistent; the raw URL host the
	// caller saw lives in raw_url, which is where it belongs.
	record.ProviderHost = s.StableProviderHost()
	record.KeyHash = s.StableFileMetaKeyHash(record.OriginalPath)

	// A caller-supplied fetch time marks a real upstream observation. Capture
	// it before the write stamp is applied so the no-op check can tell a
	// genuine refresh apart from the stamp (see fileMetaWriteUnchanged).
	record.explicitFetch = !record.UpstreamFetchedAt.IsZero()

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
	// Fast path: the row equals what this process last flushed (or last found
	// unchanged in the database) for the key, so the database already holds
	// it. Keys not in memory are compared against the database once per flush
	// (filterUnchangedFileMeta), never here on the request path.
	if last, ok := b.lastFlushed[record.KeyHash]; ok && s.reconcileUnchanged(&record, last) {
		b.mu.Unlock()
		return nil
	}
	record.NonceField = append([]byte(nil), record.NonceField...)
	b.items[record.KeyHash] = record
	b.mu.Unlock()
	return nil
}

// filterUnchangedFileMeta drops records whose stored row already equals them
// in every information-bearing column. Keys known from this process's last
// flush are checked in memory; every other key costs exactly one primary-key
// SELECT, and that same row is handed to the configured merger so the V2/V3
// size reconciliation that used to run on every request runs once per flush
// instead. A SELECT error is not fatal: the record is kept and written, which
// is the pre-dedup behaviour. The returned kept slice aliases records; the
// second return lists the records that were dropped as unchanged.
func (s *Store) filterUnchangedFileMeta(ctx context.Context, records []FileMetaRecord) (kept, unchanged []FileMetaRecord) {
	if s == nil || s.db == nil || len(records) == 0 {
		return records, nil
	}
	b := s.fileMetaBuffer
	b.mu.Lock()
	known := make(map[string]FileMetaRecord, len(b.lastFlushed))
	for k, v := range b.lastFlushed {
		known[k] = v
	}
	b.mu.Unlock()

	kept = records[:0]
	for _, record := range records {
		if last, ok := known[record.KeyHash]; ok {
			if s.reconcileUnchanged(&record, last) {
				unchanged = append(unchanged, effectiveFileMetaRow(record, last))
				continue
			}
			kept = append(kept, record)
			continue
		}
		existing, found, err := s.getFileMetaRow(ctx, "key_hash = ?", record.KeyHash)
		if err != nil || !found {
			if err != nil {
				log.Warn().Err(err).Str("key_hash", record.KeyHash).Msg("MySQL file meta dedup lookup failed, writing row")
			}
			kept = append(kept, record)
			continue
		}
		if s.reconcileUnchanged(&record, *existing) {
			// Remember what the database actually holds (the stored row with the
			// incoming record's timestamps), not the bare incoming record, so the
			// next identical write is recognised in memory.
			effective := *existing
			effective.UpdatedAt = record.UpdatedAt
			effective.LastAccessed = record.LastAccessed
			if record.UpstreamFetchedAt.After(effective.UpstreamFetchedAt) {
				effective.UpstreamFetchedAt = record.UpstreamFetchedAt
			}
			unchanged = append(unchanged, effective)
			continue
		}
		kept = append(kept, record)
	}
	return kept, unchanged
}

// effectiveFileMetaRow is the row the database is believed to hold after a
// write judged unchanged against a remembered row.
func effectiveFileMetaRow(record, remembered FileMetaRecord) FileMetaRecord {
	effective := remembered
	effective.UpdatedAt = record.UpdatedAt
	effective.LastAccessed = record.LastAccessed
	if record.UpstreamFetchedAt.After(effective.UpstreamFetchedAt) {
		effective.UpstreamFetchedAt = record.UpstreamFetchedAt
	}
	return effective
}

// reconcileUnchanged applies the configured stored-row merger to record (the
// V2/V3 plaintext-size preservation) and then reports whether writing it
// would leave the stored row informationally identical. record is modified in
// place so a kept row is written with the reconciled values.
func (s *Store) reconcileUnchanged(record *FileMetaRecord, stored FileMetaRecord) bool {
	if s != nil && s.mergeStoredRow != nil {
		s.mergeStoredRow(&stored, record)
	}
	return fileMetaWriteUnchanged(*record, stored)
}

// SetFileMetaStoredRowMerger installs the hook that reconciles a pending row
// with its stored counterpart at flush time. Pass nil to disable.
func (s *Store) SetFileMetaStoredRowMerger(merger func(stored, incoming *FileMetaRecord)) {
	if s == nil {
		return
	}
	s.mergeStoredRow = merger
}

// GetFileMetaByKeyHash returns the row for a key_hash regardless of is_active.
// It serves the write path: the no-op-write check must see an inactive row
// too, because the upsert would otherwise re-activate it (a real change).
func (s *Store) GetFileMetaByKeyHash(ctx context.Context, keyHash string) (*FileMetaRecord, bool, error) {
	if s == nil || s.db == nil {
		return nil, false, nil
	}
	return s.getFileMetaRow(ctx, "key_hash = ?", keyHash)
}

// fileMetaSelectColumns is the shared projection for the write-path row
// reader. It mirrors the read side so every column compared by
// FileMetaWriteEqual is populated.
const fileMetaSelectColumns = "SELECT key_hash, provider_host, original_path, encrypted_path, name, size, ciphertext_size, content_version, header_len, nonce_field, chunk_size, kdf_iterations, etag, content_type, raw_url, raw_url_auth_scope, sign, status_code, updated_at, last_accessed, upstream_fetched_at, is_active FROM "

// getFileMetaRow reads one file_meta row matching an arbitrary predicate.
// Decoding is shared with the read path (scanFileMetaInto) so the column
// order exists in exactly one place.
func (s *Store) getFileMetaRow(ctx context.Context, predicate string, args ...interface{}) (*FileMetaRecord, bool, error) {
	query := fileMetaSelectColumns + TableName("file_meta") + " WHERE " + predicate
	record, err := scanFileMetaRow(s.db.QueryRowContext(ctx, query, args...))
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, false, nil
		}
		return nil, false, err
	}
	return record, true, nil
}

func (s *Store) CleanupFileMeta(ctx context.Context, cutoff time.Time) error {
	if s == nil {
		return nil
	}
	return s.deleteExpiredFileMeta(ctx, cutoff)
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
		// Collation equality (sargable) + BINARY recheck: exact match, no full scan.
		query += " AND provider_host = ? AND BINARY provider_host = BINARY ?"
		args = append(args, filter.ProviderHost, filter.ProviderHost)
	}
	if filter.OriginalPath != "" {
		query += fileMetaByPathPredicates
		args = append(args, filter.OriginalPath, filter.OriginalPath)
	}
	if filter.PathPrefix != "" {
		// LIKE 'prefix%' is a range scan on idx_file_meta_path; the BINARY LIKE
		// recheck keeps case/accent-sensitive semantics for the rows it returns.
		query += " AND original_path LIKE ? ESCAPE '=' AND BINARY original_path LIKE BINARY ? ESCAPE '='"
		prefix := escapeLikePattern(filter.PathPrefix)
		args = append(args, prefix+"%", prefix+"%")
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
