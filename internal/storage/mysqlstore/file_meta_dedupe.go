package mysqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// StableProviderHostSentinel is the fallback provider_host used for file_meta
// row keys when no alist origin is configured.
//
// Background: the row key was md5(provider_host "::" original_path) where
// provider_host was the host of the raw download URL observed at write time.
// Raw URLs rotate between CDN / direct / WebDAV hosts, so one file accumulated
// up to three rows. Keying on a host that is stable per deployment (the alist
// origin) collapses every future write for a path onto one row while keeping
// the key-hash lookup GetFileMeta(ProviderKey(cfg.GetAlistURL()), path) —
// used by the size resolver and probe scheduler — hitting that row directly.
const StableProviderHostSentinel = "path"

// fileMetaDedupeBatchPaths is the number of duplicate paths one migration
// round handles. Each path is two short indexed statements, so the work is
// sliced finely and never blocks request serving.
const fileMetaDedupeBatchPaths = 500

// fileMetaDedupeInitialDelay lets schema setup, cleanup and the first request
// burst finish before the background migration starts scanning.
const fileMetaDedupeInitialDelay = 10 * time.Second

// FileMetaDedupeSummary is logged once when the migration finishes.
type FileMetaDedupeSummary struct {
	Paths           int
	RowsDeactivated int
	RowsRewritten   int
	Batches         int
	Duration        time.Duration
}

// SetStableProviderHost fixes the provider_host used for every NEW file_meta
// row key. Call it once during wiring, before requests are served; an empty
// host selects the sentinel. It returns the effective host.
func (s *Store) SetStableProviderHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		host = StableProviderHostSentinel
	}
	if s != nil {
		s.stableProviderHost = host
	}
	return host
}

// StableProviderHost reports the host new rows are keyed on.
func (s *Store) StableProviderHost() string {
	if s == nil || s.stableProviderHost == "" {
		return StableProviderHostSentinel
	}
	return s.stableProviderHost
}

// StableFileMetaKeyHash is the primary key every new file_meta row uses.
func (s *Store) StableFileMetaKeyHash(originalPath string) string {
	return KeyHash(s.StableProviderHost(), originalPath)
}

// RunFileMetaDedupe collapses duplicate active rows per original_path onto
// the stable key. It is idempotent: a second run finds no duplicate paths.
//
// For each original_path with more than one active row the survivor is
//  1. a row with a non-empty raw_url (newest upstream_fetched_at among
//     those), because signed URLs are the only non-derivable content;
//  2. else the row with the newest upstream_fetched_at / updated_at;
//  3. ties broken by the most complete content metadata, then key_hash.
//
// If a row already lives under the stable key it is kept as is. Otherwise the
// survivor is re-written under the stable key through the regular upsert
// (raw_url / geometry preserved; an existing inactive stable row is merged,
// not clobbered) and every legacy row for the path is marked is_active=0.
// Rows are never deleted, so the migration is reversible (see PR notes).
//
// Reads do not wait for it: GetFileMetaByPath ignores provider_host and orders
// by the same preference, so readers observe the same row before and after.
func (s *Store) RunFileMetaDedupe(ctx context.Context) (FileMetaDedupeSummary, error) {
	summary := FileMetaDedupeSummary{}
	if s == nil || s.db == nil {
		return summary, nil
	}
	stableHost := s.StableProviderHost()
	started := time.Now()

	// Keyset cursor over original_path: bounded statements, and rows written
	// while the migration runs cannot make the scan drift.
	lastPath := ""
	for {
		if ctx.Err() != nil {
			return summary, ctx.Err()
		}
		paths, err := s.listDuplicateFileMetaPaths(ctx, lastPath, fileMetaDedupeBatchPaths)
		if err != nil {
			return summary, err
		}
		if len(paths) == 0 {
			break
		}
		summary.Batches++
		for _, p := range paths {
			deactivated, rewritten, err := s.dedupeFileMetaPath(ctx, stableHost, p)
			if err != nil {
				return summary, err
			}
			if deactivated > 0 || rewritten {
				summary.Paths++
			}
			summary.RowsDeactivated += deactivated
			if rewritten {
				summary.RowsRewritten++
			}
		}
		lastPath = paths[len(paths)-1]
		if len(paths) < fileMetaDedupeBatchPaths {
			break
		}
	}
	summary.Duration = time.Since(started)
	return summary, nil
}

// listDuplicateFileMetaPaths returns up to limit distinct active paths having
// more than one active row, ordered by path, strictly after the cursor.
//
// The table's default utf8mb4 collation is case-insensitive, so GROUP BY
// original_path would fold "/A.mp4" and "/a.mp4" into one group and leave
// one of them unvisited. Grouping by BINARY original_path keeps each exact
// path its own group, and the per-path survivor query re-checks with BINARY.
//
// The cursor predicate must live in WHERE: MySQL rejects a bare column in
// HAVING ("Unknown column in 'having clause'"), so appending it after the
// HAVING clause would make every batch after the first fail. Inside WHERE the
// plain collation comparison lets the path prefix index range-scan from the
// cursor and the BINARY recheck keeps the ordering exact.
func (s *Store) listDuplicateFileMetaPaths(ctx context.Context, after string, limit int) ([]string, error) {
	query := "SELECT BINARY original_path FROM " + TableName("file_meta") + " WHERE is_active=1"
	args := []interface{}{}
	if after != "" {
		query += " AND original_path > ? AND BINARY original_path > BINARY ?"
		args = append(args, after, after)
	}
	query += " GROUP BY BINARY original_path HAVING COUNT(*) > 1 ORDER BY BINARY original_path LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var paths []string
	for rows.Next() {
		var p []byte
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		paths = append(paths, string(p))
	}
	return paths, rows.Err()
}

// dedupeFileMetaPath collapses the active rows of one path. It returns the
// number of rows deactivated and whether a row was written under the stable
// key. When the path no longer has duplicates (concurrent write / already
// migrated) it is a no-op.
//
// The rows of one path typically hold complementary data: a size-only row
// from the resolver (raw_url/sign, content_version=0) and a geometry row
// from the probe (content_version/nonce/header/chunk/kdf). The survivor is
// therefore MERGED: the best row (see survivor order) provides the base and
// every other row lends the column families the base lacks, so deactivating
// the duplicates cannot drop confirmed geometry (which GetFileMetaByPath
// requires, content_version > 0) or the only signed-URL copy.
func (s *Store) dedupeFileMetaPath(ctx context.Context, stableHost, originalPath string) (int, bool, error) {
	// Survivor order: raw_url present first (newest fetch among those), then
	// newest fetch/update time, then the most complete content metadata.
	rows, err := s.db.QueryContext(ctx, fileMetaSelectColumns+TableName("file_meta")+
		" WHERE BINARY original_path = BINARY ? AND is_active=1"+
		" ORDER BY (raw_url IS NOT NULL AND raw_url <> '') DESC, upstream_fetched_at DESC, updated_at DESC,"+
		" (content_version > 0) DESC, (nonce_field IS NOT NULL AND LENGTH(nonce_field) > 0) DESC,"+
		" (ciphertext_size > 0) DESC, (chunk_size > 0) DESC, (kdf_iterations > 0) DESC, (encrypted_path <> '') DESC,"+
		" key_hash ASC", originalPath)
	if err != nil {
		return 0, false, err
	}
	records, err := scanAllFileMetaRows(rows)
	_ = rows.Close()
	if err != nil {
		return 0, false, err
	}
	if len(records) <= 1 {
		return 0, false, nil
	}

	stableKey := KeyHash(stableHost, originalPath)
	losers := fileMetaKeyHashesExcept(records, stableKey)
	if len(losers) == 0 {
		return 0, false, nil
	}

	// Base: an existing stable row if present (never clobbered, only
	// completed), else the best legacy row. Then fold the others in.
	base := records[0]
	if existing, ok := fileMetaFindRow(records, stableKey); ok {
		base = existing
	}
	merged := mergeFileMetaRows(base, records)
	// A write is needed when the stable row does not exist yet (re-key) or
	// when merging the duplicates completed it with new information.
	needsWrite := !fileMetaHasRow(records, stableKey) || !fileMetaMetaEqualForMigration(merged, base)
	if needsWrite {
		merged.ProviderHost = stableHost
		merged.KeyHash = stableKey
		merged.OriginalPath = originalPath
		merged.Active = true
		merged.explicitFetch = false
		// Written synchronously (not via the flush buffer) so it lands
		// before the legacy rows are deactivated.
		if err := s.upsertFileMeta(ctx, []FileMetaRecord{merged}); err != nil {
			return 0, false, err
		}
	}

	// Deactivate legacy rows only, and only while still active, so a
	// concurrent write that re-keyed a row is left alone.
	query := "UPDATE " + TableName("file_meta") + " SET is_active=0 WHERE is_active=1 AND key_hash <> ? AND key_hash IN (" +
		strings.TrimRight(strings.Repeat("?,", len(losers)), ",") + ")"
	args := make([]interface{}, 0, len(losers)+1)
	args = append(args, stableKey)
	for _, k := range losers {
		args = append(args, k)
	}
	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, needsWrite, err
	}
	n, _ := res.RowsAffected()
	return int(n), needsWrite, nil
}

// mergeFileMetaRows completes base with column families it lacks from the
// other rows, in survivor order. Each field is taken from the first row that
// has it, so the result carries the union of the duplicates' information.
//
// Size is the one field that needs care: a row with confirmed geometry
// (content_version > 0) records the PLAINTEXT size, while a size-only row may
// have recorded the CIPHERTEXT length. When the base lacks geometry and a
// geometry row exists, the geometry row's plaintext size wins.
func mergeFileMetaRows(base FileMetaRecord, records []FileMetaRecord) FileMetaRecord {
	out := base
	// Geometry family: take the first row that has confirmed content
	// metadata, as a whole (version, nonce, header, chunk, kdf, ciphertext
	// size and its plaintext size), unless the base already has it.
	if out.ContentVersion <= 0 {
		for _, r := range records {
			if r.ContentVersion > 0 {
				out.ContentVersion = r.ContentVersion
				out.NonceField = append([]byte(nil), r.NonceField...)
				out.HeaderLen = r.HeaderLen
				out.ChunkSize = r.ChunkSize
				out.KDFIterations = r.KDFIterations
				out.CiphertextSize = r.CiphertextSize
				if r.Size > 0 || (r.ContentVersion == 3 && r.Size == 0) {
					// Confirmed plaintext size (V3: an empty file is a real
					// observation, ciphertext_size > 0 proves it).
					out.Size = r.Size
				}
				break
			}
		}
	} else if out.Size <= 0 {
		for _, r := range records {
			if r.ContentVersion == out.ContentVersion && bytes.Equal(r.NonceField, out.NonceField) && r.Size > 0 {
				out.Size = r.Size
				break
			}
		}
	}
	// URL family, as a unit (url + scope + sign + fetch time).
	if out.RawURL == "" {
		for _, r := range records {
			if r.RawURL != "" {
				out.RawURL = r.RawURL
				out.RawURLAuthScope = r.RawURLAuthScope
				out.Sign = r.Sign
				out.UpstreamFetchedAt = r.UpstreamFetchedAt
				break
			}
		}
	} else if out.Sign == "" {
		for _, r := range records {
			if r.RawURL == out.RawURL && r.Sign != "" {
				out.Sign = r.Sign
				break
			}
		}
	}
	if out.EncryptedPath == "" {
		for _, r := range records {
			if r.EncryptedPath != "" {
				out.EncryptedPath = r.EncryptedPath
				break
			}
		}
	}
	if out.Name == "" {
		for _, r := range records {
			if r.Name != "" {
				out.Name = r.Name
				break
			}
		}
	}
	if out.ETag == "" {
		for _, r := range records {
			if r.ETag != "" {
				out.ETag = r.ETag
				break
			}
		}
	}
	if out.ContentType == "" {
		for _, r := range records {
			if r.ContentType != "" {
				out.ContentType = r.ContentType
				break
			}
		}
	}
	if out.StatusCode == 0 {
		for _, r := range records {
			if r.StatusCode != 0 {
				out.StatusCode = r.StatusCode
				break
			}
		}
	}
	// Freshest timestamps.
	for _, r := range records {
		if r.UpdatedAt.After(out.UpdatedAt) {
			out.UpdatedAt = r.UpdatedAt
		}
		if r.LastAccessed.After(out.LastAccessed) {
			out.LastAccessed = r.LastAccessed
		}
		if r.UpstreamFetchedAt.After(out.UpstreamFetchedAt) {
			out.UpstreamFetchedAt = r.UpstreamFetchedAt
		}
	}
	return out
}

// fileMetaMetaEqualForMigration reports whether a and b are equal in every
// information-bearing column (timestamps excluded): if so the merged row
// need not be written.
func fileMetaMetaEqualForMigration(a, b FileMetaRecord) bool {
	a.explicitFetch, b.explicitFetch = false, false
	return FileMetaWriteEqual(a, b)
}

func fileMetaKeyHashesExcept(records []FileMetaRecord, except string) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		if r.KeyHash != except {
			out = append(out, r.KeyHash)
		}
	}
	return out
}

func fileMetaHasRow(records []FileMetaRecord, key string) bool {
	_, ok := fileMetaFindRow(records, key)
	return ok
}

func fileMetaFindRow(records []FileMetaRecord, key string) (FileMetaRecord, bool) {
	for _, r := range records {
		if r.KeyHash == key {
			return r, true
		}
	}
	return FileMetaRecord{}, false
}

// scanAllFileMetaRows reads every row of a write-path projection. The
// per-row decoding lives in scanFileMetaInto so this stays in lockstep with
// the read path's column order.
func scanAllFileMetaRows(rows *sql.Rows) ([]FileMetaRecord, error) {
	var records []FileMetaRecord
	for rows.Next() {
		var record FileMetaRecord
		if err := scanFileMetaInto(rows, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// StartFileMetaDedupe launches the duplicate-path migration in the background
// on the store's loop context, so shutdown cancels and joins it. It must be
// called after SetStableProviderHost (the server wiring does both, in order).
// It never blocks startup or request serving; failures are logged, not fatal,
// and the next start simply resumes (the migration is idempotent). Calling it
// more than once is a no-op.
func (s *Store) StartFileMetaDedupe() {
	if s == nil || s.db == nil || s.loopsCtx == nil {
		return
	}
	if !s.dedupeStarted.CompareAndSwap(false, true) {
		return
	}
	ctx := s.loopsCtx
	s.loopWG.Add(1)
	go func() {
		defer s.loopWG.Done()
		select {
		case <-ctx.Done():
			return
		case <-time.After(fileMetaDedupeInitialDelay):
		}
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
		defer cancel()
		summary, err := s.RunFileMetaDedupe(runCtx)
		if err != nil {
			if ctx.Err() == nil {
				log.Warn().Err(err).Msg("MySQL file_meta duplicate-path migration stopped (idempotent, resumes on next start)")
			}
			return
		}
		log.Info().
			Int("paths", summary.Paths).
			Int("rows_deactivated", summary.RowsDeactivated).
			Int("rows_rewritten", summary.RowsRewritten).
			Int("batches", summary.Batches).
			Dur("duration", summary.Duration).
			Msg("MySQL file_meta duplicate-path migration complete")
	}()
}
