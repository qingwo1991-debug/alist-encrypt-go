package mysqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeMetaDriver is an in-memory stand-in for MySQL that stores file_meta rows
// keyed by key_hash and recognises the handful of statements the write path,
// the dedup filter and the duplicate-path migration issue. It implements the
// subset of ON DUPLICATE KEY UPDATE semantics those paths rely on (geometry
// guards, raw_url/sign "keep when incoming is empty") so tests can assert on
// the resulting rows rather than on SQL text.
type fakeMetaDriver struct {
	mu            sync.Mutex
	rows          map[string]FileMetaRecord // keyed by key_hash
	inserts       int                       // number of INSERT ... ON DUPLICATE KEY statements executed
	updates       int
	failSel       bool // make the migration's duplicate-path SELECT return an error
	failKeyLookup bool // make the dedup row SELECT return an error
	order         []string
}

type fakeMetaConn struct{ d *fakeMetaDriver }

func (d *fakeMetaDriver) Open(string) (driver.Conn, error) { return &fakeMetaConn{d}, nil }

func (c *fakeMetaConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unsupported") }
func (c *fakeMetaConn) Close() error                        { return nil }
func (c *fakeMetaConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsupported") }

func (c *fakeMetaConn) Ping(context.Context) error { return nil }

func (d *fakeMetaDriver) snapshot() []FileMetaRecord {
	out := make([]FileMetaRecord, 0, len(d.rows))
	for _, r := range d.rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyHash < out[j].KeyHash })
	return out
}

func (c *fakeMetaConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	d := c.d
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case strings.Contains(q, "GROUP BY BINARY original_path HAVING COUNT(*) > 1"):
		if !strings.Contains(q, "ORDER BY BINARY original_path") {
			return nil, errors.New("fakeMetaDriver: duplicate-path scan must group and order by BINARY original_path")
		}
		// Regression guard: the cursor must filter rows in WHERE. Appending it
		// after HAVING is rejected by MySQL ("Unknown column in 'having clause'"),
		// which silently stopped the migration after its first batch.
		if after := args[0].Value; isStringArg(after) && !strings.Contains(q, "WHERE is_active=1 AND original_path > ? AND BINARY original_path > BINARY ? GROUP BY") {
			return nil, errors.New("fakeMetaDriver: duplicate-path cursor must be a WHERE predicate before GROUP BY")
		}
		if d.failSel {
			return nil, errors.New("boom")
		}
		counts := map[string]int{}
		for _, r := range d.rows {
			if r.Active {
				counts[r.OriginalPath]++
			}
		}
		paths := make([]string, 0)
		for p, n := range counts {
			if n > 1 {
				paths = append(paths, p)
			}
		}
		sort.Strings(paths)
		// Args: [cursor, cursor, limit] — the cursor is bound twice (collation
		// range plus BINARY recheck), so apply each string arg; filtering by the
		// same value twice is idempotent.
		limit := 500
		for _, a := range args {
			switch v := a.Value.(type) {
			case string:
				filtered := paths[:0]
				for _, p := range paths {
					if p > v {
						filtered = append(filtered, p)
					}
				}
				paths = filtered
			case int64:
				limit = int(v)
			case int:
				limit = v
			}
		}
		if len(paths) > limit {
			paths = paths[:limit]
		}
		return &fakeMetaRows{cols: []string{"original_path"}, rows: toRows(paths)}, nil
	case strings.Contains(q, "WHERE BINARY original_path = BINARY ? AND is_active=1"):
		path := args[0].Value.(string)
		var recs []FileMetaRecord
		for _, r := range d.rows {
			if r.Active && r.OriginalPath == path {
				recs = append(recs, r)
			}
		}
		// Survivor order mirrors the SQL: raw_url present first, then
		// upstream_fetched_at, updated_at, completeness, key_hash.
		sort.Slice(recs, func(i, j int) bool {
			a, b := recs[i], recs[j]
			if (a.RawURL != "") != (b.RawURL != "") {
				return a.RawURL != ""
			}
			if !a.UpstreamFetchedAt.Equal(b.UpstreamFetchedAt) {
				return a.UpstreamFetchedAt.After(b.UpstreamFetchedAt)
			}
			if !a.UpdatedAt.Equal(b.UpdatedAt) {
				return a.UpdatedAt.After(b.UpdatedAt)
			}
			if (a.ContentVersion > 0) != (b.ContentVersion > 0) {
				return a.ContentVersion > 0
			}
			if (len(a.NonceField) > 0) != (len(b.NonceField) > 0) {
				return len(a.NonceField) > 0
			}
			if (a.CiphertextSize > 0) != (b.CiphertextSize > 0) {
				return a.CiphertextSize > 0
			}
			if (a.ChunkSize > 0) != (b.ChunkSize > 0) {
				return a.ChunkSize > 0
			}
			if (a.KDFIterations > 0) != (b.KDFIterations > 0) {
				return a.KDFIterations > 0
			}
			if (a.EncryptedPath != "") != (b.EncryptedPath != "") {
				return a.EncryptedPath != ""
			}
			return a.KeyHash < b.KeyHash
		})
		return &fakeMetaRows{cols: fileMetaColumns, rows: recsToRows(recs)}, nil
	case strings.Contains(q, "WHERE key_hash = ?"):
		if d.failKeyLookup {
			return nil, errors.New("boom")
		}
		key := args[0].Value.(string)
		r, ok := d.rows[key]
		if !ok {
			return &fakeMetaRows{cols: fileMetaColumns}, nil
		}
		return &fakeMetaRows{cols: fileMetaColumns, rows: recsToRows([]FileMetaRecord{r})}, nil
	}
	return nil, fmt.Errorf("fakeMetaDriver: unsupported query: %s", q)
}

var fileMetaColumns = []string{"key_hash", "provider_host", "original_path", "encrypted_path", "name", "size", "ciphertext_size", "content_version", "header_len", "nonce_field", "chunk_size", "kdf_iterations", "etag", "content_type", "raw_url", "raw_url_auth_scope", "sign", "status_code", "updated_at", "last_accessed", "upstream_fetched_at", "is_active"}

func recsToRows(recs []FileMetaRecord) [][]driver.Value {
	out := make([][]driver.Value, 0, len(recs))
	for _, r := range recs {
		out = append(out, []driver.Value{
			r.KeyHash, r.ProviderHost, r.OriginalPath, nullableStr(r.EncryptedPath), nullableStr(r.Name),
			r.Size, r.CiphertextSize, int64(r.ContentVersion), r.HeaderLen, nullableBytes(r.NonceField),
			int64(r.ChunkSize), int64(r.KDFIterations), nullableStr(r.ETag), nullableStr(r.ContentType),
			nullableStr(r.RawURL), r.RawURLAuthScope, nullableStr(r.Sign), int64(r.StatusCode),
			r.UpdatedAt, r.LastAccessed, nullableTime(r.UpstreamFetchedAt), boolToInt(r.Active),
		})
	}
	return out
}

func toRows(paths []string) [][]driver.Value {
	out := make([][]driver.Value, 0, len(paths))
	for _, p := range paths {
		out = append(out, []driver.Value{[]byte(p)})
	}
	return out
}

func nullableStr(s string) driver.Value {
	if s == "" {
		return nil
	}
	return s
}

func nullableBytes(b []byte) driver.Value {
	if len(b) == 0 {
		return nil
	}
	return b
}

func (c *fakeMetaConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	d := c.d
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case strings.HasPrefix(q, "CREATE") || strings.HasPrefix(q, "ALTER"):
		return driver.RowsAffected(0), nil
	case strings.Contains(q, "UPDATE ") && strings.Contains(q, "SET is_active=0"):
		d.updates++
		stable := args[0].Value.(string)
		n := 0
		for _, a := range args[1:] {
			k := a.Value.(string)
			if r, ok := d.rows[k]; ok && k != stable && r.Active {
				r.Active = false
				d.rows[k] = r
				n++
			}
		}
		return driver.RowsAffected(int64(n)), nil
	case strings.Contains(q, "INSERT INTO ") && strings.Contains(q, TableName("file_meta")) && strings.Contains(q, "ON DUPLICATE KEY UPDATE"):
		d.inserts++
		const cols = 22
		if len(args)%cols != 0 {
			return nil, fmt.Errorf("fakeMetaDriver: bad arg count %d", len(args))
		}
		for i := 0; i < len(args); i += cols {
			v := func(j int) driver.Value { return args[i+j].Value }
			incoming := FileMetaRecord{
				KeyHash:         v(0).(string),
				ProviderHost:    v(1).(string),
				OriginalPath:    v(2).(string),
				Size:            v(5).(int64),
				CiphertextSize:  v(6).(int64),
				ContentVersion:  int(v(7).(int64)),
				HeaderLen:       v(8).(int64),
				ChunkSize:       uint32(v(10).(int64)),
				KDFIterations:   uint32(v(11).(int64)),
				RawURLAuthScope: v(16).(string),
				StatusCode:      int(v(14).(int64)),
				UpdatedAt:       v(19).(time.Time),
				LastAccessed:    v(18).(time.Time),
				Active:          v(21).(int64) == 1,
			}
			incoming.EncryptedPath = strOr(v(3))
			incoming.Name = strOr(v(4))
			incoming.ETag = strOr(v(12))
			incoming.ContentType = strOr(v(13))
			incoming.RawURL = strOr(v(15))
			incoming.Sign = strOr(v(17))
			incoming.NonceField = bytesOr(v(9))
			if t, ok := v(20).(time.Time); ok {
				incoming.UpstreamFetchedAt = t
			}
			merged := applyUpsertSemantics(d.rows[incoming.KeyHash], incoming)
			d.rows[incoming.KeyHash] = merged
			d.order = append(d.order, incoming.KeyHash)
		}
		return driver.RowsAffected(1), nil
	}
	return nil, fmt.Errorf("fakeMetaDriver: unsupported exec: %s", q)
}

func strOr(v driver.Value) string {
	s, _ := v.(string)
	return s
}

func bytesOr(v driver.Value) []byte {
	b, _ := v.([]byte)
	return append([]byte(nil), b...)
}

// applyUpsertSemantics mirrors the ON DUPLICATE KEY UPDATE clause of
// upsertFileMeta for the columns the tests depend on.
func applyUpsertSemantics(existing, in FileMetaRecord) FileMetaRecord {
	if !existing.Active && existing.KeyHash == "" {
		return in
	}
	out := in
	out.ProviderHost = existing.ProviderHost // never updated by the clause
	if in.EncryptedPath == "" {
		out.EncryptedPath = existing.EncryptedPath
	}
	if in.Name == "" {
		out.Name = existing.Name
	}
	nonceChanged := len(in.NonceField) > 0 && !bytes.Equal(in.NonceField, existing.NonceField)
	versionChanged := in.ContentVersion > 0 && in.ContentVersion != existing.ContentVersion
	replacement := nonceChanged || versionChanged
	if in.ContentVersion == 0 && (len(in.NonceField) == 0 || bytes.Equal(in.NonceField, existing.NonceField)) {
		if (existing.ContentVersion == 2 && existing.HeaderLen > 0 && (in.Size == existing.CiphertextSize || in.Size == existing.Size+existing.HeaderLen)) ||
			(existing.ContentVersion == 3 && existing.CiphertextSize > 0 && in.Size == existing.CiphertextSize) {
			out.Size = existing.Size
		}
	}
	if replacement {
		out.CiphertextSize, out.HeaderLen, out.ChunkSize, out.KDFIterations = in.CiphertextSize, in.HeaderLen, in.ChunkSize, in.KDFIterations
	} else {
		if in.CiphertextSize <= 0 {
			out.CiphertextSize = existing.CiphertextSize
		}
		if in.HeaderLen <= 0 {
			out.HeaderLen = existing.HeaderLen
		}
		if in.ChunkSize == 0 {
			out.ChunkSize = existing.ChunkSize
		}
		if in.KDFIterations == 0 {
			out.KDFIterations = existing.KDFIterations
		}
	}
	if in.ContentVersion > 0 {
		out.ContentVersion = in.ContentVersion
	} else {
		out.ContentVersion = existing.ContentVersion
	}
	if len(in.NonceField) > 0 {
		out.NonceField = in.NonceField
	} else {
		out.NonceField = existing.NonceField
	}
	if in.RawURL == "" {
		out.RawURL = existing.RawURL
		out.RawURLAuthScope = existing.RawURLAuthScope
	}
	if in.Sign == "" {
		out.Sign = existing.Sign
	}
	// Mirror the IF(VALUES(x) <> '', ...) rules for etag/content_type and
	// the IF(VALUES(status_code) <> 0, ...) rule for status_code.
	if in.ETag == "" {
		out.ETag = existing.ETag
	}
	if in.ContentType == "" {
		out.ContentType = existing.ContentType
	}
	if in.StatusCode == 0 {
		out.StatusCode = existing.StatusCode
	}
	if in.UpstreamFetchedAt.IsZero() {
		out.UpstreamFetchedAt = existing.UpstreamFetchedAt
	}
	out.Active = in.Active || existing.Active
	return out
}

type fakeMetaRows struct {
	cols []string
	rows [][]driver.Value
	i    int
}

func (r *fakeMetaRows) Columns() []string { return r.cols }
func (r *fakeMetaRows) Close() error      { return nil }
func (r *fakeMetaRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}

// newFakeMetaStore opens a Store backed by the fake driver. No goroutines are
// started; flushes are driven explicitly by the test.
func newFakeMetaStore(t *testing.T) (*Store, *fakeMetaDriver) {
	t.Helper()
	d := &fakeMetaDriver{rows: map[string]FileMetaRecord{}}
	return newFakeMetaStoreOver(t, d)
}

// newFakeMetaStoreOver returns a fresh Store (empty memory maps, i.e. a
// "restarted" process) over the same underlying database.
func newFakeMetaStoreOver(t *testing.T, d *fakeMetaDriver) (*Store, *fakeMetaDriver) {
	t.Helper()
	name := fmt.Sprintf("mysqlstore_fake_meta_%d", trackingDriverID.Add(1))
	sql.Register(name, d)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Store{db: db, fileMetaBuffer: newFileMetaBuffer()}, d
}

func mustUpsert(t *testing.T, s *Store, rec FileMetaRecord) {
	t.Helper()
	rec.Active = true
	if err := s.UpsertFileMeta(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
}

// flush is the synchronous equivalent of Store.flushBuffers for file meta.
func flushMeta(t *testing.T, s *Store) {
	t.Helper()
	records := s.fileMetaBuffer.drain()
	if len(records) == 0 {
		return
	}
	kept, unchanged := s.filterUnchangedFileMeta(context.Background(), records)
	s.fileMetaBuffer.rememberFlushed(unchanged)
	if len(kept) > 0 {
		if err := s.upsertFileMeta(context.Background(), kept); err != nil {
			t.Fatal(err)
		}
		s.fileMetaBuffer.markFlushed(kept)
	}
}

func activeRows(d *fakeMetaDriver, path string) []FileMetaRecord {
	var out []FileMetaRecord
	for _, r := range d.rows {
		if r.Active && r.OriginalPath == path {
			out = append(out, r)
		}
	}
	return out
}

func isStringArg(v driver.Value) bool {
	_, ok := v.(string)
	return ok
}
