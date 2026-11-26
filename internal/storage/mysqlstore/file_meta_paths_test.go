package mysqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedSQLDriver records every query with its args and answers each one with
// the rows its script returns, so the SQL shape and the Go-side row selection
// can both be verified without a live MySQL.
type scriptedSQLDriver struct {
	queries []string
	args    [][]driver.NamedValue
	script  func(query string, args []driver.NamedValue) [][]driver.Value
}

var scriptedDriverID atomic.Int64

func (d *scriptedSQLDriver) Open(string) (driver.Conn, error) { return &scriptedSQLConn{d}, nil }

type scriptedSQLConn struct{ d *scriptedSQLDriver }

func (c *scriptedSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unsupported") }
func (c *scriptedSQLConn) Close() error                        { return nil }
func (c *scriptedSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsupported") }
func (c *scriptedSQLConn) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	c.d.queries = append(c.d.queries, q)
	c.d.args = append(c.d.args, a)
	return driver.RowsAffected(1), nil
}
func (c *scriptedSQLConn) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	c.d.queries = append(c.d.queries, q)
	c.d.args = append(c.d.args, a)
	columns := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ", ")
	rows := c.d.script(q, a)
	return &scriptedSQLRows{columns: columns, rows: rows}, nil
}

type scriptedSQLRows struct {
	columns []string
	rows    [][]driver.Value
	pos     int
}

func (r *scriptedSQLRows) Columns() []string { return r.columns }
func (r *scriptedSQLRows) Close() error      { return nil }
func (r *scriptedSQLRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.pos])
	r.pos++
	return nil
}

func newScriptedStore(t *testing.T, script func(query string, args []driver.NamedValue) [][]driver.Value) (*Store, *scriptedSQLDriver) {
	t.Helper()
	d := &scriptedSQLDriver{script: script}
	name := fmt.Sprintf("file_meta_scripted_%d", scriptedDriverID.Add(1))
	sql.Register(name, d)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Store{db: db}, d
}

// fileMetaRow builds one file_meta row in the SELECT column order used by the
// path lookups, applying the same coercion the real driver performs.
func fileMetaRow(originalPath string, contentVersion int64, rawURL *string, upstreamFetchedAt time.Time) []driver.Value {
	var raw interface{}
	if rawURL != nil {
		raw = *rawURL
	}
	return []driver.Value{
		"hash", "provider", originalPath, nil, nil, int64(1), int64(2), contentVersion, int64(0), []byte("nonce"), int64(0), int64(0),
		nil, nil, raw, "", nil, int64(200), time.Now(), time.Now(), upstreamFetchedAt, int64(1),
	}
}

func strPtr(s string) *string { return &s }

// argValues flattens driver.NamedValue args into their Go values.
func argValues(args []driver.NamedValue) []interface{} {
	out := make([]interface{}, 0, len(args))
	for _, a := range args {
		out = append(out, a.Value)
	}
	return out
}

// The single-path lookup must lead with a sargable collation equality and keep
// the BINARY recheck second; the old form wrapped the column in BINARY only,
// which forced a full table scan on every PROPFIND entry.
func TestGetFileMetaByPathPredicateIsSargable(t *testing.T) {
	store, d := newScriptedStore(t, func(string, []driver.NamedValue) [][]driver.Value {
		return [][]driver.Value{fileMetaRow("/enc/a.bin", 3, nil, time.Unix(100, 0))}
	})
	rec, ok, err := store.GetFileMetaByPath(context.Background(), "/enc/a.bin")
	if err != nil || !ok || rec == nil || rec.ContentVersion != 3 {
		t.Fatalf("get: %+v ok=%v err=%v", rec, ok, err)
	}
	q := d.queries[0]
	if strings.Count(q, "original_path = ? AND BINARY original_path = BINARY ?") != 1 {
		t.Fatalf("missing sargable predicate pair: %s", q)
	}
	if strings.Contains(q, "WHERE BINARY original_path = BINARY ?") {
		t.Fatalf("old full-scan predicate still present: %s", q)
	}
	if strings.Contains(q, "BINARY original_path = BINARY ? AND is_active") {
		t.Fatalf("BINARY predicate leads the WHERE clause: %s", q)
	}
	args := argValues(d.args[0])
	if len(args) != 2 || args[0] != "/enc/a.bin" || args[1] != "/enc/a.bin" {
		t.Fatalf("args=%v, want the path twice", args)
	}
	if !strings.Contains(q, "ORDER BY (raw_url IS NOT NULL AND raw_url <> '') DESC, upstream_fetched_at DESC LIMIT 1") {
		t.Fatalf("best-row ordering changed: %s", q)
	}
	if !strings.Contains(q, "is_active=1 AND content_version > 0") {
		t.Fatalf("eligibility predicates changed: %s", q)
	}
}

// ListFileMeta must use the same sargable shape for path and provider filters,
// and a plain LIKE (index range) followed by a BINARY LIKE for prefixes.
func TestListFileMetaPredicatesAreSargable(t *testing.T) {
	store, d := newScriptedStore(t, func(string, []driver.NamedValue) [][]driver.Value { return nil })
	_, err := store.ListFileMeta(context.Background(), FileMetaFilter{
		ProviderHost: "cdn.example",
		OriginalPath: "/enc/a.bin",
		PathPrefix:   "/enc/100%_x/",
	})
	if err != nil {
		t.Fatal(err)
	}
	q := d.queries[0]
	for _, want := range []string{
		" AND provider_host = ? AND BINARY provider_host = BINARY ?",
		" AND original_path = ? AND BINARY original_path = BINARY ?",
		" AND original_path LIKE ? ESCAPE '=' AND BINARY original_path LIKE BINARY ? ESCAPE '='",
	} {
		if !strings.Contains(q, want) {
			t.Fatalf("query lacks %q: %s", want, q)
		}
	}
	if !strings.Contains(q, " AND provider_host = ? AND BINARY provider_host = BINARY ?") {
		t.Fatalf("provider predicate pair missing: %s", q)
	}
	// Every BINARY equality must be the recheck half of a sargable pair: a
	// lone "BINARY col = BINARY ?" would hide the column from the index.
	where := q[strings.Index(q, "WHERE "):strings.Index(q, " ORDER BY")]
	if strings.Count(where, "BINARY provider_host = BINARY ?") != 1 || strings.Count(where, "BINARY original_path = BINARY ?") != 1 || strings.Count(where, "BINARY original_path LIKE BINARY ?") != 1 {
		t.Fatalf("BINARY recheck predicates missing: %s", where)
	}
	for _, pair := range []string{"provider_host = ? AND BINARY provider_host = BINARY ?", "original_path = ? AND BINARY original_path = BINARY ?", "original_path LIKE ? ESCAPE '=' AND BINARY original_path LIKE BINARY ? ESCAPE '='"} {
		if strings.Count(where, pair) != 1 {
			t.Fatalf("sargable pair %q missing: %s", pair, where)
		}
	}
	// Removing the paired rechecks must leave no BINARY predicate on the
	// filter columns at all (the cursor tiebreaker on key_hash is separate).
	stripped := strings.ReplaceAll(strings.ReplaceAll(where,
		" AND BINARY provider_host = BINARY ?", ""),
		" AND BINARY original_path = BINARY ?", "")
	stripped = strings.ReplaceAll(stripped, " AND BINARY original_path LIKE BINARY ? ESCAPE '='", "")
	if strings.Contains(stripped, "BINARY provider_host") || strings.Contains(stripped, "BINARY original_path") {
		t.Fatalf("unpaired BINARY predicate defeats the index: %s", stripped)
	}
	if strings.Contains(q, "WHERE BINARY ") {
		t.Fatalf("WHERE must not open with BINARY: %s", q)
	}
	args := argValues(d.args[0])
	wantPrefix := "/enc/100=%=_x/%"
	if len(args) < 6 || args[0] != "cdn.example" || args[1] != "cdn.example" || args[2] != "/enc/a.bin" || args[3] != "/enc/a.bin" || args[4] != wantPrefix || args[5] != wantPrefix {
		t.Fatalf("args=%v", args)
	}
}

// GetFileMetaByPaths: one IN (...) query per ~200 paths, each path bound three
// times (IN, collation equality, BINARY recheck), and the row returned for a
// path is the same one GetFileMetaByPath would pick.
func TestGetFileMetaByPathsChunksAndPicksBestRow(t *testing.T) {
	const n = 450 // 200 + 200 + 50
	paths := make([]string, 0, n)
	for i := 0; i < n; i++ {
		paths = append(paths, fmt.Sprintf("/enc/f%03d.bin", i))
	}
	store, d := newScriptedStore(t, func(q string, args []driver.NamedValue) [][]driver.Value {
		vals := argValues(args)
		if !strings.Contains(q, "original_path IN (") {
			t.Fatalf("batch query lacks IN: %s", q)
		}
		if strings.Count(q, "(original_path = ? AND BINARY original_path = BINARY ?)") != len(vals)/3 {
			t.Fatalf("per-path predicate count mismatch: %d placeholders-pairs vs %d args", strings.Count(q, "(original_path = ? AND BINARY original_path = BINARY ?)"), len(vals))
		}
		if strings.Contains(q, "WHERE BINARY original_path") || strings.Contains(q, "AND BINARY original_path IN") {
			t.Fatalf("batch query must not wrap the IN column in BINARY: %s", q)
		}
		// Chunk membership is the IN list = first third of args.
		inList := vals[:len(vals)/3]
		rows := [][]driver.Value{}
		for i, p := range inList {
			if p == "/enc/f001.bin" {
				// Two rows: an older one WITH a raw URL and a newer one without.
				// The raw-URL row must win, like GetFileMetaByPath's ORDER BY.
				rows = append(rows, fileMetaRow("/enc/f001.bin", 3, strPtr("https://cdn/old"), time.Unix(100, 0)))
				rows = append(rows, fileMetaRow("/enc/f001.bin", 3, nil, time.Unix(999, 0)))
				continue
			}
			if p == "/enc/f002.bin" {
				// Two raw-URL rows: the newer upstream_fetched_at must win.
				rows = append(rows, fileMetaRow("/enc/f002.bin", 3, strPtr("https://cdn/older"), time.Unix(100, 0)))
				rows = append(rows, fileMetaRow("/enc/f002.bin", 3, strPtr("https://cdn/newer"), time.Unix(200, 0)))
				continue
			}
			if p == "/enc/f003.bin" {
				// A row whose path differs only by case (the collation folded it
				// into the IN match) must be rejected by the exact recheck.
				rows = append(rows, fileMetaRow("/enc/F003.bin", 3, strPtr("https://cdn/case"), time.Unix(100, 0)))
				continue
			}
			if i%2 == 0 {
				rows = append(rows, fileMetaRow(p.(string), 3, nil, time.Unix(100, 0)))
			}
		}
		return rows
	})
	got, err := store.GetFileMetaByPaths(context.Background(), append(paths, paths[0], ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.queries) != 3 {
		t.Fatalf("queries=%d, want 3 chunks (200/200/50)", len(d.queries))
	}
	if n1, n2, n3 := len(d.args[0])/3, len(d.args[1])/3, len(d.args[2])/3; n1 != 200 || n2 != 200 || n3 != 50 {
		t.Fatalf("chunk path counts=%d/%d/%d, want 200/200/50", n1, n2, n3)
	}
	if r := got["/enc/f001.bin"]; r == nil || r.RawURL != "https://cdn/old" {
		t.Fatalf("raw-url row should win: %+v", r)
	}
	if r := got["/enc/f002.bin"]; r == nil || r.RawURL != "https://cdn/newer" {
		t.Fatalf("newest raw-url row should win: %+v", r)
	}
	if r, ok := got["/enc/f003.bin"]; ok {
		t.Fatalf("case-folded row must not answer for another path: %+v", r)
	}
	// Expected membership: every even path has a row; f001/f002 (odd) have
	// rows; f003 (odd) is rejected by the exact recheck; other odds have none.
	wantHits := 0
	for i := 0; i < n; i++ {
		if i%2 == 0 || i == 1 || i == 2 {
			wantHits++
		}
	}
	if len(got) != wantHits {
		t.Fatalf("hits=%d want %d", len(got), wantHits)
	}
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/enc/f%03d.bin", i)
		_, ok := got[p]
		if ok != (i%2 == 0 || i == 1 || i == 2) {
			t.Fatalf("%s membership=%v", p, ok)
		}
	}
}

func TestGetFileMetaByPathsEmptyAndNil(t *testing.T) {
	if _, err := (*Store)(nil).GetFileMetaByPaths(context.Background(), []string{"/a"}); err != nil {
		t.Fatal(err)
	}
	store, d := newScriptedStore(t, func(string, []driver.NamedValue) [][]driver.Value { return nil })
	got, err := store.GetFileMetaByPaths(context.Background(), nil)
	if err != nil || got == nil || len(got) != 0 || len(d.queries) != 0 {
		t.Fatalf("got=%v err=%v queries=%d", got, err, len(d.queries))
	}
}
