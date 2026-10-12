package mysqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

type v3SQLDriver struct {
	queries []string
	args    [][]driver.NamedValue
}

func (d *v3SQLDriver) Open(string) (driver.Conn, error) { return &v3SQLConn{d}, nil }

type v3SQLConn struct{ d *v3SQLDriver }

func (c *v3SQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unsupported") }
func (c *v3SQLConn) Close() error                        { return nil }
func (c *v3SQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("unsupported") }
func (c *v3SQLConn) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	c.d.queries = append(c.d.queries, q)
	c.d.args = append(c.d.args, a)
	return driver.RowsAffected(1), nil
}
func (c *v3SQLConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	c.d.queries = append(c.d.queries, q)
	columns := strings.Split(strings.Split(strings.TrimPrefix(q, "SELECT "), " FROM ")[0], ", ")
	values := []driver.Value{"hash", "provider", "/plain", nil, nil, int64(12345), int64(16448), int64(3), int64(64), []byte("1234567890abcdef"), int64(4096), int64(1234), nil, nil, nil, "", nil, int64(200), time.Now(), time.Now(), nil, int64(1)}
	return &v3SQLRows{columns: columns, values: values}, nil
}

type v3SQLRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *v3SQLRows) Columns() []string { return r.columns }
func (r *v3SQLRows) Close() error      { return nil }
func (r *v3SQLRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

func TestV3FileMetaBufferPreservesGeometry(t *testing.T) {
	s := &Store{fileMetaBuffer: newFileMetaBuffer()}
	original := FileMetaRecord{ProviderHost: "provider", OriginalPath: "/plain", Size: 12345, CiphertextSize: 16448, ContentVersion: 3, HeaderLen: 64, NonceField: []byte("1234567890abcdef"), ChunkSize: 4096, KDFIterations: 1234}
	if err := s.UpsertFileMeta(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	original.NonceField[0] = 'x'
	if err := s.UpsertFileMeta(context.Background(), FileMetaRecord{ProviderHost: "provider", OriginalPath: "/plain", Size: 16448}); err != nil {
		t.Fatal(err)
	}
	records := s.fileMetaBuffer.drain()
	if len(records) != 1 || records[0].Size != 12345 || records[0].ChunkSize != 4096 || records[0].KDFIterations != 1234 || records[0].NonceField[0] != '1' {
		t.Fatalf("buffer lost metadata: %+v", records)
	}
	if err := s.UpsertFileMeta(context.Background(), records[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertFileMeta(context.Background(), FileMetaRecord{ProviderHost: "provider", OriginalPath: "/plain", ContentVersion: 3, NonceField: []byte("fedcba0987654321"), Size: 100}); err != nil {
		t.Fatal(err)
	}
	records = s.fileMetaBuffer.drain()
	if records[0].ChunkSize != 0 || records[0].KDFIterations != 0 || records[0].Size != 100 {
		t.Fatalf("replacement inherited geometry: %+v", records)
	}
}

func TestV3FileMetaSQLColumnsAndRoundTrip(t *testing.T) {
	d := &v3SQLDriver{}
	name := fmt.Sprintf("v3_sql_%d", trackingDriverID.Add(1))
	sql.Register(name, d)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{db: db}
	ctx := context.Background()
	if err := s.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"chunk_size", "kdf_iterations"} {
		create, alter := false, false
		for _, q := range d.queries {
			if strings.Contains(q, "CREATE TABLE IF NOT EXISTS "+TableName("file_meta")) && strings.Contains(q, column+" INT UNSIGNED NOT NULL DEFAULT 0") {
				create = true
			}
			if strings.Contains(q, "ADD COLUMN "+column+" INT UNSIGNED NOT NULL DEFAULT 0") {
				alter = true
			}
		}
		if !create || !alter {
			t.Fatalf("missing create/migration for %s", column)
		}
	}
	if err := s.upsertFileMeta(ctx, []FileMetaRecord{{ChunkSize: 4096, KDFIterations: 1234}, {ChunkSize: 8192, KDFIterations: 2345}}); err != nil {
		t.Fatal(err)
	}
	q := d.queries[len(d.queries)-1]
	a := d.args[len(d.args)-1]
	if strings.Count(q, "?") != 44 || len(a) != 44 {
		t.Fatalf("placeholders=%d args=%d", strings.Count(q, "?"), len(a))
	}
	if a[10].Value != int64(4096) || a[11].Value != int64(1234) || a[32].Value != int64(8192) || a[33].Value != int64(2345) {
		t.Fatalf("misaligned parameters: %+v", a)
	}
	if strings.Index(q, "chunk_size=IF") > strings.Index(q, "nonce_field=IF") {
		t.Fatal("nonce updated before replacement parameter guard")
	}
	got, ok, err := s.GetFileMeta(ctx, "provider", "/plain")
	if err != nil || !ok || got.ChunkSize != 4096 || got.KDFIterations != 1234 {
		t.Fatalf("get: %+v %v %v", got, ok, err)
	}
	list, err := s.ListFileMeta(ctx, FileMetaFilter{})
	if err != nil || len(list) != 1 || list[0].ChunkSize != 4096 || list[0].KDFIterations != 1234 {
		t.Fatalf("list: %+v %v", list, err)
	}
}
