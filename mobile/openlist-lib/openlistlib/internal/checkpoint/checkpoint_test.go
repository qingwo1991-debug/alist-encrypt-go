package checkpoint

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

// A database/sql adapter exercises actual Rows scanning, without a mock library.
type fixture struct {
	values           []driver.Value
	queryErr, rowErr error
	query            string
	closed           bool
	cancel           context.CancelFunc
}

func (f *fixture) Connect(context.Context) (driver.Conn, error) { return f, nil }
func (f *fixture) Driver() driver.Driver                        { return fixtureDriver{} }

type fixtureDriver struct{}

func (fixtureDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }
func (f *fixture) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected Prepare") }
func (f *fixture) Close() error                        { return nil }
func (f *fixture) Begin() (driver.Tx, error)           { return nil, errors.New("unexpected Begin") }
func (f *fixture) QueryContext(ctx context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	f.query = q
	if f.cancel != nil {
		f.cancel()
		return nil, ctx.Err()
	}
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return &fixtureRows{f: f}, nil
}

type fixtureRows struct {
	f    *fixture
	read bool
}

func (*fixtureRows) Columns() []string { return []string{"busy", "log", "checkpointed"} }
func (r *fixtureRows) Close() error    { r.f.closed = true; return nil }
func (r *fixtureRows) Next(dest []driver.Value) error {
	if r.read {
		return r.f.rowErrOrEOF()
	}
	r.read = true
	if r.f.values == nil {
		return r.f.rowErrOrEOF()
	}
	copy(dest, r.f.values)
	return nil
}
func (f *fixture) rowErrOrEOF() error {
	if f.rowErr != nil {
		return f.rowErr
	}
	return io.EOF
}

func TestRun(t *testing.T) {
	queryErr := errors.New("query failed")
	rowErr := errors.New("rows failed")
	for _, tt := range []struct {
		name                      string
		values                    []driver.Value
		queryErr, rowErr, wantErr error
		complete                  bool
	}{
		{"busy", []driver.Value{int64(1), int64(8), int64(3)}, nil, nil, ErrIncomplete, false},
		{"passive partial without busy", []driver.Value{int64(0), int64(8), int64(3)}, nil, nil, ErrIncomplete, false},
		{"full", []driver.Value{int64(0), int64(8), int64(8)}, nil, nil, nil, true},
		{"empty WAL", []driver.Value{int64(0), int64(0), int64(0)}, nil, nil, nil, true},
		{"no WAL", []driver.Value{int64(0), int64(-1), int64(-1)}, nil, nil, ErrNoWAL, false},
		{"query error", nil, queryErr, nil, queryErr, false},
		{"row error", nil, nil, rowErr, rowErr, false},
		{"error after row", []driver.Value{int64(0), int64(8), int64(8)}, nil, rowErr, rowErr, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := &fixture{values: tt.values, queryErr: tt.queryErr, rowErr: tt.rowErr}
			db := sql.OpenDB(f)
			defer db.Close()
			got, err := Run(context.Background(), "sqlite", db, "PASSIVE")
			if !errors.Is(err, tt.wantErr) || got.Complete != tt.complete {
				t.Fatalf("result=%+v err=%v want=%v", got, err, tt.wantErr)
			}
			if f.query != "PRAGMA wal_checkpoint(PASSIVE)" {
				t.Fatalf("query=%q", f.query)
			}
			if tt.values != nil && tt.rowErr == nil && got.Busy != int(tt.values[0].(int64)) {
				t.Fatalf("lost counts: %+v", got)
			}
			if tt.queryErr == nil && !f.closed {
				t.Fatal("rows not closed")
			}
		})
	}
}

func TestUnsupportedAndCancellation(t *testing.T) {
	for _, name := range []string{"mysql", "postgres", "", "sqlite3"} {
		got, err := Run(context.Background(), name, nil, "FULL")
		if !errors.Is(err, ErrUnsupported) || got.Attempted || got.Supported || got.Complete {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &fixture{cancel: cancel}
	db := sql.OpenDB(f)
	defer db.Close()
	got, err := Run(ctx, "sqlite", db, "FULL")
	if !errors.Is(err, context.Canceled) || got.Complete {
		t.Fatalf("%+v %v", got, err)
	}
	f.query = ""
	got, err = Run(ctx, "sqlite", db, "FULL")
	if !errors.Is(err, context.Canceled) || got.Attempted || f.query != "" {
		t.Fatalf("pre-canceled: %+v %v", got, err)
	}
}

func TestModesAndInvalidRows(t *testing.T) {
	for _, mode := range []string{"full", "RESTART", "TRUNCATE", "PASSIVE); DROP TABLE x;--"} {
		f := &fixture{values: []driver.Value{int64(0), int64(0), int64(0)}}
		db := sql.OpenDB(f)
		got, err := Run(context.Background(), "sqlite", db, mode)
		db.Close()
		if err != nil || strings.Contains(f.query, "DROP") || !strings.Contains(f.query, got.Mode) {
			t.Fatalf("%+v %v %q", got, err, f.query)
		}
	}
	for _, values := range [][]driver.Value{nil, {"bad", int64(0), int64(0)}} {
		f := &fixture{values: values}
		db := sql.OpenDB(f)
		got, err := Run(context.Background(), "sqlite", db, "PASSIVE")
		db.Close()
		if err == nil || got.Complete {
			t.Fatalf("invalid rows accepted: %+v", got)
		}
	}
}
