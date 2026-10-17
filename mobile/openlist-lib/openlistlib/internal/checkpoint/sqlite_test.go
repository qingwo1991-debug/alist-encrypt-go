package checkpoint

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// Uses the existing default mobile SQLite dependency; no new driver is added.
func TestSQLiteWALCheckpoint(t *testing.T) {
	gormDB, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "checkpoint.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	db, err := gormDB.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	writer, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	var journal string
	if err := writer.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&journal); err != nil || journal != "wal" {
		t.Fatalf("journal=%s err=%v", journal, err)
	}
	for _, query := range []string{"PRAGMA wal_autocheckpoint=0", "CREATE TABLE sample (id INTEGER)", "INSERT INTO sample VALUES (1)"} {
		if _, err := writer.ExecContext(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := Run(ctx, gormDB.Dialector.Name(), writer, "TRUNCATE"); err != nil || !got.Complete {
		t.Fatalf("initial: %+v %v", got, err)
	}
	reader, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.QueryRowContext(ctx, "SELECT count(*) FROM sample").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "INSERT INTO sample VALUES (2)"); err != nil {
		t.Fatal(err)
	}
	got, err := Run(ctx, gormDB.Dialector.Name(), writer, "PASSIVE")
	if !errors.Is(err, ErrIncomplete) || got.Busy != 0 || got.Log <= got.Checkpointed || got.Complete {
		t.Fatalf("reader-pinned WAL: %+v %v", got, err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	got, err = Run(ctx, gormDB.Dialector.Name(), writer, "FULL")
	if err != nil || !got.Complete || got.Log != got.Checkpointed {
		t.Fatalf("released reader: %+v %v", got, err)
	}
	if _, err := writer.ExecContext(ctx, "PRAGMA journal_mode=DELETE"); err != nil {
		t.Fatal(err)
	}
	got, err = Run(ctx, gormDB.Dialector.Name(), writer, "PASSIVE")
	if !errors.Is(err, ErrNoWAL) || got.Complete {
		t.Fatalf("non-WAL: %+v %v", got, err)
	}
}
