package mysqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	"github.com/go-sql-driver/mysql"
)

// TestMySQLV3MetadataIntegration runs only against an explicitly supplied MySQL
// instance. The DSN account needs CREATE/DROP DATABASE privileges: each run owns
// a separate database so the destructive old-schema migration case cannot alter
// another test's tables. No Store flush/cleanup goroutines are started.
func TestMySQLV3MetadataIntegration(t *testing.T) {
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("MYSQL_TEST_DSN not set")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ParseTime = true
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	database := fmt.Sprintf("alist_v3_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+database+"` CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.ExecContext(cleanupCtx, "DROP DATABASE `"+database+"`"); err != nil {
			t.Errorf("cleanup isolated database: %v", err)
		}
	}()
	cfg.DBName = database
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	write := func(record FileMetaRecord) {
		t.Helper()
		record.KeyHash = KeyHash(record.ProviderHost, record.OriginalPath)
		record.Active = true
		if err := s.upsertFileMeta(ctx, []FileMetaRecord{record}); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) *FileMetaRecord {
		t.Helper()
		got, ok, err := s.GetFileMeta(ctx, "integration", path)
		if err != nil || !ok {
			t.Fatalf("Get %s: found=%v err=%v", path, ok, err)
		}
		return got
	}
	original := func(path string) FileMetaRecord {
		return FileMetaRecord{ProviderHost: "integration", OriginalPath: path, Size: 12345, CiphertextSize: encryption.V3CiphertextSize(12345, 4096), ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: bytes.Repeat([]byte{1}, 16), ChunkSize: 4096, KDFIterations: 1234}
	}

	// A replacement's absent geometry must reset A's values, not synthesize a
	// fully populated but incorrect B record. Both nonce and version guards run
	// before their corresponding columns are assigned by MySQL.
	a := original("/replacement")
	write(a)
	b := FileMetaRecord{ProviderHost: a.ProviderHost, OriginalPath: a.OriginalPath, Size: 100, ContentVersion: 3, NonceField: bytes.Repeat([]byte{2}, 16)}
	write(b)
	got := read(a.OriginalPath)
	if got.CiphertextSize != 0 || got.HeaderLen != 0 || got.ChunkSize != 0 || got.KDFIterations != 0 || got.Size != 100 || !bytes.Equal(got.NonceField, b.NonceField) {
		t.Fatalf("replacement inherited metadata: %+v", got)
	}

	// Matching nonce and an unversioned size-only update preserve confirmed
	// plaintext and all four geometry fields, rather than subtracting the header.
	a = original("/same-nonce")
	write(a)
	write(FileMetaRecord{ProviderHost: a.ProviderHost, OriginalPath: a.OriginalPath, Size: a.CiphertextSize, NonceField: append([]byte(nil), a.NonceField...)})
	got = read(a.OriginalPath)
	if got.Size != a.Size || got.CiphertextSize != a.CiphertextSize || got.HeaderLen != a.HeaderLen || got.ChunkSize != a.ChunkSize || got.KDFIterations != a.KDFIterations || got.ContentVersion != 3 {
		t.Fatalf("size-only lost metadata: %+v", got)
	}

	a = original("/empty")
	a.Size = 0
	// Empty streaming V3 includes the 16-byte final-size trailer.
	a.CiphertextSize = encryption.V3CiphertextSize(0, int64(a.ChunkSize)) + 16
	write(a)
	write(FileMetaRecord{ProviderHost: a.ProviderHost, OriginalPath: a.OriginalPath, Size: 64})
	got = read(a.OriginalPath)
	if got.Size != 0 || got.CiphertextSize != 64 || got.HeaderLen != encryption.V3HeaderSize || got.ChunkSize != 4096 || got.KDFIterations != 1234 {
		t.Fatalf("empty V3 size-only: %+v", got)
	}

	// Simulate a pre-V3 database with real persisted rows; repeat ensureSchema
	// verifies idempotency and migrations default old records to unknown (zero).
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+TableName("file_meta")+" DROP COLUMN chunk_size, DROP COLUMN kdf_iterations"); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.ensureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	got = read("/same-nonce")
	if got.ChunkSize != 0 || got.KDFIterations != 0 || got.Size != 12345 || got.CiphertextSize != encryption.V3CiphertextSize(12345, 4096) {
		t.Fatalf("migrated old record: %+v", got)
	}
	for _, column := range []string{"chunk_size", "kdf_iterations"} {
		var columnType, defaultValue string
		err := db.QueryRowContext(ctx, "SELECT COLUMN_TYPE, COLUMN_DEFAULT FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_NAME=?", database, TableName("file_meta"), column).Scan(&columnType, &defaultValue)
		if err != nil || columnType != "int unsigned" || defaultValue != "0" {
			t.Fatalf("migration %s: type=%q default=%q err=%v", column, columnType, defaultValue, err)
		}
	}
}
