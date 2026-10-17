package mysqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func parseBackupFixtureDSN(dsn, database string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	cfg.DBName = database
	return cfg.FormatDSN(), nil
}

func TestMySQLBackupDDLNormalization(t *testing.T) {
	literal := "CREATE TABLE ` AUTO_INCREMENT=999` (`id` int AUTO_INCREMENT, `s` text DEFAULT ' AUTO_INCREMENT=123' COMMENT ' AUTO_INCREMENT=456') ENGINE=InnoDB AUTO_INCREMENT=42 COMMENT=' AUTO_INCREMENT=789'"
	want := strings.Replace(literal, " ENGINE=InnoDB AUTO_INCREMENT=42", " ENGINE=InnoDB", 1)
	if got := normalizeBackupDDL(literal); got != want {
		t.Fatalf("literal rewritten: %q", got)
	}
	for _, ddl := range []string{
		"CREATE TABLE `t` (`x` text DEFAULT 'escaped\\' AUTO_INCREMENT=123') ENGINE=InnoDB",
		"CREATE TABLE `t` (`x` text DEFAULT 'double'' AUTO_INCREMENT=123') ENGINE=InnoDB COMMENT=' AUTO_INCREMENT=456'",
		"CREATE TABLE `t` (`x` int) ENGINE=InnoDB /* AUTO_INCREMENT=123 */",
	} {
		if got := normalizeBackupDDL(ddl); got != ddl {
			t.Fatalf("quoted/comment SQL changed: %q", got)
		}
	}
}

func TestMySQLBackupValidationContract(t *testing.T) {
	table := backupTable{Name: "t", Engine: "InnoDB", DDL: "CREATE TABLE t (n BIGINT) ENGINE=InnoDB"}
	col := BackupColumn{Name: "n", DatabaseType: "BIGINT"}
	base := []backupRecord{{Kind: "table", Table: &table, Columns: []BackupColumn{col}}, {Kind: "row", Values: []BackupValue{{Kind: "int64", Value: "42"}}}}
	makeFile := func(records []backupRecord, mutate func(*BackupManifest)) []byte {
		var b []byte
		for _, r := range records {
			line, _ := json.Marshal(r)
			b = append(b, line...)
			b = append(b, '\n')
		}
		h := sha256.Sum256(b)
		m := BackupManifest{Version: 1, Component: "root-mysql-metadata", Consistency: "committed-transactions-only/repeatable-read-pinned", Sensitive: "full-database-including-transfer-secrets", StartedUTC: "2026-01-01T00:00:00Z", FinishedUTC: "2026-01-01T00:00:01Z", GoVersion: "go-fixture", ServerVersion: "8.4", PayloadBytes: int64(len(b)), PayloadSHA256: hex.EncodeToString(h[:]), SchemaSHA256: backupSchemaHash([]backupTable{table}), Tables: 1, Rows: 1}
		if mutate != nil {
			mutate(&m)
		}
		line, _ := json.Marshal(backupRecord{Kind: "manifest", Manifest: &m})
		return append(append(b, line...), '\n')
	}
	path := filepath.Join(t.TempDir(), "fixture.ndjson")
	check := func(b []byte, wantOK bool) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := ValidateMySQLBackup(context.Background(), path, 1<<20)
		if (err == nil) != wantOK {
			t.Fatalf("validation success=%v err=%v", wantOK, err)
		}
	}
	good := makeFile(base, nil)
	check(good, true)
	check(good[:len(good)-1], false) // truncated final line
	badHash := append([]byte(nil), good...)
	badHash = []byte(strings.Replace(string(badHash), "42", "43", 1))
	check(badHash, false) // valid numeric JSON, independent digest mismatch
	wrong := append([]backupRecord(nil), base...)
	wrong[1].Values = []BackupValue{{Kind: "int64", Value: "not-an-integer"}}
	check(makeFile(wrong, nil), false) // recomputed digest, invalid typed value
	for _, mutate := range []func(*BackupManifest){func(m *BackupManifest) { m.Consistency = "unknown" }, func(m *BackupManifest) { m.Sensitive = "public" }, func(m *BackupManifest) { m.StartedUTC = "bad" }, func(m *BackupManifest) { m.SourceCommit = "not-a-sha" }, func(m *BackupManifest) { m.Tables = 0 }} {
		check(makeFile(base, mutate), false)
	}
	unknown := []byte(strings.Replace(string(good), `"kind":"row"`, `"kind":"row","unknown":1`, 1))
	check(unknown, false)
	wrong = append([]backupRecord(nil), base...)
	wrong[1].Table = &table
	check(makeFile(wrong, nil), false)
	badtable := table
	badtable.DDL = ""
	wrong = append([]backupRecord(nil), base...)
	wrong[0].Table = &badtable
	check(makeFile(wrong, nil), false)
	wrong = append([]backupRecord(nil), base...)
	wrong[0].Columns = []BackupColumn{col, col}
	check(makeFile(wrong, nil), false)
}

func TestMySQLBackupTypedValues(t *testing.T) {
	for _, v := range []any{nil, []byte(nil), []byte{}, []byte{0, 255}, "text", true, int64(-9223372036854775807), uint64(18446744073709551615), float64(1.2345678901234567), time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.FixedZone("offset", 3600))} {
		got, err := encodeBackupValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if err = validateBackupValue(got); err != nil {
			t.Fatal(err)
		}
	}
	nilv, _ := encodeBackupValue([]byte(nil))
	empty, _ := encodeBackupValue([]byte{})
	if nilv.Kind == empty.Kind {
		t.Fatal("nil and empty bytes conflated")
	}
	for _, v := range []BackupValue{{Kind: "bytes", Value: "AB=="}, {Kind: "bool", Value: "1"}, {Kind: "float64", Value: "NaN"}, {Kind: "future"}} {
		if validateBackupValue(v) == nil {
			t.Fatalf("accepted invalid value: %+v", v)
		}
	}
	if _, err := encodeBackupValue(struct{}{}); err == nil {
		t.Fatal("unknown value accepted")
	}
}

func TestMySQLBackupOptionBounds(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, opt := range []BackupOptions{{Directory: dir, Name: "../escape", MaxBytes: 100, Timeout: time.Second}, {Directory: dir, Name: "safe", Timeout: time.Second}, {Directory: dir, Name: "safe", MaxBytes: 100}} {
		if _, err := BackupMySQL(context.Background(), "", opt); err == nil {
			t.Fatal("accepted invalid options")
		}
	}
}

// This fixture uses its own actual MySQL database. In CI a missing DSN is a
// failure, not a green skipped backup acceptance test.
func TestMySQLBackupIntegration(t *testing.T) {
	if os.Getenv("MYSQL_TEST_DSN") == "" && os.Getenv("MYSQL_BACKUP_REQUIRE") == "1" {
		t.Fatal("MYSQL_TEST_DSN required for cloud backup acceptance")
	}
	ctx, s, database := newMySQLIntegrationStore(t)
	dsn := os.Getenv("MYSQL_TEST_DSN")
	// Parse and retarget rather than string substitution, preserving escaping.
	cfg, err := parseBackupFixtureDSN(dsn, database)
	if err != nil {
		t.Fatal(err)
	}
	dsn = cfg
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := s.db.ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec("CREATE TABLE `a_relation` (id INT PRIMARY KEY, revision BIGINT NOT NULL) ENGINE=InnoDB")
	exec("CREATE TABLE `z_relation` (id INT PRIMARY KEY, revision BIGINT NOT NULL) ENGINE=InnoDB")
	exec("INSERT INTO a_relation VALUES (1, 9007199254740993)")
	exec("INSERT INTO z_relation VALUES (1, 9007199254740993)")
	exec("CREATE TABLE `typed_fixture` (id BIGINT UNSIGNED PRIMARY KEY, amount DECIMAL(65,30), payload VARBINARY(16), empty_payload VARBINARY(16), absent VARBINARY(16), updated DATETIME(6), clock TIME(6), point GEOMETRY, secret TEXT) ENGINE=InnoDB")
	exec("INSERT INTO typed_fixture VALUES (18446744073709551615,123456789012345678901234567890.123456789012345678901234567890,?, ?,NULL,'2026-01-02 03:04:05.123456','-25:01:02.123456',ST_GeomFromText('POINT(1 2)'),?)", []byte{0, 255}, []byte{}, "signed-url-secret")
	uncommitted, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer uncommitted.Rollback()
	if _, err = uncommitted.ExecContext(ctx, "INSERT INTO a_relation VALUES (2,77)"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	opt := BackupOptions{Directory: dir, Name: "good.ndjson", MaxBytes: 8 << 20, Timeout: 10 * time.Second, SourceCommit: "0123456789abcdef0123456789abcdef01234567"}
	m, err := backupMySQL(ctx, dsn, opt, func() error {
		writer, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer writer.Rollback()
		if _, e = writer.ExecContext(ctx, "UPDATE a_relation SET revision=9007199254740995 WHERE id=1"); e != nil {
			return e
		}
		if _, e = writer.ExecContext(ctx, "UPDATE z_relation SET revision=9007199254740995 WHERE id=1"); e != nil {
			return e
		}
		return writer.Commit()
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.Tables != 8 {
		t.Fatalf("inventory dropped table: %+v", m)
	}
	path := filepath.Join(dir, opt.Name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("artifact permissions: %v %v", st, err)
	}
	var table string
	var columns []BackupColumn
	counts := map[string]int{}
	valueText := func(v BackupValue) string {
		t.Helper()
		if v.Kind == "bytes" {
			decoded, e := base64.StdEncoding.DecodeString(v.Value)
			if e != nil {
				t.Fatal(e)
			}
			return string(decoded)
		}
		return v.Value
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var rec backupRecord
		if err = json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec.Kind == "table" {
			table = rec.Table.Name
			columns = rec.Columns
		}
		if rec.Kind != "row" {
			continue
		}
		counts[table]++
		if table == "a_relation" || table == "z_relation" {
			if valueText(rec.Values[1]) != "9007199254740993" {
				t.Fatalf("mixed/new snapshot: %+v", rec)
			}
		}
		if table == "typed_fixture" {
			values := map[string]BackupValue{}
			for i, c := range columns {
				values[c.Name] = rec.Values[i]
			}
			for k, want := range map[string]string{"id": "18446744073709551615", "amount": "123456789012345678901234567890.123456789012345678901234567890", "updated": "2026-01-02 03:04:05.123456", "clock": "-25:01:02.123456", "secret": "signed-url-secret"} {
				if got := valueText(values[k]); got != want {
					t.Fatalf("%s precision lost: %q", k, got)
				}
			}
			if values["payload"].Value != "AP8=" || values["empty_payload"].Kind != "bytes" || values["absent"].Kind != "null" || values["point"].Kind != "bytes" {
				t.Fatalf("typed binary/null/geometry lost: %+v", values)
			}
		}
	}
	if counts["a_relation"] != 1 || counts["z_relation"] != 1 || counts["typed_fixture"] != 1 {
		t.Fatalf("missing/uncommitted rows: %v", counts)
	}
	manifestJSON, _ := json.Marshal(m)
	if strings.Contains(string(manifestJSON), "signed-url-secret") || strings.Contains(string(manifestJSON), "integration-only") {
		t.Fatal("manifest leaked secret")
	}
	if _, err = ValidateMySQLBackup(ctx, path, opt.MaxBytes); err != nil {
		t.Fatal(err)
	}
	// No replace: prior known-good bytes survive publication error.
	if _, err = BackupMySQL(ctx, dsn, opt); err == nil {
		t.Fatal("existing target overwritten")
	}
	opt.Name = "limited.ndjson"
	opt.MaxBytes = 32
	if _, err = BackupMySQL(ctx, dsn, opt); err == nil {
		t.Fatal("byte limit not enforced")
	}
	if _, err = os.Stat(filepath.Join(dir, opt.Name)); !os.IsNotExist(err) {
		t.Fatal("failed snapshot published")
	}
	opt.Name = "canceled.ndjson"
	opt.MaxBytes = 8 << 20
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = BackupMySQL(canceled, dsn, opt); err == nil {
		t.Fatal("cancel ignored")
	}
	opt.Name = "changed.ndjson"
	if _, err = backupMySQL(ctx, dsn, opt, func() error {
		_, e := s.db.ExecContext(ctx, "CREATE TABLE ddl_added (id INT) ENGINE=InnoDB")
		if e != nil {
			t.Fatalf("fixture DDL failed: %v", e)
		}
		return nil
	}); !errors.Is(err, ErrBackupSchemaChanged) {
		t.Fatalf("schema drift not detected: %v", err)
	}
	exec("DROP TABLE ddl_added")
	opt.Name = "midcancel.ndjson"
	midctx, midcancel := context.WithCancel(ctx)
	if _, err = backupMySQL(midctx, dsn, opt, func() error { midcancel(); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("after-pin cancellation ignored: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, opt.Name)); !os.IsNotExist(err) {
		t.Fatal("mid-operation cancellation published")
	}

	exec("CREATE TABLE literal_fixture (id INT PRIMARY KEY AUTO_INCREMENT, s VARCHAR(128) DEFAULT ' AUTO_INCREMENT=123') ENGINE=InnoDB COMMENT=' AUTO_INCREMENT=123'")
	opt.Name = "literal.ndjson"
	if _, err = backupMySQLHooks(ctx, dsn, opt, nil, func() error {
		_, e := s.db.ExecContext(ctx, "ALTER TABLE literal_fixture COMMENT=' AUTO_INCREMENT=456'")
		return e
	}); !errors.Is(err, ErrBackupSchemaChanged) {
		t.Fatalf("literal schema change not detected: %v", err)
	}
	opt.Name = "counter.ndjson"
	if _, err = backupMySQL(ctx, dsn, opt, func() error {
		_, e := s.db.ExecContext(ctx, "INSERT INTO literal_fixture (s) VALUES ('new')")
		return e
	}); err != nil {
		t.Fatalf("ordinary counter change rejected: %v", err)
	}
	if err = os.Remove(filepath.Join(dir, opt.Name)); err != nil {
		t.Fatal(err)
	}
	exec("DROP TABLE literal_fixture")
	exec("CREATE TABLE invisible_fixture (id INT, hidden INT INVISIBLE) ENGINE=InnoDB")
	opt.Name = "invisible.ndjson"
	if _, err = BackupMySQL(ctx, dsn, opt); err == nil {
		t.Fatal("invisible column silently omitted")
	}
	exec("DROP TABLE invisible_fixture")
	exec("CREATE TABLE nontransactional (id INT) ENGINE=MyISAM")
	opt.Name = "engine.ndjson"
	if _, err = BackupMySQL(ctx, dsn, opt); err == nil {
		t.Fatal("nontransactional engine accepted")
	}
	for _, name := range []string{"changed.ndjson", "engine.ndjson", "canceled.ndjson"} {
		if _, err = os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("failed %s published", name)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(b) {
		t.Fatal("prior good backup damaged")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("private stage leaked: %v %v", entries, err)
	}
	// Corruption fails validation rather than being accepted as a restore source.
	corrupt := filepath.Join(dir, "corrupt.ndjson")
	b[10] ^= 1
	if err = os.WriteFile(corrupt, b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ValidateMySQLBackup(ctx, corrupt, opt.MaxBytes); err == nil {
		t.Fatal("corruption accepted")
	}
}
