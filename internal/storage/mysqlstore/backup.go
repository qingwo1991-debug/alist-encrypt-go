package mysqlstore

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

var (
	ErrBackupUnsupported   = errors.New("mysql backup unsupported")
	ErrBackupSchemaChanged = errors.New("mysql backup schema changed")
	ErrBackupLimit         = errors.New("mysql backup byte limit exceeded")
)

// BackupOptions requires explicit storage and time budgets. Directory must be an
// existing private, non-symlink directory owned/controlled by the caller.
type BackupOptions struct {
	Directory    string
	Name         string
	MaxBytes     int64
	Timeout      time.Duration
	SourceCommit string
}

type BackupManifest struct {
	Version       int    `json:"version"`
	Component     string `json:"component"`
	Consistency   string `json:"consistency"`
	Sensitive     string `json:"sensitive"`
	StartedUTC    string `json:"started_utc"`
	FinishedUTC   string `json:"finished_utc"`
	SourceCommit  string `json:"source_commit"`
	GoVersion     string `json:"go_version"`
	DriverVersion string `json:"driver_version"`
	ServerVersion string `json:"server_version"`
	SchemaSHA256  string `json:"schema_sha256"`
	PayloadSHA256 string `json:"payload_sha256"`
	PayloadBytes  int64  `json:"payload_bytes"`
	Rows          int64  `json:"rows"`
	Tables        int    `json:"tables"`
}

type BackupColumn struct {
	Name         string `json:"name"`
	DatabaseType string `json:"database_type"`
	Nullable     bool   `json:"nullable"`
}

// BackupValue retains the driver's concrete value kind; bytes are canonical
// base64 (including empty bytes), NULL is distinct. Numeric text is not JSON float.
type BackupValue struct {
	Kind  string `json:"kind"`
	Value string `json:"value,omitempty"`
}

type backupTable struct {
	Name   string `json:"name"`
	Engine string `json:"engine"`
	DDL    string `json:"ddl"`
}
type backupRecord struct {
	Kind     string          `json:"kind"`
	Table    *backupTable    `json:"table,omitempty"`
	Columns  []BackupColumn  `json:"columns,omitempty"`
	Values   []BackupValue   `json:"values,omitempty"`
	Manifest *BackupManifest `json:"manifest,omitempty"`
}

var autoIncrementCounter = regexp.MustCompile(` AUTO_INCREMENT=\d+`)

func quoteBackupIdentifier(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

func backupInventory(ctx context.Context, tx *sql.Tx) ([]backupTable, error) {
	rows, err := tx.QueryContext(ctx, "SELECT TABLE_NAME, TABLE_TYPE, COALESCE(ENGINE,'') FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME")
	if err != nil {
		return nil, err
	}
	var tables []backupTable
	for rows.Next() {
		var name, kind, engine string
		if err = rows.Scan(&name, &kind, &engine); err != nil {
			rows.Close()
			return nil, err
		}
		if kind != "BASE TABLE" || !strings.EqualFold(engine, "InnoDB") {
			rows.Close()
			return nil, fmt.Errorf("%w: non-InnoDB table or view", ErrBackupUnsupported)
		}
		tables = append(tables, backupTable{Name: name, Engine: engine})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(tables) == 0 {
		return nil, fmt.Errorf("%w: empty database", ErrBackupUnsupported)
	}
	for i := range tables {
		var invisible int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND EXTRA LIKE '%INVISIBLE%'", tables[i].Name).Scan(&invisible); err != nil {
			return nil, err
		}
		if invisible != 0 {
			return nil, fmt.Errorf("%w: invisible columns", ErrBackupUnsupported)
		}
		var name, ddl string
		if err = tx.QueryRowContext(ctx, "SHOW CREATE TABLE "+quoteBackupIdentifier(tables[i].Name)).Scan(&name, &ddl); err != nil {
			return nil, err
		}
		// A concurrent insert's counter is not a schema mutation.
		tables[i].DDL = autoIncrementCounter.ReplaceAllString(ddl, "")
	}
	return tables, nil
}
func backupSchemaHash(tables []backupTable) string {
	b, _ := json.Marshal(tables)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// BackupMySQL exports all base tables in the DSN's metadata database, not a
// filtered sync API. It never flushes Store buffers and never restores a database.
// It uses a dedicated single connection; credentials never reach subprocesses,
// manifests or error messages. Caller must exclude concurrent DDL (see docs).
func BackupMySQL(ctx context.Context, dsn string, opt BackupOptions) (BackupManifest, error) {
	return backupMySQL(ctx, dsn, opt, nil)
}

// afterPin is a synchronous fixture seam, never a runtime/global hook.
func backupMySQL(ctx context.Context, dsn string, opt BackupOptions, afterPin func() error) (manifest BackupManifest, err error) {
	if ctx == nil || opt.MaxBytes <= 0 || opt.Timeout <= 0 || opt.Name == "" || filepath.Base(opt.Name) != opt.Name || opt.Name == "." || opt.Name == ".." || strings.ContainsAny(opt.Name, "/\\") {
		return manifest, errors.New("invalid mysql backup options")
	}
	dir, err := filepath.Abs(opt.Directory)
	if err != nil {
		return manifest, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return manifest, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return manifest, errors.New("backup directory must be private and non-symlink")
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return manifest, errors.New("invalid mysql backup DSN")
	}
	if cfg.DBName == "" {
		return manifest, errors.New("mysql backup requires selected metadata database")
	}
	cfg.ParseTime = false // preserves zero dates, fractional seconds and wall-clock DATETIME.
	cfg.Loc = time.UTC
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	cfg.Params["lock_wait_timeout"] = "1"
	cfg.MultiStatements = false
	cfg.InterpolateParams = false
	cfg.Timeout = opt.Timeout
	cfg.ReadTimeout = opt.Timeout
	cfg.WriteTimeout = opt.Timeout
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return manifest, errors.New("invalid mysql backup connector")
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return manifest, errors.New("mysql backup begin transaction failed")
	}
	defer tx.Rollback()
	tables, err := backupInventory(ctx, tx)
	if err != nil {
		return manifest, err
	}
	// go-sql-driver/mysql BeginTx starts READ ONLY with REPEATABLE READ but does
	// not emit WITH CONSISTENT SNAPSHOT. This first actual InnoDB consistent read
	// pins that snapshot before ANY table data is exported. Do not issue a second
	// START TRANSACTION (it would implicitly commit the transaction).
	pin, err := tx.QueryContext(ctx, "SELECT * FROM "+quoteBackupIdentifier(tables[0].Name)+" LIMIT 1")
	if err != nil {
		return manifest, err
	}
	for pin.Next() {
	} // MySQL establishes the read view even for an empty table.
	err = pin.Err()
	pin.Close()
	if err != nil {
		return manifest, err
	}
	if afterPin != nil {
		if err = afterPin(); err != nil {
			return manifest, err
		}
	}
	manifest = BackupManifest{Version: 1, Component: "root-mysql-metadata", Consistency: "committed-transactions-only/repeatable-read-pinned", Sensitive: "full-database-including-transfer-secrets", StartedUTC: time.Now().UTC().Format(time.RFC3339Nano), SourceCommit: opt.SourceCommit, GoVersion: runtime.Version(), SchemaSHA256: backupSchemaHash(tables), Tables: len(tables)}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/go-sql-driver/mysql" {
				manifest.DriverVersion = d.Version
			}
		}
	}
	if err = tx.QueryRowContext(ctx, "SELECT VERSION()").Scan(&manifest.ServerVersion); err != nil {
		return manifest, err
	}
	stage, err := os.MkdirTemp(dir, ".mysql-backup-")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(stage)
	path := filepath.Join(stage, "snapshot.ndjson")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return manifest, err
	}
	defer f.Close()
	hash := sha256.New()
	var written int64
	emit := func(rec backupRecord, payload bool) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		b, e := json.Marshal(rec)
		if e != nil {
			return e
		}
		b = append(b, '\n')
		if int64(len(b)) > opt.MaxBytes-written {
			return ErrBackupLimit
		}
		n, e := f.Write(b)
		written += int64(n)
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		if payload {
			hash.Write(b)
		}
		return nil
	}
	for i := range tables {
		rows, e := tx.QueryContext(ctx, "SELECT * FROM "+quoteBackupIdentifier(tables[i].Name))
		if e != nil {
			return manifest, e
		}
		types, e := rows.ColumnTypes()
		if e != nil {
			rows.Close()
			return manifest, e
		}
		cols := make([]BackupColumn, len(types))
		for j, c := range types {
			nullable, _ := c.Nullable()
			cols[j] = BackupColumn{Name: c.Name(), DatabaseType: c.DatabaseTypeName(), Nullable: nullable}
		}
		if e = emit(backupRecord{Kind: "table", Table: &tables[i], Columns: cols}, true); e != nil {
			rows.Close()
			return manifest, e
		}
		for rows.Next() {
			raw := make([]any, len(cols))
			dest := make([]any, len(cols))
			for j := range raw {
				dest[j] = &raw[j]
			}
			if e = rows.Scan(dest...); e != nil {
				rows.Close()
				return manifest, e
			}
			values := make([]BackupValue, len(raw))
			for j, v := range raw {
				values[j], e = encodeBackupValue(v)
				if e != nil {
					rows.Close()
					return manifest, e
				}
			}
			if e = emit(backupRecord{Kind: "row", Values: values}, true); e != nil {
				rows.Close()
				return manifest, e
			}
			manifest.Rows++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return manifest, e
		}
	}
	after, err := backupInventory(ctx, tx)
	if err != nil {
		return manifest, err
	}
	if backupSchemaHash(after) != manifest.SchemaSHA256 {
		return manifest, ErrBackupSchemaChanged
	}
	if err = tx.Commit(); err != nil {
		return manifest, err
	}
	manifest.PayloadSHA256 = hex.EncodeToString(hash.Sum(nil))
	manifest.PayloadBytes = written
	manifest.FinishedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	if err = emit(backupRecord{Kind: "manifest", Manifest: &manifest}, false); err != nil {
		return manifest, err
	}
	if err = f.Sync(); err != nil {
		return manifest, err
	}
	if err = f.Close(); err != nil {
		return manifest, err
	}
	if _, err = ValidateMySQLBackup(ctx, path, opt.MaxBytes); err != nil {
		return manifest, err
	}
	if err = ctx.Err(); err != nil {
		return manifest, err
	}
	target := filepath.Join(dir, opt.Name)
	if err = os.Link(path, target); err != nil {
		return manifest, err
	} // atomic no-replace publication.
	directory, err := os.Open(dir)
	if err != nil {
		return manifest, err
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return manifest, fmt.Errorf("backup published but directory durability unconfirmed: %w", err)
	}
	return manifest, nil
}

func encodeBackupValue(v any) (BackupValue, error) {
	switch x := v.(type) {
	case nil:
		return BackupValue{Kind: "null"}, nil
	case []byte:
		if x == nil {
			return BackupValue{Kind: "null"}, nil
		}
		return BackupValue{Kind: "bytes", Value: base64.StdEncoding.EncodeToString(x)}, nil
	case string:
		return BackupValue{Kind: "string", Value: x}, nil
	case bool:
		return BackupValue{Kind: "bool", Value: strconv.FormatBool(x)}, nil
	case int64:
		return BackupValue{Kind: "int64", Value: strconv.FormatInt(x, 10)}, nil
	case uint64:
		return BackupValue{Kind: "uint64", Value: strconv.FormatUint(x, 10)}, nil
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return BackupValue{}, ErrBackupUnsupported
		}
		return BackupValue{Kind: "float64", Value: strconv.FormatFloat(x, 'g', -1, 64)}, nil
	case time.Time:
		return BackupValue{Kind: "time", Value: x.UTC().Format(time.RFC3339Nano)}, nil
	default:
		return BackupValue{}, fmt.Errorf("%w: driver value kind", ErrBackupUnsupported)
	}
}

// ValidateMySQLBackup checks the typed envelope, inventory and payload digest.
// This is not a restore proof, SQL safety approval, or engine integrity check.
func ValidateMySQLBackup(ctx context.Context, path string, maxBytes int64) (BackupManifest, error) {
	var result BackupManifest
	if maxBytes <= 0 {
		return result, ErrBackupLimit
	}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return result, ErrBackupLimit
	}
	r := bufio.NewReader(io.LimitReader(f, maxBytes+1))
	hash := sha256.New()
	var bytes, rows int64
	var tables []backupTable
	var columns int
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		line, e := r.ReadBytes('\n')
		if e != nil {
			return result, errors.New("incomplete mysql backup")
		}
		var rec backupRecord
		if err = json.Unmarshal(line, &rec); err != nil {
			return result, err
		}
		if rec.Kind == "manifest" {
			if rec.Manifest == nil {
				return result, errors.New("missing manifest")
			}
			result = *rec.Manifest
			if result.Version != 1 || result.Component != "root-mysql-metadata" || result.Rows != rows || result.Tables != len(tables) || result.PayloadBytes != bytes || result.PayloadSHA256 != hex.EncodeToString(hash.Sum(nil)) || result.SchemaSHA256 != backupSchemaHash(tables) {
				return result, errors.New("mysql backup manifest mismatch")
			}
			if _, e = r.ReadByte(); e != io.EOF {
				return result, errors.New("mysql backup trailing data")
			}
			return result, nil
		}
		switch rec.Kind {
		case "table":
			if rec.Table == nil || rec.Table.Name == "" || !strings.EqualFold(rec.Table.Engine, "InnoDB") || len(rec.Columns) == 0 {
				return result, errors.New("invalid backup table")
			}
			for _, t := range tables {
				if t.Name == rec.Table.Name {
					return result, errors.New("duplicate backup table")
				}
			}
			tables = append(tables, *rec.Table)
			columns = len(rec.Columns)
		case "row":
			if columns == 0 || len(rec.Values) != columns {
				return result, errors.New("invalid backup row")
			}
			for _, v := range rec.Values {
				if err = validateBackupValue(v); err != nil {
					return result, err
				}
			}
			rows++
		default:
			return result, errors.New("unknown backup record")
		}
		hash.Write(line)
		bytes += int64(len(line))
	}
}
func validateBackupValue(v BackupValue) error {
	var err error
	switch v.Kind {
	case "null":
		if v.Value != "" {
			err = errors.New("nonempty null")
		}
	case "bytes":
		var b []byte
		b, err = base64.StdEncoding.Strict().DecodeString(v.Value)
		if err == nil && base64.StdEncoding.EncodeToString(b) != v.Value {
			err = errors.New("noncanonical base64")
		}
	case "string":
	case "bool":
		if v.Value != "true" && v.Value != "false" {
			err = errors.New("invalid bool")
		}
	case "int64":
		_, err = strconv.ParseInt(v.Value, 10, 64)
	case "uint64":
		_, err = strconv.ParseUint(v.Value, 10, 64)
	case "float64":
		var n float64
		n, err = strconv.ParseFloat(v.Value, 64)
		if err == nil && (math.IsNaN(n) || math.IsInf(n, 0)) {
			err = errors.New("invalid float")
		}
	case "time":
		_, err = time.Parse(time.RFC3339Nano, v.Value)
	default:
		err = errors.New("unknown driver value kind")
	}
	return err
}
