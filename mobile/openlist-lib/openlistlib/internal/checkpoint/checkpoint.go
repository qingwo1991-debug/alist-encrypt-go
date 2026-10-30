// Package checkpoint reports OpenList database WAL checkpoint results, not backups.
package checkpoint

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrUnsupported = errors.New("database checkpoint unsupported")
	ErrIncomplete  = errors.New("database checkpoint incomplete")
	ErrNoWAL       = errors.New("database has no active WAL checkpoint")
)

// Result describes this invocation only; even Complete is not a snapshot or a
// promise that concurrent/subsequent writes have been checkpointed.
type Result struct {
	Driver       string
	Mode         string
	Supported    bool
	Attempted    bool
	Busy         int
	Log          int
	Checkpointed int
	Complete     bool
}

type Queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// Run uses the actual GORM dialect name, never the configured database type.
// Non-SQLite engines intentionally do nothing: transaction commit/durability is
// owned by that engine; this API cannot claim a SQLite checkpoint for them.
func Run(ctx context.Context, driver string, db Queryer, mode string) (result Result, err error) {
	mode = strings.ToUpper(strings.TrimSpace(mode))
	switch mode {
	case "PASSIVE", "FULL", "RESTART", "TRUNCATE":
	default:
		mode = "PASSIVE"
	}
	result = Result{Driver: driver, Mode: mode, Busy: -1, Log: -1, Checkpointed: -1}
	if driver != "sqlite" {
		return result, fmt.Errorf("%w: driver=%q (no checkpoint attempted)", ErrUnsupported, driver)
	}
	result.Supported = true
	if db == nil {
		return result, errors.New("database connection is nil")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Attempted = true
	rows, err := db.QueryContext(ctx, "PRAGMA wal_checkpoint("+mode+")")
	if err != nil {
		return result, fmt.Errorf("query WAL checkpoint: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close WAL checkpoint rows: %w", closeErr))
			result.Complete = false
		}
	}()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return result, fmt.Errorf("read WAL checkpoint: %w", err)
		}
		return result, errors.New("WAL checkpoint returned no result row")
	}
	if err := rows.Scan(&result.Busy, &result.Log, &result.Checkpointed); err != nil {
		return result, fmt.Errorf("scan WAL checkpoint: %w", err)
	}
	if rows.Next() {
		return result, errors.New("WAL checkpoint returned multiple result rows")
	}
	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("read WAL checkpoint: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if result.Log == -1 && result.Checkpointed == -1 && result.Busy == 0 {
		return result, ErrNoWAL
	}
	if result.Busy != 0 || result.Log < 0 || result.Checkpointed < 0 || result.Log != result.Checkpointed {
		return result, fmt.Errorf("%w: mode=%s busy=%d log=%d checkpointed=%d", ErrIncomplete, mode, result.Busy, result.Log, result.Checkpointed)
	}
	result.Complete = true
	return result, nil
}
