package mysqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

var trackingDriverID atomic.Uint64

type trackingDriver struct {
	pingErr   error
	execErr   error
	closeCall atomic.Int32
}

func (d *trackingDriver) Open(string) (driver.Conn, error) {
	return &trackingConn{driver: d}, nil
}

type trackingConn struct {
	driver *trackingDriver
}

func (c *trackingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepare not implemented")
}

func (c *trackingConn) Close() error {
	c.driver.closeCall.Add(1)
	return nil
}

func (c *trackingConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions not implemented")
}

func (c *trackingConn) Ping(context.Context) error {
	return c.driver.pingErr
}

func (c *trackingConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	if c.driver.execErr != nil {
		return nil, c.driver.execErr
	}
	return driver.RowsAffected(1), nil
}

func useTrackingDriver(t *testing.T, d *trackingDriver) {
	t.Helper()
	driverName := fmt.Sprintf("mysqlstore_tracking_%d", trackingDriverID.Add(1))
	sql.Register(driverName, d)
	previous := openDB
	openDB = func(string, string) (*sql.DB, error) {
		return sql.Open(driverName, "")
	}
	t.Cleanup(func() {
		openDB = previous
	})
}

func mysqlTestConfig() *config.Config {
	cfg := config.DefaultConfig()
	cfg.Database.Type = "mysql"
	cfg.Database.DSN = "tracking"
	cfg.Database.DisableCleanup = true
	return cfg
}

func TestNewStoreClosesDBAfterPingFailure(t *testing.T) {
	wantErr := errors.New("ping failed")
	d := &trackingDriver{pingErr: wantErr}
	useTrackingDriver(t, d)

	store, err := NewStore(mysqlTestConfig())
	if store != nil {
		t.Fatal("NewStore returned a store after ping failure")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewStore error = %v, want %v", err, wantErr)
	}
	if got := d.closeCall.Load(); got == 0 {
		t.Fatal("database was not closed after ping failure")
	}
}

func TestNewStoreClosesDBAfterSchemaFailure(t *testing.T) {
	wantErr := errors.New("schema failed")
	d := &trackingDriver{execErr: wantErr}
	useTrackingDriver(t, d)

	store, err := NewStore(mysqlTestConfig())
	if store != nil {
		t.Fatal("NewStore returned a store after schema failure")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("NewStore error = %v, want %v", err, wantErr)
	}
	if got := d.closeCall.Load(); got == 0 {
		t.Fatal("database was not closed after schema failure")
	}
}
