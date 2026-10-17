// store-maint performs offline, root-Bolt-only maintenance. It never stops a
// service, loads/defaults live config, contacts providers, or clears recovery.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/alist-encrypt-go/internal/storage"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: store-maint verify|restore [options]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	bundle := fs.String("bundle", "", "absolute snapshot tar path")
	max := fs.Int64("max-bytes", 1<<30, "maximum database bytes")
	dir := fs.String("store-dir", "", "absolute existing stopped service store directory")
	cfg := fs.String("config", "", "absolute external config path (never restored)")
	hash := fs.String("config-sha256", "", "required independently pinned external config SHA256")
	timeout := fs.Duration("timeout", 30*time.Second, "total cooperative operation budget")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *timeout <= 0 || *max <= 0 || *max > 1<<40 {
		return fmt.Errorf("invalid time/byte budget")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	switch args[0] {
	case "verify":
		if err := storage.VerifyBundle(ctx, *bundle, *max); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"verified": true, "component": "root-bolt", "full_restore": false, "config": "external-required", "reconciliation": "unknown: remote objects not enumerated"})
	case "restore":
		report, err := storage.RestoreOffline(ctx, storage.RestoreOptions{StoreDir: *dir, Bundle: *bundle, Config: *cfg, ConfigSHA256: *hash, MaxBytes: *max})
		encodeErr := json.NewEncoder(os.Stdout).Encode(report)
		if err != nil {
			return err
		}
		return encodeErr
	default:
		return fmt.Errorf("unsupported operation (no clear/unfence command)")
	}
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
