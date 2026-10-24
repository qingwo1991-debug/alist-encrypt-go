// backup-audit inventories only an explicitly scoped, offline rehearsal copy.
// It does not repair a database, establish snapshot consistency, or prove media integrity.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	bolt "go.etcd.io/bbolt"
)

const maxDBBytes int64 = 512 << 20
const maxEntries = 1000000

var auditBuckets = []string{
	"filename_reservations_v1", "filename_original_index_v1", "filename_read_candidates_v1",
	"filename_recoveries_v1", "filename_retry_audit_v1",
	"verified_media_aliases_v1", "verified_media_reverse_v1", "playback_confirmed_v1",
}
var countOnlyBuckets = []string{"users", "passwd", "config"}

type bucketReport struct {
	Present       bool           `json:"present"`
	Entries       int            `json:"entries"`
	NestedBuckets int            `json:"nested_buckets"`
	SHA256        string         `json:"sha256,omitempty"`
	StatusCounts  map[string]int `json:"status_counts,omitempty"`
}
type report struct {
	Schema                       int                     `json:"schema"`
	ReadOnly                     bool                    `json:"read_only"`
	InventoryOnly                bool                    `json:"inventory_only"`
	SnapshotConsistencyValidated bool                    `json:"snapshot_consistency_validated"`
	DatabaseBytes                int64                   `json:"database_bytes"`
	TransactionID                int                     `json:"transaction_id"`
	Buckets                      map[string]bucketReport `json:"buckets"`
	OtherRootBucketCount         int                     `json:"other_root_bucket_count"`
}

func beneath(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}
func livePath(p string) bool {
	for _, base := range []string{"/root/docker", "/app/data", "/app/conf", "/app/configs"} {
		if p == base || beneath(base, p) {
			return true
		}
	}
	return false
}
func singleLink(info os.FileInfo) bool {
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer && !v.IsNil() {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}
	f := v.FieldByName("Nlink")
	return f.IsValid() && f.CanUint() && f.Uint() == 1
}
func scopedDB(root, dbPath string) (string, os.FileInfo, error) {
	deny := errors.New("offline_copy_scope_required")
	if root == "" || dbPath == "" {
		return "", nil, deny
	}
	r, err := filepath.Abs(root)
	if err != nil {
		return "", nil, deny
	}
	p, err := filepath.Abs(dbPath)
	if err != nil {
		return "", nil, deny
	}
	// Both lexical and resolved paths must stay under the explicit copy directory.
	if r == filepath.VolumeName(r)+string(os.PathSeparator) || r == "/root" || r == "/app" || !beneath(r, p) || livePath(r) || livePath(p) {
		return "", nil, deny
	}
	resolvedRoot, err := filepath.EvalSymlinks(r)
	if err != nil {
		return "", nil, deny
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", nil, deny
	}
	if resolvedRoot == filepath.VolumeName(resolvedRoot)+string(os.PathSeparator) || resolvedRoot == "/root" || resolvedRoot == "/app" || !beneath(resolvedRoot, resolved) || livePath(resolvedRoot) || livePath(resolved) {
		return "", nil, deny
	}
	ri, err := os.Stat(resolvedRoot)
	if err != nil || !ri.IsDir() {
		return "", nil, deny
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxDBBytes || !singleLink(info) {
		return "", nil, deny
	}
	return resolved, info, nil
}
func framed(h hash.Hash, data []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(data)))
	h.Write(n[:])
	h.Write(data)
}
func digestBucket(ctx context.Context, b *bolt.Bucket, h hash.Hash, depth int, n *int, status map[string]int) (entries, nested int, err error) {
	if depth > 32 {
		return 0, 0, errors.New("audit_limits_exceeded")
	}
	err = b.ForEach(func(k, v []byte) error {
		if err := ctx.Err(); err != nil {
			return errors.New("inspection_cancelled")
		}
		(*n)++
		if *n > maxEntries {
			return errors.New("audit_limits_exceeded")
		}
		if v == nil {
			nested++
			h.Write([]byte{1})
			framed(h, k)
			_, _, err := digestBucket(ctx, b.Bucket(k), h, depth+1, n, nil)
			h.Write([]byte{2})
			return err
		}
		entries++
		h.Write([]byte{0})
		framed(h, k)
		framed(h, v)
		if status != nil {
			// Do not unmarshal any origin, path, token, password or recovery evidence.
			var row struct{ Status string }
			if len(v) > 1<<20 || json.Unmarshal(v, &row) != nil {
				status["invalid_json"]++
				return nil
			}
			switch row.Status {
			case "pending", "complete", "failed":
				status[row.Status]++
			default:
				status["unknown"]++
			}
		}
		return nil
	})
	return
}
func inspect(ctx context.Context, root, dbPath string) (report, error) {
	var out report
	resolved, info, err := scopedDB(root, dbPath)
	if err != nil {
		return out, err
	}
	db, err := bolt.Open(resolved, 0400, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		return out, errors.New("offline_database_open_failed")
	}
	defer db.Close()
	// Recheck identity after lock acquisition. The copy directory must remain trusted
	// and immutable: this is not protection against an adversary racing path changes.
	current, err := os.Stat(resolved)
	if err != nil || !os.SameFile(info, current) || current.Size() != info.Size() || !singleLink(current) {
		return out, errors.New("offline_copy_changed")
	}
	out = report{Schema: 1, ReadOnly: true, InventoryOnly: true, DatabaseBytes: info.Size(), Buckets: make(map[string]bucketReport)}
	err = db.View(func(tx *bolt.Tx) error {
		out.TransactionID = tx.ID()
		known := make(map[string]bool)
		n := 0
		for _, name := range auditBuckets {
			known[name] = true
			b := tx.Bucket([]byte(name))
			r := bucketReport{Present: b != nil}
			if b != nil {
				if name == "filename_reservations_v1" {
					r.StatusCounts = map[string]int{"pending": 0, "complete": 0, "failed": 0, "unknown": 0, "invalid_json": 0}
				}
				h := sha256.New()
				framed(h, []byte("backup-audit-v1"))
				framed(h, []byte(name))
				r.Entries, r.NestedBuckets, err = digestBucket(ctx, b, h, 0, &n, r.StatusCounts)
				if err != nil {
					return err
				}
				r.SHA256 = hex.EncodeToString(h.Sum(nil))
			}
			out.Buckets[name] = r
		}
		for _, name := range countOnlyBuckets {
			known[name] = true
			b := tx.Bucket([]byte(name))
			r := bucketReport{Present: b != nil}
			if b != nil {
				err = b.ForEach(func(_, v []byte) error {
					if ctx.Err() != nil {
						return errors.New("inspection_cancelled")
					}
					n++
					if n > maxEntries {
						return errors.New("audit_limits_exceeded")
					}
					if v == nil {
						r.NestedBuckets++
					} else {
						r.Entries++
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
			out.Buckets[name] = r
		}
		return tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
			if !known[string(name)] {
				out.OtherRootBucketCount++
			}
			return nil
		})
	})
	if err != nil {
		return report{}, errors.New("offline_inventory_failed")
	}
	return out, nil
}
func writeReport(path string, r report) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return errors.New("report_encoding_failed")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("report_destination_unavailable")
	}
	_, writeErr := io.Copy(f, strings.NewReader(string(raw)+"\n"))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("report_write_failed")
	}
	return nil
}
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("backup-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("allow-root", "", "Explicit trusted, immutable offline copy directory (not a production mount)")
	db := flags.String("db", "", "Existing Bolt file beneath allow-root; never a live database")
	output := flags.String("output", "", "New report file; exclusive creation, mode 0600")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *output == "" {
		fmt.Fprintln(stderr, `{"error":"explicit_offline_arguments_required"}`)
		return 1
	}
	r, err := inspect(ctx, *root, *db)
	if err == nil {
		err = writeReport(*output, r)
	}
	if err != nil {
		fmt.Fprintf(stderr, "{\"error\":%q}\n", err.Error())
		return 1
	}
	fmt.Fprintln(stdout, `{"report_written":true,"read_only":true,"inventory_only":true}`)
	return 0
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
