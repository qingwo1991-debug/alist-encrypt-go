package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	p := filepath.Join(root, "copy.db")
	db, e := bolt.Open(p, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket([]byte("filename_reservations_v1"))
		if e != nil {
			return e
		}
		for k, v := range map[string]string{"a": `{"Status":"failed","OriginalPath":"SECRET_SOURCE","Token":"SECRET_TOKEN"}`, "b": `{"Status":"complete"}`, "c": `{"Status":"pending"}`, "d": `{"Status":"future_status"}`, "e": `not-json`, "f": `{"Status":12}`, "g": `null`} {
			if e = b.Put([]byte(k), []byte(v)); e != nil {
				return e
			}
		}
		sub, e := b.CreateBucket([]byte("SECRET_NESTED"))
		if e != nil {
			return e
		}
		if e = sub.Put([]byte("SECRET_KEY"), []byte("SECRET_VALUE")); e != nil {
			return e
		}
		for _, name := range []string{"filename_recoveries_v1", "filename_retry_audit_v1", "verified_media_aliases_v1", "filename_original_index_v1", "filename_read_candidates_v1", "users"} {
			c, e := tx.CreateBucket([]byte(name))
			if e != nil {
				return e
			}
			if e = c.Put([]byte("SECRET_RECORD_ID"), []byte(`{"secret":"SECRET_PASSWORD"}`)); e != nil {
				return e
			}
		}
		_, e = tx.CreateBucket([]byte("SECRET_FUTURE_BUCKET"))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Close(); e != nil {
		t.Fatal(e)
	}
	return root, p
}
func TestCountsDigestRedactionAndNoMutation(t *testing.T) {
	root, p := fixture(t)
	before, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	a, e := inspect(context.Background(), root, p)
	if e != nil {
		t.Fatal(e)
	}
	b, e := inspect(context.Background(), root, p)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("inventory changed without writes")
	}
	if !a.InventoryOnly || a.SnapshotConsistencyValidated || !a.ReadOnly {
		t.Fatal("wrong assurance flags")
	}
	r := a.Buckets["filename_reservations_v1"]
	if r.Entries != 7 || r.NestedBuckets != 1 || len(r.SHA256) != 64 {
		t.Fatalf("counts=%+v", r)
	}
	expected := map[string]int{"pending": 1, "complete": 1, "failed": 1, "unknown": 2, "invalid_json": 2}
	if !reflect.DeepEqual(r.StatusCounts, expected) {
		t.Fatalf("statuses=%v", r.StatusCounts)
	}
	if a.Buckets["filename_recoveries_v1"].Entries != 1 || a.Buckets["filename_retry_audit_v1"].Entries != 1 {
		t.Fatal("lost recovery/retry count")
	}
	if a.Buckets["users"].SHA256 != "" || a.Buckets["users"].Entries != 1 {
		t.Fatal("user values must never be hashed or emitted")
	}
	if a.OtherRootBucketCount != 1 {
		t.Fatal("unknown root bucket count")
	}
	encoded, _ := json.Marshal(a)
	if bytes.Contains(encoded, []byte("SECRET")) || bytes.Contains(encoded, []byte("future_status")) {
		t.Fatal("secret or arbitrary status escaped")
	}
	after, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("database bytes mutated")
	}
}
func TestDigestDetectsChangedRecordWithoutChangingCounts(t *testing.T) {
	root, p := fixture(t)
	a, e := inspect(context.Background(), root, p)
	if e != nil {
		t.Fatal(e)
	}
	db, e := bolt.Open(p, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	e = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("filename_recoveries_v1")).Put([]byte("SECRET_RECORD_ID"), []byte(`{"new":"SECRET_CHANGED"}`))
	})
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	b, e := inspect(context.Background(), root, p)
	if e != nil {
		t.Fatal(e)
	}
	x, y := a.Buckets["filename_recoveries_v1"], b.Buckets["filename_recoveries_v1"]
	if x.Entries != y.Entries || x.SHA256 == y.SHA256 {
		t.Fatal("digest missed altered recovery")
	}
	if a.Buckets["filename_reservations_v1"].SHA256 != b.Buckets["filename_reservations_v1"].SHA256 {
		t.Fatal("unrelated bucket digest changed")
	}
}
func TestScopesAndLinks(t *testing.T) {
	root, p := fixture(t)
	for _, pair := range [][2]string{{"", p}, {"/", p}, {"/root", p}, {"/app", p}, {root, root}, {root, filepath.Join(t.TempDir(), "outside.db")}, {"/root/docker", "/root/docker/alist-encrypt1/data/alist-encrypt.db"}, {"/app/data", "/app/data/alist-encrypt.db"}} {
		if _, _, e := scopedDB(pair[0], pair[1]); e == nil {
			t.Errorf("accepted bad scope %q", pair[0])
		}
	}
	outsideRoot, outside := fixture(t)
	_ = outsideRoot
	link := filepath.Join(root, "escape.db")
	if e := os.Symlink(outside, link); e != nil {
		t.Fatal(e)
	}
	if _, _, e := scopedDB(root, link); e == nil {
		t.Fatal("accepted escaping symlink")
	}
	liveLink := filepath.Join(root, "live.db")
	if e := os.Symlink("/root/docker/alist-encrypt1/data/alist-encrypt.db", liveLink); e != nil {
		t.Fatal(e)
	}
	if _, _, e := scopedDB(root, liveLink); e == nil {
		t.Fatal("accepted production symlink")
	}
	hard := filepath.Join(root, "hard.db")
	if e := os.Link(p, hard); e != nil {
		t.Fatal(e)
	}
	if _, _, e := scopedDB(root, hard); e == nil {
		t.Fatal("accepted hardlinked source")
	}
}
func TestBusyDatabaseTimesOutWithoutOutput(t *testing.T) {
	root, p := fixture(t)
	db, e := bolt.Open(p, 0600, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var out, errs bytes.Buffer
	dest := filepath.Join(root, "report.json")
	start := time.Now()
	if run(context.Background(), []string{"--allow-root", root, "--db", p, "--output", dest}, &out, &errs) == 0 {
		t.Fatal("accepted writer-locked DB")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("busy lock wait exceeded bound")
	}
	if !strings.Contains(errs.String(), "offline_database_open_failed") || strings.Contains(errs.String(), root) {
		t.Fatal("unredacted error")
	}
	if _, e = os.Stat(dest); !os.IsNotExist(e) {
		t.Fatal("failed inspection created report")
	}
}
func TestExclusiveReportAndCancelledContext(t *testing.T) {
	root, p := fixture(t)
	dest := filepath.Join(root, "report.json")
	var out, errs bytes.Buffer
	args := []string{"--allow-root", root, "--db", p, "--output", dest}
	if run(context.Background(), args, &out, &errs) != 0 {
		t.Fatal(errs.String())
	}
	st, e := os.Stat(dest)
	if e != nil {
		t.Fatal(e)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatal("report permissions")
	}
	if run(context.Background(), args, &out, &errs) == 0 {
		t.Fatal("overwrote report")
	}
	link := filepath.Join(root, "report-link.json")
	if e = os.Symlink(dest, link); e != nil {
		t.Fatal(e)
	}
	if writeReport(link, report{}) == nil {
		t.Fatal("followed output symlink")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = inspect(ctx, root, p); e == nil {
		t.Fatal("ignored cancellation")
	}
	if run(context.Background(), nil, &out, &errs) == 0 {
		t.Fatal("accepted missing flags")
	}
}
