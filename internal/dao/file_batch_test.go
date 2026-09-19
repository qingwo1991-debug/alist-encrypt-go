package dao_test

import (
	"fmt"
	"testing"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func newBatchTestStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestPersistFromListSingleWriteTransaction proves the "5000 项列表 ≤ 少量写事务"
// gate: a full listing prepared with PrepareFromAlistResponse and flushed with
// PersistFromList must cost exactly ONE BoltDB write transaction, never one per
// entry.
func TestPersistFromListSingleWriteTransaction(t *testing.T) {
	s := newBatchTestStore(t)
	d := dao.NewFileDAO(s)
	t.Cleanup(d.Stop)

	const n = 5000
	infos := make([]*dao.FileInfo, 0, n)
	start := s.WriteTxnCount()
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("file%04d.mp4", i)
		info := d.PrepareFromAlistResponse("/movies/"+name, map[string]interface{}{
			"name":   name,
			"size":   float64(1000 + i),
			"is_dir": false,
		}, "")
		if info == nil {
			t.Fatal("PrepareFromAlistResponse returned nil")
		}
		infos = append(infos, info)
	}
	if err := d.PersistFromList(infos); err != nil {
		t.Fatalf("PersistFromList: %v", err)
	}
	delta := s.WriteTxnCount() - start
	if delta != 1 {
		t.Fatalf("PersistFromList issued %d write transactions, want exactly 1", delta)
	}

	// The whole directory must be durably present in the bucket (not just memory).
	got := d.List(n)
	if len(got) != n {
		t.Fatalf("List returned %d entries, want %d", len(got), n)
	}
	// Read straight from storage: cache must be populated too (no disk read for
	// the same path right after a listing).
	if _, ok := d.Get("/movies/file0000.mp4"); !ok {
		t.Fatal("Get after listing missed cache")
	}
}

// TestPersistFromListPreservesMergedFields keeps the historical Set() semantics
// when the listing is sparse (e.g. OpenList omits raw_url and encrypted paths):
// previously known raw_url/sign/encrypted_path must survive into storage.
func TestPersistFromListPreservesMergedFields(t *testing.T) {
	s := newBatchTestStore(t)
	d := dao.NewFileDAO(s)
	t.Cleanup(d.Stop)

	path := "/movies/one.mp4"
	d.Set(&dao.FileInfo{
		Path:            path,
		Name:            "one.mp4",
		Size:            1000,
		EncryptedPath:   "/movies/encrypted-one.mp4",
		RawURL:          "https://upstream.example/raw/one.mp4",
		RawURLAuthScope: "user-1",
		Sign:            "sig-abc",
	})

	// Sparse listing item: name+size only, as real OpenList payloads commonly are.
	info := d.PrepareFromAlistResponse(path, map[string]interface{}{
		"name":   "one.mp4",
		"size":   float64(2000),
		"is_dir": false,
	}, "")
	if info == nil {
		t.Fatal("PrepareFromAlistResponse returned nil")
	}
	if err := d.PersistFromList([]*dao.FileInfo{info}); err != nil {
		t.Fatalf("PersistFromList: %v", err)
	}

	var persisted dao.FileInfo
	if err := s.GetJSON(storage.BucketFileInfo, path, &persisted); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if persisted.RawURL != "https://upstream.example/raw/one.mp4" {
		t.Errorf("raw_url not merged: got %q", persisted.RawURL)
	}
	if persisted.RawURLAuthScope != "user-1" {
		t.Errorf("raw_url_auth_scope not merged: got %q", persisted.RawURLAuthScope)
	}
	if persisted.Sign != "sig-abc" {
		t.Errorf("sign not merged: got %q", persisted.Sign)
	}
	if persisted.EncryptedPath != "/movies/encrypted-one.mp4" {
		t.Errorf("encrypted_path not merged: got %q", persisted.EncryptedPath)
	}
	if persisted.Size != 2000 {
		t.Errorf("size should reflect the listing (larger media size preserved), got %d", persisted.Size)
	}
}

// TestPersistFromListIdempotent resuming a listing after a crash must not
// corrupt prior rows: baking over the same directory twice leaves the bucket
// consistent (single row per path).
func TestPersistFromListOverwriteNoGrowth(t *testing.T) {
	s := newBatchTestStore(t)
	d := dao.NewFileDAO(s)
	t.Cleanup(d.Stop)

	for round := 0; round < 2; round++ {
		infos := make([]*dao.FileInfo, 0, 100)
		for i := 0; i < 100; i++ {
			name := fmt.Sprintf("f%03d", i)
			infos = append(infos, d.PrepareFromAlistResponse("/d/"+name, map[string]interface{}{
				"name": name, "size": float64(i), "is_dir": false,
			}, ""))
		}
		if err := d.PersistFromList(infos); err != nil {
			t.Fatalf("round %d PersistFromList: %v", round, err)
		}
		if got := len(d.List(1000)); got != 100 {
			t.Fatalf("round %d List length = %d, want 100 (no growth)", round, got)
		}
	}
}

// BenchmarkPersistFromList5000 measures the whole "5000-item directory" listing
// write pass: prepare all items + flush in one transaction. The audit's p95
// budget for the internal listing step is 150ms; this isolates the
// storage-adjacent portion so regressions in batch writing are visible.
func BenchmarkPersistFromList5000(b *testing.B) {
	s, err := storage.NewStore(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	d := dao.NewFileDAO(s)
	defer d.Stop()

	const n = 5000
	paths := make([]string, n)
	items := make([]map[string]interface{}, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("file%04d.mp4", i)
		paths[i] = "/movies/" + name
		items[i] = map[string]interface{}{"name": name, "size": float64(1000 + i), "is_dir": false}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prepared := make([]*dao.FileInfo, 0, n)
		for j := 0; j < n; j++ {
			prepared = append(prepared, d.PrepareFromAlistResponse(paths[j], items[j], ""))
		}
		if err := d.PersistFromList(prepared); err != nil {
			b.Fatal(err)
		}
	}
}
