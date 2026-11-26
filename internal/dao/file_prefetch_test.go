package dao_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

// countingBatchReader is a MySQL-style reader that counts single-path and
// batch calls separately so the tests can prove which code path ran.
type countingBatchReader struct {
	mu        sync.Mutex
	infos     map[string]*dao.FileInfo
	single    atomic.Int32
	batch     atomic.Int32
	batchSize []int
}

func (r *countingBatchReader) GetFileInfoByPath(_ context.Context, path string) (*dao.FileInfo, bool) {
	r.single.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	info, ok := r.infos[path]
	if !ok {
		return nil, false
	}
	// Like MySQLFileMetaWriter, hand back a fresh object per lookup.
	copyInfo := *info
	copyInfo.NonceField = append([]byte(nil), info.NonceField...)
	return &copyInfo, true
}

// GetFileInfosByPaths honours chunking: each call sees at most the chunk of
// paths it was given, exactly like mysqlstore.GetFileMetaByPaths.
func (r *countingBatchReader) GetFileInfosByPaths(_ context.Context, paths []string) map[string]*dao.FileInfo {
	r.batch.Add(1)
	r.mu.Lock()
	r.batchSize = append(r.batchSize, len(paths))
	r.mu.Unlock()
	out := make(map[string]*dao.FileInfo)
	for _, p := range paths {
		if info, ok := r.infos[p]; ok {
			copyInfo := *info
			copyInfo.NonceField = append([]byte(nil), info.NonceField...)
			out[p] = &copyInfo
		}
	}
	return out
}

func (r *countingBatchReader) snapshot() (single, batch int32, sizes []int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.single.Load(), r.batch.Load(), append([]int(nil), r.batchSize...)
}

func newReaderDAO(t *testing.T, reader *countingBatchReader) *dao.FileDAO {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store)
	t.Cleanup(func() { files.Stop(); _ = store.Close() })
	// With a meta writer configured, persistInfo skips BoltDB so the reader is
	// the only external source — the production MySQL deployment shape.
	files.SetFileMetaWriter(noopMetaWriter{})
	files.SetFileInfoReader(reader)
	return files
}

type noopMetaWriter struct{}

func (noopMetaWriter) UpsertFileMeta(*dao.FileInfo) error { return nil }

// A miss must be remembered: the second Get for the same path must not hit the
// reader again.
func TestNegativeCacheCachesReaderMiss(t *testing.T) {
	reader := &countingBatchReader{infos: map[string]*dao.FileInfo{}}
	files := newReaderDAO(t, reader)

	for i := 0; i < 5; i++ {
		if _, ok := files.Get("/missing/file.bin"); ok {
			t.Fatal("unexpected hit")
		}
	}
	if single, batch, _ := reader.snapshot(); single != 1 || batch != 0 {
		t.Fatalf("reader single=%d batch=%d, want single=1 batch=0", single, batch)
	}
}

// A miss is negative-cached, but a Set on the same path must clear it so the
// next Get observes the write (through the path cache here; and the reader is
// consulted again once the entry is gone).
func TestNegativeCacheClearedBySet(t *testing.T) {
	reader := &countingBatchReader{infos: map[string]*dao.FileInfo{}}
	files := newReaderDAO(t, reader)

	if _, ok := files.Get("/dir/new.bin"); ok {
		t.Fatal("unexpected hit")
	}
	if err := files.Set(&dao.FileInfo{Path: "/dir/new.bin", Name: "new.bin", Size: 10}); err != nil {
		t.Fatal(err)
	}
	got, ok := files.Get("/dir/new.bin")
	if !ok || got == nil || got.Size != 10 {
		t.Fatalf("Set not observed after negative cache: %+v ok=%v", got, ok)
	}
	// Clear the positive entry the way Delete does and prove the negative
	// entry is gone too: the reader must be asked again.
	if err := files.Delete("/dir/new.bin"); err != nil {
		t.Fatal(err)
	}
	if _, ok := files.Get("/dir/new.bin"); ok {
		t.Fatal("unexpected hit after delete")
	}
	if single, _, _ := reader.snapshot(); single != 2 {
		t.Fatalf("reader single calls=%d, want 2 (initial miss + post-delete lookup)", single)
	}
}

// Every mutator that writes a path must drop its cached miss.
func TestNegativeCacheClearedByEveryMutator(t *testing.T) {
	mutators := map[string]func(d *dao.FileDAO, p string){
		"Set":                       func(d *dao.FileDAO, p string) { _ = d.Set(&dao.FileInfo{Path: p, Name: "x", Size: 1}) },
		"SetComplete":               func(d *dao.FileDAO, p string) { _ = d.SetComplete(&dao.FileInfo{Path: p, Name: "x", Size: 1}) },
		"SetEncPathMapping":         func(d *dao.FileDAO, p string) { d.SetEncPathMapping(p, p+".enc") },
		"SetEncPathMappingWithInfo": func(d *dao.FileDAO, p string) { d.SetEncPathMappingWithInfo(p, p+".enc", "x", 1, false) },
		"SetFileSize":               func(d *dao.FileDAO, p string) { d.SetFileSize(p, 1, time.Hour) },
		"DeleteFileSize":            func(d *dao.FileDAO, p string) { d.DeleteFileSize(p) },
		"InvalidateDisplayPath":     func(d *dao.FileDAO, p string) { d.InvalidateDisplayPath(p) },
		"InvalidateDisplaySubtree":  func(d *dao.FileDAO, p string) { d.InvalidateDisplaySubtree("/dir") },
		"DeleteEncPathMapping":      func(d *dao.FileDAO, p string) { d.DeleteEncPathMapping(p) },
		"InvalidateRawURLForScope":  func(d *dao.FileDAO, p string) { d.InvalidateRawURLForScope(p, "anon") },
		"PrepareFromAlistResponse": func(d *dao.FileDAO, p string) {
			d.PrepareFromAlistResponse(p, map[string]interface{}{"name": "x", "size": float64(1)}, "")
		},
		"PersistFromList/SetFromAlist": func(d *dao.FileDAO, p string) {
			_ = d.SetFromAlistResponse(p, map[string]interface{}{"name": "x", "size": float64(1)}, "")
			_ = d.PersistFromList([]*dao.FileInfo{{Path: p, Name: "x", Size: 1}})
		},
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			reader := &countingBatchReader{infos: map[string]*dao.FileInfo{}}
			files := newReaderDAO(t, reader)
			const p = "/dir/file.bin"
			if _, ok := files.Get(p); ok {
				t.Fatal("unexpected hit")
			}
			if _, ok := files.Get("/dir"); ok {
				t.Fatal("unexpected hit")
			}
			before, _, _ := reader.snapshot()
			mutate(files, p)
			// Remove whatever positive entry the mutator created so Get has to
			// consult the reader again; if the miss survived, it would not.
			files.InvalidateDisplaySubtree("/dir")
			_, _ = files.Get(p)
			if after, _, _ := reader.snapshot(); after == before {
				t.Fatalf("negative cache entry survived %s: reader calls %d -> %d", name, before, after)
			}
		})
	}
}

// An expired miss is forgotten even without a write.
func TestNegativeCacheTTLExpiry(t *testing.T) {
	reader := &countingBatchReader{infos: map[string]*dao.FileInfo{}}
	files := newReaderDAO(t, reader)
	// Shrink the TTL on the DAO's own negative cache for the test.
	files.SetMissCacheTTLForTest(20 * time.Millisecond)

	if _, ok := files.Get("/ttl/file.bin"); ok {
		t.Fatal("unexpected hit")
	}
	if _, ok := files.Get("/ttl/file.bin"); ok {
		t.Fatal("unexpected hit")
	}
	if single, _, _ := reader.snapshot(); single != 1 {
		t.Fatalf("reader single calls=%d before expiry, want 1", single)
	}
	time.Sleep(40 * time.Millisecond)
	_, _ = files.Get("/ttl/file.bin")
	if single, _, _ := reader.snapshot(); single != 2 {
		t.Fatalf("reader single calls=%d after expiry, want 2", single)
	}
}

// Prefetch issues ONE batch call for N paths, caches hits and negative-caches
// misses; subsequent per-entry Get calls touch neither the batch nor the
// single-path reader.
func TestPrefetchOneBatchCallCachesHitsAndMisses(t *testing.T) {
	const n = 150
	infos := map[string]*dao.FileInfo{}
	paths := make([]string, 0, n)
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("/enc/dir/file%03d.mp4", i)
		paths = append(paths, p)
		if i%2 == 0 { // half the files have metadata rows, half do not
			infos[p] = &dao.FileInfo{Path: p, EncryptedPath: p, Name: fmt.Sprintf("file%03d.mp4", i), Size: int64(1000 + i), ContentVersion: 3, CiphertextSize: int64(1100 + i), NonceField: []byte("nonce")}
		}
	}
	reader := &countingBatchReader{infos: infos}
	files := newReaderDAO(t, reader)

	files.Prefetch(context.Background(), paths)
	single, batch, sizes := reader.snapshot()
	if single != 0 || batch != 1 {
		t.Fatalf("prefetch reader calls single=%d batch=%d, want 0/1", single, batch)
	}
	if len(sizes) != 1 || sizes[0] != n {
		t.Fatalf("batch sizes=%v, want one call with %d paths", sizes, n)
	}

	for i, p := range paths {
		got, ok := files.Get(p)
		if i%2 == 0 {
			if !ok || got == nil || got.Size != int64(1000+i) || got.ContentVersion != 3 {
				t.Fatalf("hit %s not cached by prefetch: %+v ok=%v", p, got, ok)
			}
		} else if ok {
			t.Fatalf("miss %s should not resolve", p)
		}
	}
	single, batch, _ = reader.snapshot()
	if single != 0 || batch != 1 {
		t.Fatalf("Get after prefetch hit the reader: single=%d batch=%d", single, batch)
	}
}

// Paths already in the path cache are excluded from the batch, as are
// duplicates and empty strings.
func TestPrefetchSkipsAlreadyCachedPaths(t *testing.T) {
	infos := map[string]*dao.FileInfo{}
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("/enc/h%d.bin", i)
		infos[p] = &dao.FileInfo{Path: p, Name: fmt.Sprintf("h%d.bin", i), Size: 5}
	}
	reader := &countingBatchReader{infos: infos}
	files := newReaderDAO(t, reader)

	// Warm two paths through the single-path reader (they land in the path cache).
	_, _ = files.Get("/enc/h0.bin")
	_, _ = files.Get("/enc/h1.bin")
	before, _, _ := reader.snapshot()

	paths := []string{"/enc/h0.bin", "/enc/h1.bin", "/enc/h2.bin", "/enc/h2.bin", "/enc/missing.bin", ""}
	files.Prefetch(context.Background(), paths)
	single, batch, sizes := reader.snapshot()
	if single != before || batch != 1 {
		t.Fatalf("prefetch reader calls single=%d batch=%d, want single unchanged (%d) and batch=1", single, batch, before)
	}
	// h0/h1 are in the path cache; duplicate h2 and the empty path collapse;
	// remaining: h2 + missing.
	if sizes[0] != 2 {
		t.Fatalf("batch asked for %d paths, want 2", sizes[0])
	}
	if _, ok := files.Get("/enc/h2.bin"); !ok {
		t.Fatal("h2 should have been prefetched")
	}
	if _, ok := files.Get("/enc/missing.bin"); ok {
		t.Fatal("missing should not resolve")
	}
	// Neither Get touched the reader.
	single, batch, _ = reader.snapshot()
	if single != before || batch != 1 {
		t.Fatalf("Get after prefetch hit the reader: single=%d batch=%d", single, batch)
	}
}

// singlePathOnlyReader implements only FileInfoReader (no batch method).
type singlePathOnlyReader struct {
	info *dao.FileInfo
}

func (r *singlePathOnlyReader) GetFileInfoByPath(_ context.Context, path string) (*dao.FileInfo, bool) {
	if r.info != nil && r.info.Path == path {
		return r.info, true
	}
	return nil, false
}

// Without a batch reader Prefetch is a no-op and Get keeps per-path semantics.
func TestPrefetchNoopWithSinglePathReader(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store)
	t.Cleanup(func() { files.Stop(); _ = store.Close() })
	files.SetFileMetaWriter(noopMetaWriter{})
	want := &dao.FileInfo{Path: "/plain/a.bin", Name: "a.bin", Size: 3}
	files.SetFileInfoReader(&singlePathOnlyReader{info: want})

	files.Prefetch(context.Background(), []string{"/plain/a.bin", "/plain/b.bin"})
	if got, ok := files.Get("/plain/a.bin"); !ok || got.Size != 3 {
		t.Fatalf("single-path reader Get: %+v ok=%v", got, ok)
	}
}

// Concurrent Prefetch + Get must not race (guarded by run with -race).
func TestPrefetchConcurrentWithGet(t *testing.T) {
	infos := map[string]*dao.FileInfo{}
	paths := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		p := fmt.Sprintf("/race/f%03d.bin", i)
		paths = append(paths, p)
		if i%3 == 0 {
			infos[p] = &dao.FileInfo{Path: p, Name: p, Size: 1}
		}
	}
	reader := &countingBatchReader{infos: infos}
	files := newReaderDAO(t, reader)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				p := paths[(w*50+i)%len(paths)]
				_, _ = files.Get(p)
				if i%10 == 0 {
					files.Prefetch(context.Background(), paths[:50])
				}
				if i%7 == 0 {
					_ = files.Set(&dao.FileInfo{Path: p, Name: "x", Size: 2})
				}
			}
		}(w)
	}
	wg.Wait()
}
