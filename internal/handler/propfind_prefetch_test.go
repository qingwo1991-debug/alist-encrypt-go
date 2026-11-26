package handler

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// handlerBatchReader is a MySQL-shaped FileInfoReader whose single-path calls
// are what the production bug was made of (one full table scan per entry).
type handlerBatchReader struct {
	mu     sync.Mutex
	infos  map[string]*dao.FileInfo
	single int
	batch  int
	paths  []string
}

func (r *handlerBatchReader) GetFileInfoByPath(_ context.Context, path string) (*dao.FileInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.single++
	info, ok := r.infos[path]
	if !ok {
		return nil, false
	}
	cp := *info
	cp.NonceField = append([]byte(nil), info.NonceField...)
	return &cp, true
}

func (r *handlerBatchReader) GetFileInfosByPaths(_ context.Context, paths []string) map[string]*dao.FileInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batch++
	r.paths = append(r.paths, paths...)
	out := make(map[string]*dao.FileInfo)
	for _, p := range paths {
		if info, ok := r.infos[p]; ok {
			cp := *info
			cp.NonceField = append([]byte(nil), info.NonceField...)
			out[p] = &cp
		}
	}
	return out
}

type handlerNoopMetaWriter struct{}

func (handlerNoopMetaWriter) UpsertFileMeta(*dao.FileInfo) error { return nil }

// parsePropfindResponse reads every entry's raw path twice (propfindPlainSize
// and the direct Get) and the decrypted display path once more via Set paths.
// With a MySQL-backed cache each cold miss was a path lookup in the database;
// the prefetch must collapse all of them into ONE batch call so the per-entry
// loop never touches the single-path reader.
func TestParsePropfindResponsePrefetchesAllEntryPathsInOneBatch(t *testing.T) {
	passwd := config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/encrypt/"},
	}
	cfg := config.LoadFromBaseDir(t.TempDir())
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	conv := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	const n = 300 // above propfindPersistentWriteThreshold so the loop takes the SetEncPathMappingWithInfo branch
	type entry struct{ enc, plain string }
	entries := make([]entry, 0, n)
	body := `<?xml version="1.0" encoding="utf-8"?><multistatus>`
	for i := 0; i < n; i++ {
		plain := fmt.Sprintf("video%03d.mp4", i)
		enc := conv.ToRealName(plain)
		entries = append(entries, entry{enc: enc, plain: plain})
		body += `<response><href>/dav/encrypt/` + enc + `</href><propstat><prop><displayname>` + enc + `</displayname><getcontentlength>12345</getcontentlength><resourcetype></resourcetype></prop></propstat></response>`
	}
	body += `</multistatus>`

	// Every other file has confirmed V2 geometry in MySQL; the rest have nothing.
	reader := &handlerBatchReader{infos: map[string]*dao.FileInfo{}}
	for i, e := range entries {
		if i%2 == 0 {
			p := "/encrypt/" + e.enc
			reader.infos[p] = &dao.FileInfo{Path: p, EncryptedPath: p, Name: e.plain, Size: 4096, CiphertextSize: 12345, ContentVersion: 2, HeaderLen: 32, NonceField: []byte("0123456789abcdef")}
		}
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	t.Cleanup(func() { files.Stop(); _ = store.Close() })
	files.SetFileMetaWriter(handlerNoopMetaWriter{})
	files.SetFileInfoReader(reader)

	h := &WebDAVHandler{cfg: cfg, passwdDAO: &staticPasswdDAO{info: &passwd}, fileDAO: files}
	got := h.parsePropfindResponse(context.Background(), []byte(body), "/encrypt/")
	if len(got) != n {
		t.Fatalf("entries=%d want %d", len(got), n)
	}

	reader.mu.Lock()
	single, batch, prefetched := reader.single, reader.batch, len(reader.paths)
	reader.mu.Unlock()
	if batch != 1 {
		t.Fatalf("batch reader calls=%d, want exactly 1", batch)
	}
	if single != 0 {
		t.Fatalf("single-path reader calls=%d, want 0 (per-entry loop must be served from cache)", single)
	}
	// Raw path for every entry + display path for every encrypted-name file.
	if want := n * 2; prefetched != want {
		t.Fatalf("prefetched paths=%d want %d", prefetched, want)
	}
	// Geometry for the hydrated half reached the cache under the raw path.
	for i := 0; i < n; i += 2 {
		if size, known := h.propfindPlainSize("/encrypt/"+entries[i].enc, 12345, &passwd); !known || size != 4096 {
			t.Fatalf("entry %d geometry not served from cache: size=%d known=%v", i, size, known)
		}
	}
}

// Repositories without batch support must behave exactly as before.
func TestParsePropfindResponseWithoutBatchReaderStillWorks(t *testing.T) {
	passwd := config.PasswdInfo{Password: "123456", EncType: "aesctr", EncName: true, Enable: true, EncPath: []string{"/encrypt/"}}
	cfg := config.LoadFromBaseDir(t.TempDir())
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}
	fileDAO := &recordingFileDAO{}
	h := &WebDAVHandler{cfg: cfg, passwdDAO: &staticPasswdDAO{info: &passwd}, fileDAO: fileDAO}
	conv := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	enc := conv.ToRealName("video0.mp4")
	body := `<?xml version="1.0" encoding="utf-8"?><multistatus><response><href>/dav/encrypt/` + enc + `</href><propstat><prop><displayname>` + enc + `</displayname><getcontentlength>12345</getcontentlength><resourcetype></resourcetype></prop></propstat></response></multistatus>`
	got := h.parsePropfindResponse(context.Background(), []byte(body), "/encrypt/")
	if len(got) != 1 {
		t.Fatalf("entries=%d", len(got))
	}
	if setCalls, _ := fileDAO.counts(); setCalls != 1 {
		t.Fatalf("set calls=%d want 1 (persistToStore branch)", setCalls)
	}
}
