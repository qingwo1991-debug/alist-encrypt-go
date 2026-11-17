package dao

import (
	"context"
	"testing"

	"github.com/alist-encrypt-go/internal/storage"
)

type stubMetaWriter struct{}

func (stubMetaWriter) UpsertFileMeta(info *FileInfo) error { return nil }

type stubInfoReader struct {
	info *FileInfo
	hit  bool
}

func (s *stubInfoReader) GetFileInfoByPath(ctx context.Context, path string) (*FileInfo, bool) {
	return s.info, s.hit
}

// With a meta writer configured, persistInfo skips the BoltDB fileinfo bucket,
// so Get must fall back to the injected reader or every restart loses cached
// content metadata even though the rows still exist in MySQL.
func TestGetHydratesFromFileInfoReader(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := NewFileDAO(store)
	t.Cleanup(func() { files.Stop(); _ = store.Close() })
	files.SetFileMetaWriter(stubMetaWriter{})

	want := &FileInfo{
		Path:           "/enc/ movie.mp4",
		EncryptedPath:  "/enc/abc.bin",
		Name:           "movie.mp4",
		Size:           1234,
		CiphertextSize: 1266,
		ContentVersion: 2,
		HeaderLen:      32,
		NonceField:     make([]byte, 16),
	}
	files.SetFileInfoReader(&stubInfoReader{info: want, hit: true})

	got, ok := files.Get(want.Path)
	if !ok || got == nil {
		t.Fatal("expected hydrated FileInfo")
	}
	if got.ContentVersion != 2 || got.CiphertextSize != 1266 || string(got.NonceField) != string(make([]byte, 16)) {
		t.Fatalf("hydrated info lost content metadata: %+v", got)
	}

	// Second read must come from the path cache, not the reader again.
	files.SetFileInfoReader(&stubInfoReader{hit: false})
	if _, ok := files.Get(want.Path); !ok {
		t.Fatal("expected path-cache hit after hydration")
	}
}

func TestGetWithoutReaderStillMisses(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := NewFileDAO(store)
	t.Cleanup(func() { files.Stop(); _ = store.Close() })
	files.SetFileMetaWriter(stubMetaWriter{})

	if _, ok := files.Get("/never-seen.mp4"); ok {
		t.Fatal("unexpected hit without reader")
	}
}
