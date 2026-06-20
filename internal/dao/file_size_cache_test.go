package dao

import (
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
)

func newTestFileDAO(t *testing.T) *FileDAO {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("storage.NewStore: %v", err)
	}
	return NewFileDAO(store)
}

func TestSetFileSizePreservesLargeMediaSize(t *testing.T) {
	fileDAO := newTestFileDAO(t)
	path := "/dav/movie.mp4"

	fileDAO.SetFileSize(path, 5_112_444_347, time.Hour)
	fileDAO.SetFileSize(path, 12, time.Hour)

	got, ok := fileDAO.GetFileSize(path)
	if !ok {
		t.Fatal("expected cached size")
	}
	if got != 5_112_444_347 {
		t.Fatalf("size=%d, want 5112444347", got)
	}
}

func TestSetFileSizeAllowsLargeMediaSizeRefresh(t *testing.T) {
	fileDAO := newTestFileDAO(t)
	path := "/dav/movie.mp4"

	fileDAO.SetFileSize(path, 5_112_444_347, time.Hour)
	fileDAO.SetFileSize(path, 4_900_000_000, time.Hour)

	got, ok := fileDAO.GetFileSize(path)
	if !ok {
		t.Fatal("expected cached size")
	}
	if got != 4_900_000_000 {
		t.Fatalf("size=%d, want 4900000000", got)
	}
}

func TestSetEncPathMappingWithInfoPreservesLargeMediaSize(t *testing.T) {
	fileDAO := newTestFileDAO(t)
	displayPath := "/dav/movie.mp4"
	encryptedPath := "/dav/encrypted.bin"

	fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, "movie.mp4", 5_112_444_347, false)
	fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, "movie.mp4", 12, false)

	got, ok := fileDAO.GetFileSize(displayPath)
	if !ok {
		t.Fatal("expected cached display size")
	}
	if got != 5_112_444_347 {
		t.Fatalf("display size=%d, want 5112444347", got)
	}

	got, ok = fileDAO.GetFileSize(encryptedPath)
	if !ok {
		t.Fatal("expected cached encrypted size")
	}
	if got != 5_112_444_347 {
		t.Fatalf("encrypted size=%d, want 5112444347", got)
	}
}
