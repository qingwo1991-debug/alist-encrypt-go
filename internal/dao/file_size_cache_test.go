package dao

import (
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/encryption"
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

func TestSetPreservesV2PlainSizeWhenPropfindReportsCiphertextSize(t *testing.T) {
	fileDAO := newTestFileDAO(t)
	path := "/dav/movie.mp4"

	if err := fileDAO.Set(&FileInfo{
		Path:           path,
		Name:           "movie.mp4",
		Size:           4_438_676_680,
		CiphertextSize: 4_438_676_712,
		ContentVersion: encryption.ContentVersionV2,
		HeaderLen:      encryption.ContentHeaderSize(),
		NonceField:     make([]byte, 16),
	}); err != nil {
		t.Fatalf("set v2 info: %v", err)
	}
	if err := fileDAO.Set(&FileInfo{
		Path: path,
		Name: "movie.mp4",
		Size: 4_438_676_712,
	}); err != nil {
		t.Fatalf("set propfind info: %v", err)
	}

	got, ok := fileDAO.Get(path)
	if !ok {
		t.Fatal("expected cached file info")
	}
	if got.Size != 4_438_676_680 {
		t.Fatalf("size=%d, want plaintext size", got.Size)
	}
	if got.CiphertextSize != 4_438_676_712 || got.ContentVersion != encryption.ContentVersionV2 || got.HeaderLen != encryption.ContentHeaderSize() {
		t.Fatalf("v2 metadata not preserved: %+v", got)
	}
}

func TestSetEncPathMappingWithInfoPreservesV2PlainSize(t *testing.T) {
	fileDAO := newTestFileDAO(t)
	displayPath := "/dav/movie.mp4"
	encryptedPath := "/dav/encrypted.bin"

	if err := fileDAO.Set(&FileInfo{
		Path:           displayPath,
		EncryptedPath:  encryptedPath,
		Name:           "movie.mp4",
		Size:           4_438_676_680,
		CiphertextSize: 4_438_676_712,
		ContentVersion: encryption.ContentVersionV2,
		HeaderLen:      encryption.ContentHeaderSize(),
		NonceField:     make([]byte, 16),
	}); err != nil {
		t.Fatalf("set v2 info: %v", err)
	}

	fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, "movie.mp4", 4_438_676_712, false)

	got, ok := fileDAO.Get(displayPath)
	if !ok {
		t.Fatal("expected cached display info")
	}
	if got.Size != 4_438_676_680 {
		t.Fatalf("display size=%d, want plaintext size", got.Size)
	}
	if got.CiphertextSize != 4_438_676_712 || got.ContentVersion != encryption.ContentVersionV2 {
		t.Fatalf("v2 metadata not preserved: %+v", got)
	}
}
