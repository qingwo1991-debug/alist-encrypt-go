package dao

import (
	"testing"

	"github.com/alist-encrypt-go/internal/storage"
)

func TestExportAllReadErrorsAndPathFallback(t *testing.T) {
	var nilDAO *FileDAO
	if _, err := nilDAO.ExportAll(); err == nil {
		t.Fatal("nil store silently succeeded")
	}
	s, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := NewFileDAO(s)
	defer d.Stop()
	defer s.Close()
	if err := s.SetJSON(storage.BucketFileInfo, "/legacy", &FileInfo{Name: "legacy"}); err != nil {
		t.Fatal(err)
	}
	items, err := d.ExportAll()
	if err != nil || len(items) != 1 || items[0].Path != "/legacy" {
		t.Fatalf("items=%v err=%v", items, err)
	}
	if err := s.Set(storage.BucketFileInfo, "/corrupt", []byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ExportAll(); err == nil {
		t.Fatal("corrupt JSON silently skipped")
	}
}
