package dao

import (
	"testing"

	"github.com/alist-encrypt-go/internal/storage"
)

func TestInvalidateDisplaySubtreeClearsDescendants(t *testing.T) {
	d := newTestFileDAO(t)

	d.SetEncPathMappingWithInfo("/enc/dir", "/enc/dir", "dir", 0, true)
	d.SetEncPathMappingWithInfo("/enc/dir/movie.mp4", "/enc/dir/a.bin", "movie.mp4", 100, false)
	d.SetEncPathMappingWithInfo("/enc/dir/sub", "/enc/dir/sub", "sub", 0, true)
	d.SetEncPathMappingWithInfo("/enc/dir/sub/song.mp3", "/enc/dir/sub/b.bin", "song.mp3", 200, false)
	d.SetEncPathMappingWithInfo("/enc/other.txt", "/enc/other.bin", "other.txt", 5, false)

	if err := d.Set(&FileInfo{Path: "/enc/dir/movie.mp4", Size: 100}); err != nil {
		t.Fatalf("Set file info: %v", err)
	}

	d.InvalidateDisplaySubtree("/enc/dir")

	for _, gone := range []string{
		"/enc/dir", "/enc/dir/movie.mp4", "/enc/dir/a.bin",
		"/enc/dir/sub", "/enc/dir/sub/song.mp3", "/enc/dir/sub/b.bin",
	} {
		if _, ok := d.Get(gone); ok {
			t.Fatalf("subtree entry %q should be invalidated", gone)
		}
	}
	if _, ok := d.Get("/enc/other.txt"); !ok {
		t.Fatal("unrelated entry should be kept")
	}
	if _, ok := d.Get("/enc/other.bin"); !ok {
		t.Fatal("unrelated encrypted entry should be kept")
	}

	raw, err := d.store.Get(storage.BucketFileInfo, "/enc/dir/movie.mp4")
	if err != nil {
		t.Fatalf("store get: %v", err)
	}
	if raw != nil {
		t.Fatal("persisted file info for descendant should be deleted")
	}
}
