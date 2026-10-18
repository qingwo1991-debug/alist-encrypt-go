package dao

import (
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/storage"
)

// The separate durable confirmation cache must follow mapping invalidation, not
// merely the volatile PathEntry. Do not claim detection of same-size replacements.
func TestListingMappingChangesFenceDurablePlayback(t *testing.T) {
	for _, change := range []string{"size", "type", "path", "path-sequence", "same-object"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			store, err := storage.NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			files := NewFileDAO(store)
			t.Cleanup(func() { files.Stop(); _ = store.Close() })
			info := &FileInfo{Path: "/plain.mp4", EncryptedPath: "/raw-old", Name: "plain.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: make([]byte, 16), GeometryIdentity: "confirmed-object", GeometryConfirmedAt: time.Now()}
			epoch := files.PlaybackEpoch(info.Path)
			if !files.PublishConfirmedPlayback(info, epoch) {
				t.Fatal("seed confirmation failed")
			}
			if _, hit := files.GetConfirmedPlayback(info.GeometryIdentity); !hit {
				t.Fatal("seed confirmation absent")
			}
			raw, size, isDir := info.EncryptedPath, int64(132), false
			switch change {
			case "size":
				size = 164
			case "type":
				isDir = true
			case "path", "path-sequence":
				raw = "/raw-new"
			}
			if change == "path-sequence" {
				files.SetEncPathMapping(info.Path, raw)
			}
			files.SetEncPathMappingWithInfo(info.Path, raw, info.Name, size, isDir)
			wantHit := change == "same-object"
			if _, hit := files.GetConfirmedPlayback(info.GeometryIdentity); hit != wantHit {
				t.Fatalf("confirmation hit=%v after %s", hit, change)
			}
			if !wantHit && files.PublishConfirmedPlayback(info, epoch) {
				t.Fatal("old loader epoch republished confirmation")
			}
			if wantHit && files.PlaybackEpoch(info.Path) != epoch {
				t.Fatal("unchanged listing fenced valid loaders")
			}
			files.Stop()
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store, err = storage.NewStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			files = NewFileDAO(store)
			if _, hit := files.GetConfirmedPlayback(info.GeometryIdentity); hit != wantHit {
				t.Fatalf("durable confirmation hit=%v after restart following %s", hit, change)
			}
		})
	}
}

func TestListingMappingPreservesPlaybackAdmissionsOnlyForSameObject(t *testing.T) {
	for _, name := range []string{"same-object", "changed-object", "changed-size", "changed-type", "changed-object-mapping-sequence"} {
		t.Run(name, func(t *testing.T) {
			files := newTestFileDAO(t)
			defer files.Stop()
			confirmed := time.Now().Truncate(time.Second)
			info := &FileInfo{Path: "/plain.mp4", EncryptedPath: "/raw-old", Name: "plain.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: make([]byte, 16), RawURL: "https://cdn.test/video?fid=old", RawURLIdentity: "transport", RawURLAuthScope: "trusted_local", UpstreamFetchedAt: confirmed, GeometryIdentity: "geometry", GeometryConfirmedAt: confirmed}
			if err := files.Set(info); err != nil {
				t.Fatal(err)
			}
			raw, size := "/raw-old", int64(132)
			if name == "changed-object" || name == "changed-object-mapping-sequence" {
				raw = "/raw-new"
			}
			if name == "changed-size" {
				size = 164
			}
			if name == "changed-object-mapping-sequence" {
				files.SetEncPathMapping(info.Path, raw)
				mapped, ok := files.Get(info.Path)
				if !ok || mapped.RawURLIdentity != "" || mapped.GeometryIdentity != "" || mapped.RawURL != "" {
					t.Fatalf("raw mapping retained old admission: %+v", mapped)
				}
			}
			files.SetEncPathMappingWithInfo(info.Path, raw, info.Name, size, name == "changed-type")
			got, ok := files.Get(info.Path)
			if !ok {
				t.Fatal("mapping absent")
			}
			if name != "same-object" {
				if got.RawURLIdentity != "" || got.GeometryIdentity != "" || !got.GeometryConfirmedAt.IsZero() || got.RawURL != "" || got.HeaderLen != 0 || len(got.NonceField) != 0 {
					t.Fatalf("replacement inherited old admissions: %+v", got)
				}
			} else if got.RawURLIdentity != info.RawURLIdentity || got.GeometryIdentity != info.GeometryIdentity || !got.GeometryConfirmedAt.Equal(confirmed) || got.RawURL != info.RawURL || got.RawURLAuthScope != info.RawURLAuthScope || got.Size != 100 {
				t.Fatalf("listing discarded playback admissions: %+v", got)
			}
		})
	}
}
