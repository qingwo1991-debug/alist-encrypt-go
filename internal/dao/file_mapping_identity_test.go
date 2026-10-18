package dao

import (
	"testing"
	"time"
)

func TestListingMappingPreservesPlaybackAdmissionsOnlyForSameObject(t *testing.T) {
	for _, name := range []string{"same-object", "changed-object", "changed-size", "changed-object-mapping-sequence"} {
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
			files.SetEncPathMappingWithInfo(info.Path, raw, info.Name, size, false)
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
