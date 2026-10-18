package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestPropfindAliasRefreshDoesNotRotateTrustedPlaybackLocator(t *testing.T) {
	var network atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		network.Add(1)
		http.Error(w, "unexpected locator refresh", 500)
	}))
	defer upstream.Close()
	cfg := config.LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	defer func() { files.Stop(); store.Close() }()
	display, raw := "/plain.mp4", "/raw-object"
	now := time.Now()
	identity := playbackIdentity(cfg, upstream.URL, raw, nil, nil)
	info := &dao.FileInfo{Path: display, EncryptedPath: raw, Name: "plain.mp4", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: make([]byte, 16), RawURL: "https://cdn.test/video?fid=stable", RawURLIdentity: identity, RawURLAuthScope: "trusted_local", UpstreamFetchedAt: now, GeometryIdentity: "geometry", GeometryConfirmedAt: now}
	if err := files.Set(info); err != nil {
		t.Fatal(err)
	}
	// Exercise the exact DAO publication performed by PROPFIND alias rewrites,
	// interleaved with the shared transport resolver used by subsequent GETs.
	for i := 0; i < 3; i++ {
		files.SetEncPathMapping(display, raw)
		files.SetEncPathMappingWithInfo(display, raw, info.Name, 132, false)
		got, _ := files.Get(display)
		if got.RawURLIdentity != identity || got.GeometryIdentity != "geometry" || !got.GeometryConfirmedAt.Equal(now) {
			t.Fatalf("metadata refresh lost admission: %+v", got)
		}
		resolved := fetchRawURL(context.Background(), upstream.URL, display, raw, nil, files, time.Minute)
		if resolved.RawURL != info.RawURL || resolved.Source != "cache" {
			t.Fatalf("locator rotated after listing: %+v", resolved)
		}
	}
	if network.Load() != 0 {
		t.Fatalf("metadata caused %d locator requests", network.Load())
	}
}
