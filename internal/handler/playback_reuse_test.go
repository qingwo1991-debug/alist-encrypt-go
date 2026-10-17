package handler

import (
	"context"
	"github.com/alist-encrypt-go/internal/proxy"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestTrustedHotHeadUsesOnlyConfirmedGeometry(t *testing.T) {
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
	rule := &config.PasswdInfo{Password: "pw", EncType: "aesctr", Enable: true}
	identity := playbackIdentity(cfg, cfg.GetAlistURL(), "/raw", rule, nil)
	if !files.PublishConfirmedPlayback(&dao.FileInfo{Path: "/plain.mp4", EncryptedPath: "/raw", Size: 123, CiphertextSize: 155, ContentVersion: 2, HeaderLen: 32, NonceField: make([]byte, 16), GeometryIdentity: identity, GeometryConfirmedAt: time.Now()}, files.PlaybackEpoch("/plain.mp4")) {
		t.Fatal("publish")
	}
	var network atomic.Int32
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { network.Add(1); w.WriteHeader(500) }))
	defer upstream.Close()
	rr := httptest.NewRecorder()
	executeDecryptPlayback(decryptPlaybackRequest{ResponseWriter: rr, Request: httptest.NewRequest(http.MethodHead, "/plain.mp4", nil), Config: cfg, StreamProxy: proxy.NewStreamProxy(cfg), FileDAO: files, PasswdInfo: rule, FileItem: FileItem{DisplayPath: "/plain.mp4", EncryptedPath: "/raw", FileName: "plain.mp4"}, TargetURL: upstream.URL, ConsumerScenario: consumerScenarioWebDAV})
	if network.Load() != 0 || rr.Code != 200 || rr.Header().Get("Content-Length") != "123" || rr.Body.Len() != 0 {
		t.Fatalf("network=%d code=%d length=%s body=%d", network.Load(), rr.Code, rr.Header().Get("Content-Length"), rr.Body.Len())
	}
}

func TestPlaybackIdentityTrustedSharesTokensButFencesOriginRuleAndProfile(t *testing.T) {
	cfg := config.LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	a := http.Header{"Authorization": []string{"Basic token-a"}}
	b := http.Header{"Authorization": []string{"Basic token-b"}}
	first := playbackIdentity(cfg, "https://origin", "/raw", nil, a)
	if first != playbackIdentity(cfg, "https://origin", "/raw", nil, b) {
		t.Fatal("local token fragmented identity")
	}
	if first == playbackIdentity(cfg, "https://other", "/raw", nil, a) {
		t.Fatal("origin omitted")
	}
	if first == playbackIdentity(cfg, "https://origin", "/raw-other", nil, a) {
		t.Fatal("raw path omitted")
	}
	server.PlaybackProfile = config.PlaybackProfileStandard
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	if playbackIdentity(cfg, "https://origin", "/raw", nil, a) == playbackIdentity(cfg, "https://origin", "/raw", nil, b) {
		t.Fatal("standard credentials shared")
	}
}

func TestPlaybackTransportCannotReplaceConfirmedPlainGeometry(t *testing.T) {
	cfg := config.LoadFromBaseDir(t.TempDir())
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	defer func() { files.Stop(); store.Close() }()
	info := &dao.FileInfo{Path: "/plain.mp4", EncryptedPath: "/raw", Size: 100, ContentVersion: 2, HeaderLen: 32, CiphertextSize: 132, NonceField: make([]byte, 16), GeometryIdentity: "geometry", GeometryConfirmedAt: time.Now()}
	epoch := files.PlaybackEpoch(info.Path)
	if !files.PublishConfirmedPlayback(info, epoch) {
		t.Fatal("confirmed publication")
	}
	ctx := context.WithValue(context.Background(), playbackTransportKey{}, playbackTransportAdmission{epoch: epoch, identity: "transport", scope: "anon", revision: cfg.RuntimeRevision()})
	if !cachePlaybackRawURL(ctx, files, info.Path, info.EncryptedPath, "https://cdn/video?Expires=9999999999", 9999, nil) {
		t.Fatal("transport publication")
	}
	got, _ := files.Get(info.Path)
	if got.Size != 100 || got.CiphertextSize != 132 || got.HeaderLen != 32 || got.GeometryIdentity != "geometry" {
		t.Fatalf("geometry poisoned: %+v", got)
	}
	if got.RawURLIdentity != "transport" {
		t.Fatal("transport identity not published")
	}
	files.InvalidateDisplayPath(info.Path)
	if cachePlaybackRawURL(ctx, files, info.Path, info.EncryptedPath, "https://cdn/old", 132, nil) {
		t.Fatal("old transport republished after invalidate")
	}
}
