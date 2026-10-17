package handler

import (
	"bytes"
	"context"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestConfirmedColdV2InspectionSixteenCallersAndWarmReuse(t *testing.T) {
	header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 4096, bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	body := append(header, make([]byte, 4096)...)
	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			close(entered)
		}
		<-release
		http.ServeContent(w, r, "movie.bin", time.Time{}, bytes.NewReader(body))
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
	request := decryptPlaybackRequest{Request: httptest.NewRequest("GET", "/dav/movie.mp4", nil), Config: cfg, FileDAO: files, StreamProxy: proxy.NewStreamProxy(cfg), PasswdInfo: &config.PasswdInfo{Enable: true, EncType: "aesctr", Password: "pw"}, FileItem: FileItem{DisplayPath: "/movie.mp4", EncryptedPath: "/raw", FileName: "movie.mp4"}, TargetURL: upstream.URL, ConsumerScenario: consumerScenarioWebDAV}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta, ok := confirmedPlaybackMeta(request, nil, int64(len(body)))
			if !ok || meta.PlainSize != 4096 || meta.Version != 2 {
				t.Errorf("meta=%+v confirmed=%v", meta, ok)
			}
		}()
	}
	<-entered
	close(release)
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("cold inspection requests=%d want1", hits.Load())
	}
	for i := 0; i < 3; i++ {
		if _, ok := confirmedPlaybackMeta(request, nil, 0); !ok {
			t.Fatal("warm miss")
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("warm reprobed count=%d", hits.Load())
	}
}

func TestWebDAVMutationFencesConfirmedGeometry(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			defer upstream.Close()
			ah, files := newTestAlistHandler(t, upstream.URL, &config.PasswdInfo{Enable: false})
			defer ah.Stop()
			info := &dao.FileInfo{Path: "/plain", EncryptedPath: "/raw", Size: 12, GeometryIdentity: "identity", GeometryConfirmedAt: time.Now()}
			epoch := files.PlaybackEpoch(info.Path)
			if !files.PublishConfirmedPlayback(info, epoch) {
				t.Fatal("publish")
			}
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: files, passwdDAO: ah.passwdDAO, streamProxy: proxy.NewStreamProxy(ah.cfg), stdClient: upstream.Client(), shortClient: upstream.Client()}
			rr := httptest.NewRecorder()
			h.Handle(rr, httptest.NewRequest(method, "/dav/plain", nil))
			if rr.Code != 204 {
				t.Fatalf("mutation status=%d", rr.Code)
			}
			if _, hit := files.GetConfirmedPlayback("identity"); hit {
				t.Fatal("old geometry survived mutation")
			}
			if files.PublishConfirmedPlayback(info, epoch) {
				t.Fatal("old-flight republished")
			}
		})
	}
}

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
