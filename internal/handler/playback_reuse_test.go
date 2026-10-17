package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestOldLocatorAdmissionCannotPublishIntoNewEpoch(t *testing.T) {
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
	epoch, revision := files.PlaybackEpoch("/plain"), cfg.RuntimeRevision()
	var hits atomic.Int32
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(500) }))
	defer upstream.Close()
	req := decryptPlaybackRequest{Request: httptest.NewRequest("GET", "/dav/plain", nil), Config: cfg, FileDAO: files, StreamProxy: proxy.NewStreamProxy(cfg), PasswdInfo: &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}, FileItem: FileItem{DisplayPath: "/plain", EncryptedPath: "/raw"}, TargetURL: upstream.URL, ConsumerScenario: consumerScenarioWebDAV, ExpectedGeometryEpoch: &epoch, ExpectedConfigRevision: &revision}
	// The transport locator was selected, then a write/refresh invalidated it.
	files.InvalidateDisplayPath("/plain")
	if _, ok := confirmedPlaybackMeta(req, nil, 4096); ok {
		t.Fatal("old admission accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("old locator was inspected")
	}
	rr := httptest.NewRecorder()
	req.ResponseWriter = rr
	executeDecryptPlayback(req)
	if rr.Code != 503 || hits.Load() != 0 {
		t.Fatalf("status=%d network=%d", rr.Code, hits.Load())
	}
	identity := playbackIdentity(cfg, cfg.GetAlistURL(), "/raw", req.PasswdInfo, nil)
	if _, hit := files.GetConfirmedPlayback(identity); hit {
		t.Fatal("old admission published into new epoch")
	}
}

func TestConfirmedColdV2InspectionSixteenCallersAndWarmReuse(t *testing.T) {
	header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 4096, bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	testSharedInspectionBody(t, append(header, make([]byte, 4096)...), 2, 1, 4096)
}
func TestConfirmedColdNonDefaultV3InspectionSixteenCallersAndWarmReuse(t *testing.T) {
	header, err := encryption.NewV3Header(4096, bytes.Repeat([]byte{7}, int(encryption.V3NonceFieldLen())), 73, 1234)
	if err != nil {
		t.Fatal(err)
	}
	total := encryption.V3CiphertextSize(4096, 73)
	testSharedInspectionBody(t, append(header, make([]byte, int(total)-len(header))...), 3, 2, 4096)
}
func testSharedInspectionBody(t *testing.T, body []byte, version int, wantRequests int32, plainSize int64) {
	t.Helper()
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
			if !ok || meta.PlainSize != plainSize || meta.Version != version || (version == 3 && (meta.ChunkSize != 73 || meta.KDFIterations != 1234)) {
				t.Errorf("meta=%+v confirmed=%v", meta, ok)
			}
		}()
	}
	<-entered
	close(release)
	wg.Wait()
	if hits.Load() != wantRequests {
		t.Fatalf("cold inspection requests=%d want1", hits.Load())
	}
	for i := 0; i < 3; i++ {
		if _, ok := confirmedPlaybackMeta(request, nil, 0); !ok {
			t.Fatal("warm miss")
		}
	}
	if hits.Load() != wantRequests {
		t.Fatalf("warm reprobed count=%d", hits.Load())
	}
}

func TestExpiredRawURLSixteenCallersShareRefreshAndKeepGeometry(t *testing.T) {
	var hits atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fs/get" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if hits.Add(1) == 1 {
			close(entered)
		}
		<-release
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": "https://cdn/fresh?Expires=9999999999", "size": 132}})
	}))
	defer upstream.Close()
	cfg := config.LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	parsed, _ := url.Parse(upstream.URL)
	server.ServerHost = parsed.Hostname()
	server.ServerPort, _ = strconv.Atoi(parsed.Port())
	server.HTTPS = false
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	defer func() { files.Stop(); store.Close() }()
	info := &dao.FileInfo{Path: "/plain", EncryptedPath: "/raw", Size: 100, CiphertextSize: 132, ContentVersion: 2, HeaderLen: 32, NonceField: make([]byte, 16), GeometryIdentity: "geo", GeometryConfirmedAt: time.Now(), RawURL: "https://cdn/old?Expires=1", RawURLAuthScope: "trusted_local", RawURLIdentity: playbackIdentity(cfg, upstream.URL, "/raw", nil, nil), UpstreamFetchedAt: time.Now()}
	if !files.PublishConfirmedPlayback(info, files.PlaybackEpoch(info.Path)) {
		t.Fatal("publish")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := fetchRawURL(context.Background(), upstream.URL, info.Path, info.EncryptedPath, nil, files, 30*time.Minute)
			if result.RawURL != "https://cdn/fresh?Expires=9999999999" {
				t.Errorf("resolve=%+v", result)
			}
		}()
	}
	<-entered
	close(release)
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("refreshes=%d", hits.Load())
	}
	got, ok := files.GetConfirmedPlayback("geo")
	if !ok || got.Size != 100 || got.CiphertextSize != 132 {
		t.Fatalf("geometry lost: %+v", got)
	}
}

func TestPropfindSignedURLConfirmationSharedWithPlayback(t *testing.T) {
	header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 4096, bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	body := append(header, make([]byte, 4096)...)
	var api, media, dav atomic.Int32
	var upstreamURL string
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			api.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": upstreamURL + "/signed", "size": len(body)}})
		case "/signed":
			media.Add(1)
			http.ServeContent(w, r, "raw.bin", time.Time{}, bytes.NewReader(body))
		default:
			dav.Add(1)
			w.WriteHeader(401)
		}
	}))
	defer upstream.Close()
	upstreamURL = upstream.URL
	cfg := config.LoadFromBaseDir(t.TempDir())
	server := cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	parsed, _ := url.Parse(upstream.URL)
	server.ServerHost = parsed.Hostname()
	server.ServerPort, _ = strconv.Atoi(parsed.Port())
	server.HTTPS = false
	if err := cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	defer func() { files.Stop(); store.Close() }()
	rule := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
	h := &WebDAVHandler{cfg: cfg, fileDAO: files, streamProxy: proxy.NewStreamProxy(cfg)}
	r := httptest.NewRequest("PROPFIND", "/dav/plain.mp4", nil)
	h.confirmPropfindGeometry(r, "/plain.mp4", "/raw", rule, int64(len(body)))
	if size, ok := h.propfindPlainSize("/raw", int64(len(body)), rule); !ok || size != 4096 {
		t.Fatalf("rewrite size=%d known=%v", size, ok)
	}
	h.confirmPropfindGeometry(r, "/plain.mp4", "/raw", rule, int64(len(body)))
	req := decryptPlaybackRequest{Request: httptest.NewRequest("GET", "/dav/plain.mp4", nil), Config: cfg, FileDAO: files, StreamProxy: h.streamProxy, PasswdInfo: rule, FileItem: FileItem{DisplayPath: "/plain.mp4", EncryptedPath: "/raw"}, TargetURL: upstreamURL + "/signed", ConsumerScenario: consumerScenarioWebDAV}
	if _, ok := confirmedPlaybackMeta(req, nil, 0); !ok {
		t.Fatal("playback failed to reuse PF confirmation")
	}
	if api.Load() != 1 || media.Load() != 1 || dav.Load() != 0 {
		t.Fatalf("api=%d inspect=%d DAV=%d", api.Load(), media.Load(), dav.Load())
	}
	files.InvalidateDisplayPath("/plain.mp4")
	if _, known := h.propfindPlainSize("/raw", int64(len(body)), rule); known {
		t.Fatal("legacy raw mirror survived confirmed invalidation")
	}
}

func TestExplicitFSMetaRefreshInvalidatesConfirmedGeometry(t *testing.T) {
	for _, endpoint := range []string{"get", "list"} {
		t.Run(endpoint, func(t *testing.T) {
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if endpoint == "list" {
					_, _ = w.Write([]byte(`{"code":200,"data":{"content":[],"total":0}}`))
				} else {
					_, _ = w.Write([]byte(`{"code":200,"data":{"name":"plain","size":132,"raw_url":"https://cdn/plain"}}`))
				}
			}))
			defer upstream.Close()
			ah, files := newTestAlistHandler(t, upstream.URL, &config.PasswdInfo{Enable: false})
			defer ah.Stop()
			ah.cfg.AlistServer.PlaybackProfile = config.PlaybackProfileTrustedLocal
			info := &dao.FileInfo{Path: "/plain", EncryptedPath: "/raw", Size: 100, GeometryIdentity: "old", GeometryConfirmedAt: time.Now()}
			epoch := files.PlaybackEpoch(info.Path)
			if !files.PublishConfirmedPlayback(info, epoch) {
				t.Fatal("publish")
			}
			rr := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/fs/"+endpoint, bytes.NewBufferString(`{"path":"/plain","refresh":true}`))
			if endpoint == "list" {
				ah.HandleFsList(rr, r)
			} else {
				ah.HandleFsGet(rr, r)
			}
			if rr.Code != 200 {
				t.Fatalf("status=%d", rr.Code)
			}
			if _, hit := files.GetConfirmedPlayback("old"); hit {
				t.Fatal("explicit refresh retained confirmation")
			}
			if files.PublishConfirmedPlayback(info, epoch) {
				t.Fatal("old flight published after refresh")
			}
		})
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
