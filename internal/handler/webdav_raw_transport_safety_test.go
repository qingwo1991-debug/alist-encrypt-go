package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	appErrors "github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

type rawSafetyStreamer struct {
	ports.Streamer
	target      string
	rangeHeader string
	auth        string
	calls       int
	started     chan struct{}
}

func (*rawSafetyStreamer) AcquireStream() (func(), bool) { return func() {}, true }
func (*rawSafetyStreamer) SelectOptimalStrategy(string, string, string, string) proxy.StreamStrategy {
	return proxy.StreamStrategyRange
}
func (*rawSafetyStreamer) RecordPlaybackHint(string, string, proxy.StreamStrategy) {}
func (s *rawSafetyStreamer) ProxyDownloadDecryptWithStrategyForStorage(w http.ResponseWriter, r *http.Request, target string, _ *config.PasswdInfo, _ int64, _ proxy.StreamStrategy, _ string) *proxy.StreamOutcome {
	s.target = target
	s.rangeHeader = r.Header.Get("Range")
	s.auth = r.Header.Get("Authorization")
	s.calls++
	if s.started != nil {
		close(s.started)
	}
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write([]byte("plain-bytes"))
	return &proxy.StreamOutcome{StatusCode: http.StatusPartialContent, ResponseStarted: true, NoLearning: true, BytesWritten: 11, ExpectedBytes: 11}
}

func newRawWarmupSafetyHandler(t *testing.T, origin string) *WebDAVHandler {
	t.Helper()
	cfg := config.LoadFromBaseDir(t.TempDir())
	alist := cfg.AlistServerSnapshot()
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	alist.ServerHost = u.Hostname()
	alist.ServerPort, _ = strconv.Atoi(u.Port())
	alist.HTTPS = false
	alist.PlaybackProfile = config.PlaybackProfileTrustedLocal
	alist.PasswdList = []config.PasswdInfo{{Enable: true, Password: "test-password", EncType: "aesctr", EncName: true, EncPath: []string{"/*"}}}
	if err := cfg.UpdateAlistServer(alist); err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	keys := dao.NewPasswdDAO(store, cfg)
	h := NewWebDAVHandler(cfg, nil, files, keys, nil, nil, nil)
	t.Cleanup(func() { h.Stop(); files.Stop(); keys.Stop(); _ = store.Close() })
	return h
}

func awaitRawSafety(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
	}
}

func seedRawSafetyGeometry(t *testing.T, h *WebDAVHandler, r *http.Request, locator string) {
	t.Helper()
	rule, found := h.passwdDAO.FindByPath("/plain")
	if !found {
		t.Fatal("missing test rule")
	}
	identity := playbackIdentity(h.cfg, h.cfg.GetAlistURL(), "/raw", rule, r.Header)
	info := &dao.FileInfo{Path: "/plain", EncryptedPath: "/raw", Size: 4096, CiphertextSize: 4096, ContentVersion: 1, GeometryIdentity: identity, GeometryConfirmedAt: time.Now(), RawURL: locator, RawURLIdentity: playbackIdentity(h.cfg, h.cfg.GetAlistURL(), "/raw", nil, r.Header), RawURLAuthScope: "trusted_local", UpstreamFetchedAt: time.Now()}
	repo := h.fileDAO.(playbackCacheRepository)
	if !repo.PublishConfirmedPlayback(info, repo.PlaybackEpoch("/plain")) {
		t.Fatal("seed geometry rejected")
	}
	h.fileDAO.SetEncPathMapping("/plain", "/raw")
}

func TestWebDAVColdPlaybackDoesNotWaitForMetadata(t *testing.T) {
	metadata := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseMetadata := func() { releaseOnce.Do(func() { close(release) }) }
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata <- struct{}{}
		<-release
		_, _ = w.Write([]byte(`{"code":401,"data":{}}`))
	}))
	defer srv.Close()
	defer releaseMetadata()
	h := newRawWarmupSafetyHandler(t, srv.URL)
	r := httptest.NewRequest("GET", "/dav/plain", nil)
	r.Header.Set("Authorization", "Bearer caller")
	r.Header.Set("Range", "bytes=0-10")
	seedRawSafetyGeometry(t, h, r, "")
	streamer := &rawSafetyStreamer{started: make(chan struct{})}
	h.streamProxy = streamer
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { h.handleGet(rec, r, "/plain"); close(done) }()
	// Metadata may already have started or not have been scheduled: neither is
	// allowed to gate actual playback. It cannot complete until explicitly released.
	awaitRawSafety(t, streamer.started, "DAV playback before metadata release")
	awaitRawSafety(t, done, "playback completion before metadata release")
	awaitRawSafety(t, metadata, "optional metadata admission")
	releaseMetadata()
	h.rawWarmups.wg.Wait()
	if streamer.target != srv.URL+"/dav/raw" || streamer.rangeHeader != "bytes=0-10" || streamer.auth != "Bearer caller" || rec.Code != 206 || rec.Body.String() != "plain-bytes" {
		t.Fatalf("route/range/body changed target=%s range=%s status=%d body=%q", streamer.target, streamer.rangeHeader, rec.Code, rec.Body.String())
	}
}

func TestWebDAVBasicRepeatedColdPlaybackAndPositiveReuse(t *testing.T) {
	var api atomic.Int32
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { api.Add(1); http.Error(w, "unexpected metadata", 500) }))
	defer srv.Close()
	h := newRawWarmupSafetyHandler(t, srv.URL)
	streamer := &rawSafetyStreamer{}
	h.streamProxy = streamer
	for _, locator := range []string{"", "https://cdn.example/cached?Expires=9999999999"} {
		r := httptest.NewRequest("GET", "/dav/plain", nil)
		r.Header.Set("Authorization", "Basic synthetic-caller")
		r.Header.Set("Range", "bytes=0-10")
		seedRawSafetyGeometry(t, h, r, locator)
		for i := 0; i < 24; i++ {
			rec := httptest.NewRecorder()
			h.handleGet(rec, r, "/plain")
			want := locator
			if want == "" {
				want = srv.URL + "/dav/raw"
			}
			if streamer.target != want || rec.Code != 206 || rec.Body.String() != "plain-bytes" {
				t.Fatalf("bad positive/cold playback target=%q status=%d", streamer.target, rec.Code)
			}
		}
	}
	if api.Load() != 0 || streamer.calls != 48 {
		t.Fatalf("repeated metadata=%d playback=%d", api.Load(), streamer.calls)
	}
}

func TestRawTransportBusinessErrorsNeverFallbackOrCache(t *testing.T) {
	for _, endpoint := range []string{"/api/fs/get", "/api/fs/link"} {
		for _, code := range []int{401, 403, 404, 500} {
			t.Run(fmt.Sprintf("%s/%d", endpoint, code), func(t *testing.T) {
				var get, link, redirects atomic.Int32
				srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/api/fs/get":
						get.Add(1)
					case "/api/fs/link":
						link.Add(1)
					default:
						redirects.Add(1)
						http.Error(w, "forbidden", 401)
						return
					}
					c := 200
					if r.URL.Path == endpoint {
						c = code
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"code": c, "data": map[string]any{"raw_url": ""}})
				}))
				defer srv.Close()
				h := newRawWarmupSafetyHandler(t, srv.URL)
				for i := 0; i < 2; i++ {
					result := fetchRawURL(context.Background(), srv.URL, "/plain", "/raw", authHeader("Bearer test"), h.fileDAO, time.Minute)
					if result.StatusCode != 200 || result.BusinessCode != code || result.FailureReason == appErrors.ReasonRawURLEmpty || result.RawURL != "" {
						t.Fatalf("result=%+v", result)
					}
				}
				wantLink := int32(0)
				if endpoint == "/api/fs/link" {
					wantLink = 2
				}
				if get.Load() != 2 || link.Load() != wantLink || redirects.Load() != 0 {
					t.Fatalf("unexpected fallback or negative cache: get=%d link=%d redirects=%d", get.Load(), link.Load(), redirects.Load())
				}
				if info, ok := h.fileDAO.Get("/plain"); ok && info.RawURL != "" {
					t.Fatal("business failure cached a locator")
				}
			})
		}
	}
}

func TestRawTransportHTTPAndRedirectAuthErrorsStopFallback(t *testing.T) {
	for _, stage := range []string{"get", "link", "redirect"} {
		t.Run(stage, func(t *testing.T) {
			var hits atomic.Int32
			srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if stage == "get" || stage == "link" && r.URL.Path == "/api/fs/link" || stage == "redirect" && r.URL.Path != "/api/fs/get" && r.URL.Path != "/api/fs/link" {
					http.Error(w, "unauthorized", 401)
					return
				}
				_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":""}}`))
			}))
			defer srv.Close()
			h := newRawWarmupSafetyHandler(t, srv.URL)
			result := fetchRawURL(context.Background(), srv.URL, "/plain", "/raw", nil, h.fileDAO, 0)
			want := int32(1)
			if stage == "link" {
				want = 2
			}
			if stage == "redirect" {
				want = 3
			}
			if hits.Load() != want || result.RawURL != "" || result.FailureReason == appErrors.ReasonRawURLEmpty {
				t.Fatalf("hits=%d result=%+v", hits.Load(), result)
			}
		})
	}
}

func TestWebDAVRawWarmupBoundedScopedAndStopped(t *testing.T) {
	started := make(chan struct{}, 10)
	canceled := make(chan struct{}, 10)
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // Drain POST body so disconnect cancellation is observable.
		started <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer srv.Close()
	h := newRawWarmupSafetyHandler(t, srv.URL)
	request := func(token, cookie string) *http.Request {
		r := httptest.NewRequest("GET", "/dav/plain", nil)
		r.Header.Set("Authorization", token)
		r.Header.Set("Cookie", cookie)
		return r
	}
	r := request("Bearer a", "session=a")
	if !h.enqueueRawURLWarmup(r, "/plain", "/raw") {
		t.Fatal("first admission rejected")
	}
	awaitRawSafety(t, started, "initial load")
	if h.enqueueRawURLWarmup(r, "/plain", "/raw") {
		t.Fatal("same scope admitted twice")
	}
	// Even in trusted-local mode, these represent distinct credential/path work.
	for _, tc := range []struct {
		r            *http.Request
		display, raw string
	}{
		{request("Bearer b", "session=a"), "/plain", "/raw"},
		{request("Bearer a", "session=b"), "/plain", "/raw"},
		{request("Bearer a", "session=a"), "/plain", "/different-raw"},
	} {
		if !h.enqueueRawURLWarmup(tc.r, tc.display, tc.raw) {
			t.Fatal("distinct scope improperly joined")
		}
		awaitRawSafety(t, started, "distinct scoped load")
	}
	for i := 0; i < 100; i++ {
		if h.enqueueRawURLWarmup(r, fmt.Sprintf("/overflow-%d", i), "/raw") {
			t.Fatal("exceeded active capacity")
		}
	}
	h.Stop()
	for i := 0; i < maxWebDAVRawWarmups; i++ {
		awaitRawSafety(t, canceled, "canceled I/O")
	}
	h.rawWarmups.mu.Lock()
	n := len(h.rawWarmups.pending)
	h.rawWarmups.mu.Unlock()
	if n != 0 || h.enqueueRawURLWarmup(r, "/after", "/raw") {
		t.Fatal("shutdown retained or accepted work")
	}
}

func TestWebDAVRawWarmupRequestCancellationAndBasicSkip(t *testing.T) {
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // Drain POST body so disconnect cancellation is observable.
		started <- struct{}{}
		<-r.Context().Done()
		canceled <- struct{}{}
	}))
	defer srv.Close()
	h := newRawWarmupSafetyHandler(t, srv.URL)
	for _, basic := range []string{"Basic dGVzdDp0ZXN0", "bAsIc dGVzdDp0ZXN0"} {
		r := httptest.NewRequest("GET", "/dav/plain", nil)
		r.Header.Set("Authorization", basic)
		for i := 0; i < 24; i++ {
			if h.enqueueRawURLWarmup(r, "/plain", "/raw") {
				t.Fatal("Basic metadata attempt admitted")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest("GET", "/dav/plain", nil).WithContext(ctx)
	if !h.enqueueRawURLWarmup(r, "/plain", "/raw") {
		t.Fatal("warmup rejected")
	}
	awaitRawSafety(t, started, "warmup")
	cancel()
	awaitRawSafety(t, canceled, "request cancellation")
	h.Stop()
	if info, ok := h.fileDAO.Get("/plain"); ok && info.RawURL != "" {
		t.Fatal("canceled result published")
	}
}

func TestWebDAVRawWarmupRefreshAndPublicationFences(t *testing.T) {
	for _, fence := range []string{"none", "epoch", "revision", "cancel"} {
		t.Run(fence, func(t *testing.T) {
			started := make(chan struct{}, 1)
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseMetadata := func() { releaseOnce.Do(func() { close(release) }) }
			var calls atomic.Int32
			srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				started <- struct{}{}
				<-release
				_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"https://cdn.example/fresh?Expires=9999999999","size":132}}`))
			}))
			defer srv.Close()
			defer releaseMetadata()
			h := newRawWarmupSafetyHandler(t, srv.URL)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := httptest.NewRequest("GET", "/dav/plain", nil).WithContext(ctx)
			r.Header.Set("Authorization", "Bearer a")
			identity := playbackIdentity(h.cfg, srv.URL, "/raw", nil, r.Header)
			seed := &dao.FileInfo{Path: "/plain", EncryptedPath: "/raw", RawURL: "https://cdn.example/expired?Expires=1", RawURLIdentity: identity, RawURLAuthScope: "trusted_local", UpstreamFetchedAt: time.Now()}
			if err := h.fileDAO.Set(seed); err != nil {
				t.Fatal(err)
			}
			if !h.enqueueRawURLWarmup(r, "/plain", "/raw") {
				t.Fatal("expired locator did not refresh")
			}
			awaitRawSafety(t, started, "refresh")
			switch fence {
			case "epoch":
				h.fileDAO.InvalidateDisplayPath("/plain")
			case "revision":
				alist := h.cfg.AlistServerSnapshot()
				alist.RedirectMaxHops++
				if err := h.cfg.UpdateAlistServer(alist); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			releaseMetadata()
			// Join the admitted worker without canceling a successful publication.
			h.rawWarmups.wg.Wait()
			info, ok := h.fileDAO.Get("/plain")
			if fence == "none" {
				if !ok || info.RawURL != "https://cdn.example/fresh?Expires=9999999999" {
					t.Fatalf("fresh locator missing: %+v", info)
				}
				if h.enqueueRawURLWarmup(r, "/plain", "/raw") || calls.Load() != 1 {
					t.Fatal("fresh positive locator was not reused")
				}
			} else if ok && info.RawURL == "https://cdn.example/fresh?Expires=9999999999" {
				t.Fatalf("%s failed to fence publication", fence)
			}
		})
	}
}
