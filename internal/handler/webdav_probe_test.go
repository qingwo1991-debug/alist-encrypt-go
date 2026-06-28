package handler

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

type probeResponse struct {
	href  string
	size  int64
	isDir bool
}

func TestStartupProbeDeepScanUsesScanAuthHeader(t *testing.T) {
	var (
		mu        sync.Mutex
		calls     []string
		authByURL = map[string]string{}
	)

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Path)
		authByURL[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		switch r.URL.Path {
		case "/dav/encrypt/":
			_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/", isDir: true},
				{href: "/dav/encrypt/sub/", isDir: true},
			})))
		case "/dav/encrypt/sub/":
			_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/sub/", isDir: true},
			})))
		default:
			_, _ = w.Write([]byte(buildProbeMultistatus(nil)))
		}
	}))
	defer srv.Close()

	h := newProbeTestHandler(t, srv.URL)
	h.cfg.AlistServer.StartupProbeDeepScan = true
	h.cfg.AlistServer.ScanAuthHeader = "Bearer test-token"

	h.StartupProbe(context.Background(), []string{"/encrypt"})

	mu.Lock()
	defer mu.Unlock()

	if len(calls) < 2 {
		t.Fatalf("expected deep scan to traverse child directory, got calls=%v", calls)
	}
	if authByURL["/dav/encrypt/"] != "Bearer test-token" {
		t.Fatalf("root probe auth=%q, want %q", authByURL["/dav/encrypt/"], "Bearer test-token")
	}
	if authByURL["/dav/encrypt/sub/"] != "Bearer test-token" {
		t.Fatalf("child probe auth=%q, want %q", authByURL["/dav/encrypt/sub/"], "Bearer test-token")
	}
}

func TestStartupProbeDeepScanRespectsMaxDepth(t *testing.T) {
	var (
		mu    sync.Mutex
		calls []string
	)

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Path)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		switch r.URL.Path {
		case "/dav/encrypt/":
			_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/", isDir: true},
				{href: "/dav/encrypt/sub/", isDir: true},
			})))
		case "/dav/encrypt/sub/":
			_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/sub/", isDir: true},
				{href: "/dav/encrypt/sub/deeper/", isDir: true},
			})))
		case "/dav/encrypt/sub/deeper/":
			_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/sub/deeper/", isDir: true},
			})))
		default:
			_, _ = w.Write([]byte(buildProbeMultistatus(nil)))
		}
	}))
	defer srv.Close()

	h := newProbeTestHandler(t, srv.URL)
	h.cfg.AlistServer.StartupProbeDeepScan = true
	h.cfg.AlistServer.ScanMaxDepth = 1

	h.StartupProbe(context.Background(), []string{"/encrypt"})

	mu.Lock()
	defer mu.Unlock()

	if !containsPath(calls, "/dav/encrypt/") || !containsPath(calls, "/dav/encrypt/sub/") {
		t.Fatalf("missing expected calls, got %v", calls)
	}
	if containsPath(calls, "/dav/encrypt/sub/deeper/") {
		t.Fatalf("deep scan exceeded max depth, got %v", calls)
	}
}

func TestStartupProbeBuildsBasicAuthFromScanCredentials(t *testing.T) {
	var gotAuth string

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
			{href: "/dav/encrypt/", isDir: true},
		})))
	}))
	defer srv.Close()

	h := newProbeTestHandler(t, srv.URL)
	h.cfg.AlistServer.ScanUsername = "scanner"
	h.cfg.AlistServer.ScanPassword = "secret"

	h.StartupProbe(context.Background(), []string{"/encrypt"})

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("scanner:secret"))
	if gotAuth != want {
		t.Fatalf("auth=%q, want %q", gotAuth, want)
	}
}

func TestFetchRawURLFromAlistUsesRequestAuthorization(t *testing.T) {
	var gotAuth string

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/fs/get" {
			t.Fatalf("path=%q, want /api/fs/get", r.URL.Path)
		}
		if gotAuth != "Bearer request-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":401}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"data":{"raw_url":"https://cdn.example/file","size":4096}}`))
	}))
	defer srv.Close()

	h := newProbeTestHandler(t, srv.URL)
	req := httptest.NewRequest(http.MethodGet, "/dav/encrypt/movie.mp4", nil)
	req.Header.Set("Authorization", "Bearer request-token")

	rawURL := h.fetchRawURLFromAlist(req, "/encrypt/movie.mp4", "/enc/movie.bin")
	if rawURL != "https://cdn.example/file" {
		t.Fatalf("rawURL=%q", rawURL)
	}
	if gotAuth != "Bearer request-token" {
		t.Fatalf("authorization=%q", gotAuth)
	}
}

func TestExtractAuthorizationValue(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "Bearer abc", want: "Bearer abc"},
		{raw: "Authorization: Bearer abc", want: "Bearer abc"},
		{raw: "authorization: Basic aaa", want: "Basic aaa"},
		{raw: "   ", want: ""},
	}

	for _, tt := range tests {
		if got := extractAuthorizationValue(tt.raw); got != tt.want {
			t.Fatalf("raw=%q, got=%q, want=%q", tt.raw, got, tt.want)
		}
	}
}

func TestParsePropfindEntriesIncludesDirectories(t *testing.T) {
	h := &WebDAVHandler{}
	body := buildProbeMultistatus([]probeResponse{
		{href: "/dav/encrypt/", isDir: true},
		{href: "/dav/encrypt/sub/", isDir: true},
		{href: "/dav/encrypt/video.mp4", size: 123, isDir: false},
	})

	entries := h.parsePropfindEntries([]byte(body))
	if len(entries) != 3 {
		t.Fatalf("entries=%d, want 3", len(entries))
	}
	if !entries[0].IsDir || !entries[1].IsDir {
		t.Fatalf("expected first two entries to be directories, got %#v", entries)
	}
	if entries[1].Path != "/encrypt/sub/" {
		t.Fatalf("entry path=%q, want %q", entries[1].Path, "/encrypt/sub/")
	}
}

func TestHandlePropfindUsesDirRuleAndPersistsRetryMapping(t *testing.T) {
	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() {
		cfg.AlistServer = original
	})

	passwd := config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/encrypt/.*/__probe__"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	realName := converter.ToRealName("movie.mp4")
	var filePropfindCalls int
	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PROPFIND" {
			t.Fatalf("method=%s, want PROPFIND", r.Method)
		}
		switch r.URL.Path {
		case "/dav/encrypt/" + realName:
			filePropfindCalls++
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
				{href: "/dav/encrypt/" + realName, size: 321, isDir: false},
			})))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer backend.Close()

	h := newProbeTestHandler(t, backend.URL)

	req := httptest.NewRequest("PROPFIND", "/dav/encrypt/movie.mp4", nil)
	rec := httptest.NewRecorder()

	h.handlePropfind(rec, req, "/encrypt/movie.mp4")

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if filePropfindCalls != 1 {
		t.Fatalf("propfind calls=%d, want 1", filePropfindCalls)
	}
	if encPath, ok := h.fileDAO.GetEncPath("/encrypt/movie.mp4"); !ok || encPath != "/encrypt/"+realName {
		t.Fatalf("encPath=%q ok=%v", encPath, ok)
	}
}

func TestHandleGetUsesInternalDavWhenRawURLAuthFails(t *testing.T) {
	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() {
		cfg.AlistServer = original
	})

	passwd := config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/encrypt/*"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	var (
		callMu                       sync.Mutex
		fsGetCalls, dCalls, davCalls int
	)
	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			callMu.Lock()
			fsGetCalls++
			callMu.Unlock()
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"code":401}`))
		case "/d/encrypt/enc_movie.bin":
			callMu.Lock()
			dCalls++
			callMu.Unlock()
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", "4096")
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Range", "bytes 0-0/4096")
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte{0})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		case "/dav/encrypt/enc_movie.bin":
			callMu.Lock()
			davCalls++
			callMu.Unlock()
			if r.Method == http.MethodHead {
				w.Header().Set("Content-Length", "4096")
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Range", "bytes 0-0/4096")
				w.Header().Set("Content-Length", "1")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte{0})
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer backend.Close()

	h := newProbeTestHandler(t, backend.URL)
	h.fileDAO.SetEncPathMapping("/encrypt/movie.mp4", "/encrypt/enc_movie.bin")
	h.fileDAO.Set(&dao.FileInfo{
		Path:              "/encrypt/movie.mp4",
		Name:              "movie.mp4",
		Size:              4096,
		UpstreamFetchedAt: time.Time{},
	})

	req := httptest.NewRequest(http.MethodGet, "/dav/encrypt/movie.mp4", nil)
	rec := httptest.NewRecorder()

	h.handleGet(rec, req, "/encrypt/movie.mp4")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for {
		callMu.Lock()
		got := fsGetCalls
		callMu.Unlock()
		if got >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	callMu.Lock()
	defer callMu.Unlock()
	if fsGetCalls != 1 {
		t.Fatalf("fsGetCalls=%d, want 1", fsGetCalls)
	}
	if dCalls == 0 {
		t.Fatalf("dCalls=%d, want V2 probe to try /d candidate", dCalls)
	}
	if davCalls == 0 {
		t.Fatalf("davCalls=%d, want playback/probe to use internal /dav", davCalls)
	}
}

func TestPreferCachedV2PlainSizeForWebDAVPlayback(t *testing.T) {
	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	h := newProbeTestHandler(t, backend.URL)
	if err := h.fileDAO.Set(&dao.FileInfo{
		Path:              "/encrypt/movie.mp4",
		Name:              "movie.mp4",
		Size:              4096,
		CiphertextSize:    4128,
		ContentVersion:    encryption.ContentVersionV2,
		HeaderLen:         encryption.ContentHeaderSize(),
		NonceField:        []byte("1234567890abcdef"),
		UpstreamFetchedAt: time.Now(),
	}); err != nil {
		t.Fatalf("set cached info: %v", err)
	}

	size, strategy := h.preferCachedV2PlainSize("/encrypt/movie.mp4", 4128, StrategyPROPFIND)
	if size != 4096 {
		t.Fatalf("size=%d, want 4096", size)
	}
	if strategy != StrategyFileInfoCache {
		t.Fatalf("strategy=%s, want %s", strategy, StrategyFileInfoCache)
	}
}

func TestConvertToRealPathKeepsEncryptedNamePassthrough(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/encrypt/*"},
	}
	converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
	encryptedName := converter.ToRealName("movie.mp4")

	h := newProbeTestHandler(t, "http://127.0.0.1:5244")

	got, mode := h.resolveRealPathWithMode("/encrypt/"+encryptedName, passwd)
	if got != "/encrypt/"+encryptedName {
		t.Fatalf("realPath=%q, want passthrough %q", got, "/encrypt/"+encryptedName)
	}
	if mode != pathModeEncryptedNamePassthrough {
		t.Fatalf("mode=%q, want %q", mode, pathModeEncryptedNamePassthrough)
	}
}

func TestHandlePropfindDirectoryDoesNotConvertToEncryptedFilePath(t *testing.T) {
	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() {
		cfg.AlistServer = original
	})

	passwd := config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/encrypt/*"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	var gotPaths []string
	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPaths = append(gotPaths, r.URL.Path)
		if r.URL.Path != "/dav/encrypt/" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write([]byte(buildProbeMultistatus([]probeResponse{
			{href: "/dav/encrypt/", isDir: true},
		})))
	}))
	defer backend.Close()

	h := newProbeTestHandler(t, backend.URL)
	req := httptest.NewRequest("PROPFIND", "/dav/encrypt/", nil)
	rec := httptest.NewRecorder()

	h.handlePropfind(rec, req, "/encrypt/")

	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(gotPaths) != 1 || gotPaths[0] != "/dav/encrypt/" {
		t.Fatalf("gotPaths=%v", gotPaths)
	}
}

func TestHandlePropfindDirectory404DoesNotPopulateNegativeCache(t *testing.T) {
	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() {
		cfg.AlistServer = original
	})

	backend := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	h := newProbeTestHandler(t, backend.URL)
	h.negCache = newNegativePathCache(time.Minute)
	req := httptest.NewRequest("PROPFIND", "/dav/encrypt/", nil)
	rec := httptest.NewRecorder()

	h.handlePropfind(rec, req, "/encrypt/")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if h.negCache.IsBlocked("/encrypt/") {
		t.Fatal("directory propfind should not populate negative cache")
	}
}

func newProbeTestHandler(t *testing.T, backendURL string) *WebDAVHandler {
	t.Helper()

	u, err := url.Parse(backendURL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	cfg := config.DefaultConfig()
	cfg.AlistServer.ServerHost = host
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = strings.EqualFold(u.Scheme, "https")
	cfg.AlistServer.RequestTimeoutSeconds = 3
	fileDAO := dao.NewFileDAO(store)
	passwdDAO := dao.NewPasswdDAO(store)

	return &WebDAVHandler{
		cfg:           cfg,
		fileDAO:       fileDAO,
		passwdDAO:     passwdDAO,
		streamProxy:   proxy.NewStreamProxy(cfg),
		strategyCache: NewStrategyCache(1000),
		sizeResolver:  NewFileSizeResolver(cfg, fileDAO, nil, 1, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		negCache:      newNegativePathCache(0),
	}
}

func containsPath(paths []string, target string) bool {
	for _, p := range paths {
		if p == target {
			return true
		}
	}
	return false
}

func buildProbeMultistatus(entries []probeResponse) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<multistatus>`)
	for _, entry := range entries {
		b.WriteString(`<response>`)
		b.WriteString(`<href>`)
		b.WriteString(entry.href)
		b.WriteString(`</href>`)
		b.WriteString(`<propstat><prop>`)
		b.WriteString(`<displayname>`)
		b.WriteString(pathTail(entry.href))
		b.WriteString(`</displayname>`)
		b.WriteString(`<getcontentlength>`)
		b.WriteString(strconv.FormatInt(entry.size, 10))
		b.WriteString(`</getcontentlength>`)
		b.WriteString(`<resourcetype>`)
		if entry.isDir {
			b.WriteString(`collection`)
		}
		b.WriteString(`</resourcetype>`)
		b.WriteString(`</prop></propstat>`)
		b.WriteString(`</response>`)
	}
	b.WriteString(`</multistatus>`)
	return b.String()
}

func pathTail(href string) string {
	trimmed := strings.Trim(href, "/")
	if trimmed == "" {
		return "/"
	}
	parts := strings.Split(trimmed, "/")
	return parts[len(parts)-1]
}
