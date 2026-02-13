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

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	return &WebDAVHandler{
		cfg:      cfg,
		fileDAO:  dao.NewFileDAO(store),
		negCache: newNegativePathCache(0),
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
