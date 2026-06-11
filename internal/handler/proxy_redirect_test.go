package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

func newTestProxyHandler(t *testing.T, cfg *config.Config) *ProxyHandler {
	t.Helper()

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	fileDAO := dao.NewFileDAO(store)
	passwdDAO := dao.NewPasswdDAO(store)
	streamProxy := proxy.NewStreamProxy(cfg)
	handler := NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, nil, nil)
	t.Cleanup(handler.Stop)
	return handler
}

func TestRegisterRedirectStoresDisplayPathAndCompatKey(t *testing.T) {
	cfg := config.DefaultConfig()
	handler := newTestProxyHandler(t, cfg)
	passwd := &config.PasswdInfo{
		Password: "secret",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/enc/*"},
	}

	key := handler.RegisterRedirect("https://cdn.example.com/file", 123, passwd, "/enc/demo.mp4")
	value, ok := handler.redirectMap.Load(key)
	if !ok {
		t.Fatal("redirect info not stored")
	}
	info := value.(*redirectInfo)
	if info.DisplayPath != "/enc/demo.mp4" {
		t.Fatalf("display path=%q, want %q", info.DisplayPath, "/enc/demo.mp4")
	}
	if info.CompatKey != "/enc" {
		t.Fatalf("compat key=%q, want %q", info.CompatKey, "/enc")
	}
}

func TestHandleRedirectDecryptsUsingUnifiedPlaybackFlow(t *testing.T) {
	cfg := config.DefaultConfig()

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/enc/*"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{*passwd}

	// Also update the global config so the PasswdDAO (which uses config.Get())
	// can look up the password during HandleRedirect.
	globalCfg := config.Get()
	origPasswdList := globalCfg.AlistServer.PasswdList
	globalCfg.AlistServer.PasswdList = []config.PasswdInfo{*passwd}
	t.Cleanup(func() {
		globalCfg.AlistServer.PasswdList = origPasswdList
	})

	handler := newTestProxyHandler(t, cfg)

	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("R"), int(fileSize))
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("create flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("Authorization header should be stripped, got %q", got)
		}
		if got := r.Header.Get("Referer"); got != "" {
			t.Fatalf("Referer header should be stripped, got %q", got)
		}
		switch got := r.Header.Get("Range"); got {
		case "bytes=0-31":
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 0-31/4096")
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:32])
			return
		case "bytes=0-1023":
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 0-1023/4096")
			w.Header().Set("Content-Length", "1024")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:1024])
			return
		default:
			t.Fatalf("Range=%q, want probe or playback range", got)
		}
	}))
	defer upstream.Close()

	key := handler.RegisterRedirect(upstream.URL, fileSize, passwd, "/enc/demo.mp4")

	req := httptest.NewRequest(http.MethodGet, "/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-1023")
	req.Header.Set("Authorization", "Bearer webdav-token")
	req.Header.Set("Referer", "http://alist.local/player")
	rec := httptest.NewRecorder()

	handler.HandleRedirect(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 0-1023/4096" {
		t.Fatalf("Content-Range=%q", got)
	}
	if body := rec.Body.Bytes(); !bytes.Equal(body, plain[:1024]) {
		t.Fatalf("decrypted body mismatch: got %d bytes", len(body))
	}
}

func TestHandleRedirectRefreshesMetadataBeforeDecrypt(t *testing.T) {
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
		EncPath:  []string{"/enc/*"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("S"), int(fileSize))
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("create flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	var staleHits, freshHits, fsGetHits int
	var backendURL string
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			fsGetHits++
			writeJSONResponse(w, map[string]interface{}{
				"code": 200,
				"data": map[string]interface{}{
					"raw_url": backendURL + "/fresh",
					"size":    float64(fileSize),
					"is_dir":  false,
				},
			})
		case "/stale":
			staleHits++
			w.WriteHeader(http.StatusUnauthorized)
		case "/fresh":
			freshHits++
			switch got := r.Header.Get("Range"); got {
			case "bytes=0-31":
				w.Header().Set("Content-Type", "video/mp4")
				w.Header().Set("Content-Range", "bytes 0-31/4096")
				w.Header().Set("Content-Length", "32")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(ciphertext[:32])
				return
			case "bytes=0-1023":
			default:
				t.Fatalf("Range=%q, want bytes=0-1023 or probe", got)
			}
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 0-1023/4096")
			w.Header().Set("Content-Length", "1024")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:1024])
		case "/d/enc/real_demo.bin", "/dav/enc/real_demo.bin":
			switch got := r.Header.Get("Range"); got {
			case "bytes=0-31":
				w.Header().Set("Content-Type", "video/mp4")
				w.Header().Set("Content-Range", "bytes 0-31/4096")
				w.Header().Set("Content-Length", "32")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(ciphertext[:32])
				return
			default:
				t.Fatalf("Range=%q, want probe range for fallback inspect", got)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer upstream.Close()
	backendURL = upstream.URL

	parsed, err := url.Parse(backendURL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	cfg.AlistServer.ServerHost = parsed.Hostname()
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = false

	handler := newTestProxyHandler(t, cfg)
	handler.fileDAO.SetEncPathMapping("/enc/demo.mp4", "/enc/real_demo.bin")

	key := handler.RegisterRedirect(backendURL+"/stale", 0, &passwd, "/enc/demo.mp4")
	req := httptest.NewRequest(http.MethodGet, "/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-1023")
	rec := httptest.NewRecorder()

	handler.HandleRedirect(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rec.Code, http.StatusPartialContent, rec.Body.String())
	}
	if staleHits != 0 {
		t.Fatalf("staleHits=%d, want 0 because redirect metadata should refresh before decrypt", staleHits)
	}
	if fsGetHits == 0 {
		t.Fatal("expected /api/fs/get refresh before redirect decrypt")
	}
	if freshHits == 0 {
		t.Fatal("expected fresh raw_url to be used")
	}
	if body := rec.Body.Bytes(); !bytes.Equal(body, plain[:1024]) {
		t.Fatalf("decrypted body mismatch: got %d bytes", len(body))
	}
}
