package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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
	return NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, nil, nil)
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
		if got := r.Header.Get("Range"); got != "bytes=0-1023" {
			t.Fatalf("Range=%q, want %q", got, "bytes=0-1023")
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Range", "bytes 0-1023/4096")
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(ciphertext[:1024])
	}))
	defer upstream.Close()

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		EncName:  true,
		Enable:   true,
		EncPath:  []string{"/enc/*"},
	}
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
