package handler

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestExecuteDecryptPlaybackFirstFrameFallsBackToChunked(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := proxy.NewStreamProxy(cfg)

	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("A"), int(fileSize))
	ciphertext := make([]byte, len(plain))
	copy(ciphertext, plain)

	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to build flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", "4096")
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ciphertext)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/demo.mp4", nil)
	req.Header.Set("Range", "bytes=0-1023")
	rr := httptest.NewRecorder()

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter: rr,
		Request:        req,
		Config:         cfg,
		StreamProxy:    sp,
		PasswdInfo:     passwd,
		FileItem: FileItem{
			DisplayPath: "/demo.mp4",
			TargetURL:   srv.URL,
			FileName:    "demo.mp4",
		},
		TargetURL:     srv.URL,
		ProviderKey:   ProviderKey(srv.URL, "/demo.mp4"),
		Path:          "/demo.mp4",
		InitialSize:   fileSize,
		OverridePath:  "/demo.mp4",
		CompatKey:     "/encrypt",
		FailureLogMsg: "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusPartialContent)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if len(body) != 1024 {
		t.Fatalf("body len=%d, want 1024", len(body))
	}
	if !bytes.Equal(body, plain[:1024]) {
		t.Fatal("decrypted first-frame payload mismatch")
	}
	if hits != 2 {
		t.Fatalf("upstream hits=%d, want 2 (range attempt + chunked fallback)", hits)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-1023/4096" {
		t.Fatalf("content-range=%q", got)
	}
}

func TestExecuteDecryptPlaybackEnqueuesWarmupAfterFirstFrameSuccess(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sp := proxy.NewStreamProxy(cfg)
	ps := &ProbeScheduler{
		cfg:          cfg,
		fileDAO:      fileDAO,
		stream:       sp,
		enabled:      true,
		queue:        make(chan probeItem, 1),
		seen:         make(map[string]time.Time),
		providerSem:  make(map[string]chan struct{}),
		minSizeBytes: cfg.AlistServer.ProbeMinSizeBytes,
	}

	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("B"), int(fileSize))
	ciphertext := make([]byte, len(plain))
	copy(ciphertext, plain)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to build flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Length", "4096")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/demo.mp4", nil)
	req.Header.Set("Range", "bytes=0-1023")
	req.Header.Set("Authorization", "Bearer test-token")
	rr := httptest.NewRecorder()

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}
	fileItem := FileItem{
		DisplayPath:      "/demo.mp4",
		TargetURL:        srv.URL,
		FileName:         "demo.mp4",
		CompatStorageKey: "/encrypt",
	}

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter: rr,
		Request:        req,
		Config:         cfg,
		Probe:          ps,
		StreamProxy:    sp,
		PasswdInfo:     passwd,
		FileItem:       fileItem,
		TargetURL:      srv.URL,
		ProviderKey:    ProviderKey(srv.URL, "/demo.mp4"),
		Path:           "/demo.mp4",
		InitialSize:    fileSize,
		OverridePath:   "/demo.mp4",
		CompatKey:      "/encrypt",
		FailureLogMsg:  "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusPartialContent)
	}
	if len(ps.queue) != 1 {
		t.Fatalf("queue len=%d, want 1", len(ps.queue))
	}
	item := <-ps.queue
	if item.file.DisplayPath != "/demo.mp4" {
		t.Fatalf("display path=%q", item.file.DisplayPath)
	}
	if item.file.CompatStorageKey != "/encrypt" {
		t.Fatalf("compat key=%q", item.file.CompatStorageKey)
	}
	if got := item.authHeaders.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("authorization=%q", got)
	}
}
