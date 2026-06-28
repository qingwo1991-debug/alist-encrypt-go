package handler

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestExecuteDecryptPlaybackRejectsWhenStreamLimitReached(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.MaxActiveStreams = 1
	cfg.AlistServer.StreamOverloadStatus = http.StatusTooManyRequests
	sp := proxy.NewStreamProxy(cfg)
	release, ok := sp.AcquireStream()
	if !ok {
		t.Fatal("failed to acquire initial stream slot")
	}
	defer release()

	var hits int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/demo.mp4", nil)
	rr := httptest.NewRecorder()

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter: rr,
		Request:        req,
		Config:         cfg,
		StreamProxy:    sp,
		PasswdInfo: &config.PasswdInfo{
			Password: "123456",
			EncType:  "aesctr",
			Enable:   true,
		},
		FileItem: FileItem{
			DisplayPath: "/demo.mp4",
			TargetURL:   srv.URL,
			FileName:    "demo.mp4",
		},
		TargetURL:     srv.URL,
		ProviderKey:   ProviderKey(srv.URL, "/demo.mp4"),
		Path:          "/demo.mp4",
		InitialSize:   1024,
		OverridePath:  "/demo.mp4",
		CompatKey:     "/encrypt",
		FailureLogMsg: "test playback failed",
	})

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusTooManyRequests)
	}
	if got := rr.Header().Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After=%q, want 2", got)
	}
	if hits != 0 {
		t.Fatalf("upstream hits=%d, want 0", hits)
	}
	stats := sp.StreamLimitStats()
	if got := stats["rejected_streams"]; got != uint64(1) {
		t.Fatalf("rejected_streams=%v, want 1", got)
	}
}

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
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		ResponseWriter:   rr,
		Request:          req,
		Config:           cfg,
		Probe:            ps,
		StreamProxy:      sp,
		PasswdInfo:       passwd,
		FileItem:         fileItem,
		TargetURL:        srv.URL,
		ProviderKey:      ProviderKey(srv.URL, "/demo.mp4"),
		Path:             "/demo.mp4",
		InitialSize:      fileSize,
		OverridePath:     "/demo.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioHTTP,
		FailureLogMsg:    "test playback failed",
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
	if item.source != probeSourceFirstFrame {
		t.Fatalf("source=%q, want %q", item.source, probeSourceFirstFrame)
	}
	if got := item.authHeaders.Get("Authorization"); got != "Bearer test-token" {
		t.Fatalf("authorization=%q", got)
	}

	ps.recordTerminal(fileItem, probeSourceFirstFrame, probeStatusSuccess, fileSize, probeExecutionResult{resolvedSize: fileSize})
	ps.RecordConsumerHit(fileItem, consumerScenarioHTTP)
	stats := ps.Stats()
	if got := stats["consumer_hit_total"]; got != uint64(1) {
		t.Fatalf("consumer_hit_total=%v, want 1", got)
	}
	bySource, _ := stats["consumer_hits_by_source"].(map[string]uint64)
	if bySource[probeSourceFirstFrame] != 1 {
		t.Fatalf("consumer_hits_by_source=%#v", bySource)
	}
}

func TestExecuteDecryptPlaybackHTTPDetectsV2WithoutCachedMeta(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := proxy.NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("http-v2-cold-cache-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch got := r.Header.Get("Range"); got {
		case "bytes=0-31":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-31/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:32])
		case "bytes=32-63":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 32-63/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[32:64])
		default:
			t.Fatalf("unexpected range: %q", got)
		}
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/demo.mp4", nil)
	req.Header.Set("Range", "bytes=0-31")
	rr := httptest.NewRecorder()

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:   rr,
		Request:          req,
		Config:           cfg,
		StreamProxy:      sp,
		PasswdInfo:       passwd,
		FileItem:         FileItem{DisplayPath: "/demo.mp4", EncryptedPath: "/demo.mp4", TargetURL: srv.URL, FileName: "demo.mp4"},
		TargetURL:        srv.URL,
		ProviderKey:      ProviderKey(srv.URL, "/demo.mp4"),
		Path:             "/demo.mp4",
		InitialSize:      int64(len(ciphertext)),
		OverridePath:     "/demo.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioHTTP,
		FailureLogMsg:    "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, plain[:32]) {
		t.Fatal("decrypted V2 HTTP body mismatch")
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-31/"+strconv.Itoa(len(plain)) {
		t.Fatalf("content-range=%q", got)
	}
}

func TestExecuteDecryptPlaybackDoesNotPassthroughEncryptedContentOnFailure(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.PlayFirstFallback = true
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sp := proxy.NewStreamProxy(cfg)
	ps := &ProbeScheduler{
		cfg: cfg,
	}

	fileSize := int64(1024)
	plain := bytes.Repeat([]byte("Z"), int(fileSize))
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("correct-password", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to build flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ciphertext)
	}))
	defer srv.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/broken.bin", nil)
	rr := httptest.NewRecorder()

	passwd := &config.PasswdInfo{
		Password: "wrong-password",
		EncType:  "aesctr",
		Enable:   true,
	}
	fileDAO.SetEncPathMapping("/broken.bin", "/enc/broken.bin")
	fileDAO.Set(&dao.FileInfo{
		Path:              "/broken.bin",
		Name:              "broken.bin",
		Size:              fileSize,
		RawURL:            srv.URL,
		UpstreamFetchedAt: time.Now(),
	})
	ps.recordTerminal(FileItem{DisplayPath: "/broken.bin", FileName: "broken.bin"}, probeSourceFirstFrame, probeStatusSuccess, fileSize, probeExecutionResult{resolvedSize: fileSize})

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter: rr,
		Request:        req,
		Config:         cfg,
		Probe:          ps,
		StreamProxy:    sp,
		FileDAO:        fileDAO,
		PasswdInfo:     passwd,
		FileItem: FileItem{
			DisplayPath:   "/broken.bin",
			EncryptedPath: "/enc/broken.bin",
			TargetURL:     srv.URL,
			FileName:      "broken.bin",
		},
		TargetURL:     srv.URL,
		ProviderKey:   ProviderKey(srv.URL, "/broken.bin"),
		Path:          "/broken.bin",
		InitialSize:   fileSize,
		OverridePath:  "/broken.bin",
		CompatKey:     "/encrypt",
		FailureLogMsg: "test playback failed",
	})

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusBadGateway)
	}
	if bytes.Equal(rr.Body.Bytes(), ciphertext) {
		t.Fatal("should not passthrough encrypted content on decrypt failure")
	}
	if _, ok := fileDAO.Get("/broken.bin"); !ok {
		t.Fatal("expected display-path mapping to remain present after invalidation")
	} else if info, _ := fileDAO.Get("/broken.bin"); info.RawURL != "" || info.Size != 0 {
		t.Fatalf("expected raw_url and size cleared after invalidation, got raw_url=%q size=%d", info.RawURL, info.Size)
	}
	stats := ps.Stats()
	warmStateCounts, _ := stats["warm_state_counts"].(map[string]uint64)
	if warmStateCounts[warmStateInvalid] != 1 {
		t.Fatalf("invalid warm count=%d, want 1", warmStateCounts[warmStateInvalid])
	}
}

func TestExecuteDecryptPlaybackInspectsAndCachesV2MetaWhenMissing(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sp := proxy.NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "testpass",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("v2-plain-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	var inspectCalls int
	var rangeCalls int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Range") {
		case "bytes=0-31":
			inspectCalls++
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-31/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:32])
		case "bytes=32-63":
			rangeCalls++
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 32-63/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[32:64])
		default:
			t.Fatalf("unexpected range: %q", r.Header.Get("Range"))
		}
	}))
	defer srv.Close()

	fileDAO.Set(&dao.FileInfo{
		Path:              "/demo.mp4",
		Name:              "demo.mp4",
		Size:              int64(len(ciphertext)),
		RawURL:            srv.URL,
		UpstreamFetchedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/d/demo.mp4", nil)
	req.Header.Set("Range", "bytes=0-31")
	rr := httptest.NewRecorder()

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:   rr,
		Request:          req,
		Config:           cfg,
		StreamProxy:      sp,
		FileDAO:          fileDAO,
		PasswdInfo:       passwd,
		FileItem:         FileItem{DisplayPath: "/demo.mp4", TargetURL: srv.URL, FileName: "demo.mp4"},
		TargetURL:        srv.URL,
		ProviderKey:      ProviderKey(srv.URL, "/demo.mp4"),
		Path:             "/demo.mp4",
		InitialSize:      int64(len(ciphertext)),
		OverridePath:     "/demo.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioWebDAV,
		FailureLogMsg:    "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if inspectCalls != 1 {
		t.Fatalf("inspectCalls=%d, want 1", inspectCalls)
	}
	if rangeCalls != 1 {
		t.Fatalf("rangeCalls=%d, want 1", rangeCalls)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, plain[:32]) {
		t.Fatal("decrypted body mismatch")
	}
	info, ok := fileDAO.Get("/demo.mp4")
	if !ok || info == nil {
		t.Fatal("expected cached file info")
	}
	if info.ContentVersion != encryption.ContentVersionV2 {
		t.Fatalf("content version=%d, want v2", info.ContentVersion)
	}
	if info.Size != int64(len(plain)) {
		t.Fatalf("plain size=%d want=%d", info.Size, len(plain))
	}
	if info.CiphertextSize != int64(len(ciphertext)) {
		t.Fatalf("ciphertext size=%d want=%d", info.CiphertextSize, len(ciphertext))
	}
}

func TestExecuteDecryptPlaybackReprobesCachedV2MetaWithoutNonce(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sp := proxy.NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "testpass",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("v2-cached-plain-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	var inspectCalls int
	var rangeCalls int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Range") {
		case "bytes=0-31":
			inspectCalls++
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-31/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:32])
		case "bytes=32-63":
			rangeCalls++
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 32-63/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[32:64])
		default:
			t.Fatalf("unexpected range: %q", r.Header.Get("Range"))
		}
	}))
	defer srv.Close()

	fileDAO.Set(&dao.FileInfo{
		Path:              "/demo-cached.mp4",
		Name:              "demo-cached.mp4",
		Size:              int64(len(plain)),
		CiphertextSize:    int64(len(ciphertext)),
		ContentVersion:    encryption.ContentVersionV2,
		HeaderLen:         32,
		RawURL:            srv.URL,
		UpstreamFetchedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/d/demo-cached.mp4", nil)
	req.Header.Set("Range", "bytes=0-31")
	rr := httptest.NewRecorder()

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:   rr,
		Request:          req,
		Config:           cfg,
		StreamProxy:      sp,
		FileDAO:          fileDAO,
		PasswdInfo:       passwd,
		FileItem:         FileItem{DisplayPath: "/demo-cached.mp4", TargetURL: srv.URL, FileName: "demo-cached.mp4"},
		TargetURL:        srv.URL,
		ProviderKey:      ProviderKey(srv.URL, "/demo-cached.mp4"),
		Path:             "/demo-cached.mp4",
		InitialSize:      int64(len(plain)),
		OverridePath:     "/demo-cached.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioWebDAV,
		FailureLogMsg:    "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if inspectCalls != 1 {
		t.Fatalf("inspectCalls=%d, want 1", inspectCalls)
	}
	if rangeCalls != 1 {
		t.Fatalf("rangeCalls=%d, want 1", rangeCalls)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, plain[:32]) {
		t.Fatal("decrypted body mismatch")
	}
}

func TestExecuteDecryptPlaybackUsesCachedV2MetaWithNonce(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sp := proxy.NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "testpass",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("v2-cache-hit-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	var calls int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch r.Header.Get("Range") {
		case "bytes=32-63":
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Range", "bytes 32-63/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[32:64])
		default:
			t.Fatalf("unexpected range: %q", r.Header.Get("Range"))
		}
	}))
	defer srv.Close()

	fileDAO.Set(&dao.FileInfo{
		Path:              "/demo-cached-hit.mp4",
		Name:              "demo-cached-hit.mp4",
		Size:              int64(len(plain)),
		CiphertextSize:    int64(len(ciphertext)),
		ContentVersion:    encryption.ContentVersionV2,
		HeaderLen:         encryption.ContentHeaderSize(),
		NonceField:        append([]byte(nil), contentEnc.Meta.NonceField...),
		RawURL:            srv.URL,
		UpstreamFetchedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/d/demo-cached-hit.mp4", nil)
	req.Header.Set("Range", "bytes=0-31")
	rr := httptest.NewRecorder()

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:   rr,
		Request:          req,
		Config:           cfg,
		StreamProxy:      sp,
		FileDAO:          fileDAO,
		PasswdInfo:       passwd,
		FileItem:         FileItem{DisplayPath: "/demo-cached-hit.mp4", TargetURL: srv.URL, FileName: "demo-cached-hit.mp4"},
		TargetURL:        srv.URL,
		ProviderKey:      ProviderKey(srv.URL, "/demo-cached-hit.mp4"),
		Path:             "/demo-cached-hit.mp4",
		InitialSize:      int64(len(plain)),
		OverridePath:     "/demo-cached-hit.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioWebDAV,
		FailureLogMsg:    "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if calls != 1 {
		t.Fatalf("calls=%d, want 1", calls)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, plain[:32]) {
		t.Fatal("decrypted body mismatch")
	}
}

func TestExecuteDecryptPlaybackDoesNotCacheRangeLengthAsFileSize(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sizeResolver := NewFileSizeResolver(cfg, fileDAO, nil, 2, 0, 2)
	sp := proxy.NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "testpass",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("v2-tail-cache-"), 320)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	plainStart := int64(len(plain) - 12)
	plainEnd := int64(len(plain) - 1)
	cipherStart := plainStart + encryption.ContentHeaderSize()
	cipherEnd := plainEnd + encryption.ContentHeaderSize()
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Range"); got != "bytes="+strconv.FormatInt(cipherStart, 10)+"-" {
			t.Fatalf("upstream Range=%q", got)
		}
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Content-Range", "bytes "+strconv.FormatInt(cipherStart, 10)+"-"+strconv.FormatInt(cipherEnd, 10)+"/"+strconv.Itoa(len(ciphertext)))
		w.Header().Set("Content-Length", "12")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(ciphertext[cipherStart : cipherEnd+1])
	}))
	defer srv.Close()

	fileDAO.Set(&dao.FileInfo{
		Path:              "/demo-tail.mp4",
		Name:              "demo-tail.mp4",
		Size:              int64(len(plain)),
		CiphertextSize:    int64(len(ciphertext)),
		ContentVersion:    encryption.ContentVersionV2,
		HeaderLen:         encryption.ContentHeaderSize(),
		NonceField:        append([]byte(nil), contentEnc.Meta.NonceField...),
		RawURL:            srv.URL,
		UpstreamFetchedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/dav/demo-tail.mp4", nil)
	req.Header.Set("Range", "bytes="+strconv.FormatInt(plainStart, 10)+"-")
	rr := httptest.NewRecorder()

	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:   rr,
		Request:          req,
		Config:           cfg,
		StreamProxy:      sp,
		FileDAO:          fileDAO,
		SizeResolver:     sizeResolver,
		PasswdInfo:       passwd,
		FileItem:         FileItem{DisplayPath: "/demo-tail.mp4", TargetURL: srv.URL, FileName: "demo-tail.mp4"},
		TargetURL:        srv.URL,
		ProviderKey:      ProviderKey(srv.URL, "/demo-tail.mp4"),
		Path:             "/demo-tail.mp4",
		InitialSize:      int64(len(plain)),
		OverridePath:     "/demo-tail.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioWebDAV,
		FailureLogMsg:    "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain[plainStart:]) {
		t.Fatalf("tail body mismatch: got %d bytes", len(got))
	}
	if got, ok := fileDAO.GetFileSize("/demo-tail.mp4"); !ok || got != int64(len(plain)) {
		t.Fatalf("cached size=%d ok=%v, want %d", got, ok, len(plain))
	}
	if result, ok := sizeResolver.tryFastPath(req.Context(), FileItem{DisplayPath: "/demo-tail.mp4", FileName: "demo-tail.mp4"}); !ok || result.Size != int64(len(plain)) {
		t.Fatalf("fast path size=%d ok=%v, want %d", result.Size, ok, len(plain))
	}
}

func TestInspectPlaybackContentMetaPrefersCurrentTargetURL(t *testing.T) {
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	sp := proxy.NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "testpass",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("v2-probe-order-"), 128)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	var gotProbePaths []string
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dav/demo.bin":
			gotProbePaths = append(gotProbePaths, r.URL.Path)
			t.Fatalf("/dav target should not be probed before current raw target")
		case "/d/demo.bin":
			gotProbePaths = append(gotProbePaths, r.URL.Path)
			t.Fatalf("/d target should not be probed before current raw target")
		case "/raw/demo.bin":
			gotProbePaths = append(gotProbePaths, r.URL.Path)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Range", "bytes 0-31/"+strconv.Itoa(len(ciphertext)))
			w.Header().Set("Content-Length", "32")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(ciphertext[:32])
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	parsedURL := srv.URL
	cfg.AlistServer.ServerHost = strings.TrimPrefix(strings.TrimPrefix(parsedURL, "http://"), "https://")
	cfg.AlistServer.HTTPS = false
	if host, port, err := net.SplitHostPort(cfg.AlistServer.ServerHost); err == nil {
		cfg.AlistServer.ServerHost = host
		if parsedPort, convErr := strconv.Atoi(port); convErr == nil {
			cfg.AlistServer.ServerPort = parsedPort
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/dav/demo.mp4", nil)
	meta, ok := inspectPlaybackContentMeta(decryptPlaybackRequest{
		Request:     req,
		Config:      cfg,
		StreamProxy: sp,
		FileDAO:     fileDAO,
		PasswdInfo:  passwd,
		FileItem: FileItem{
			DisplayPath:   "/demo.mp4",
			EncryptedPath: "/demo.bin",
			TargetURL:     srv.URL + "/raw/demo.bin",
			FileName:      "demo.mp4",
		},
		TargetURL:        srv.URL + "/raw/demo.bin",
		Path:             "/demo.mp4",
		ConsumerScenario: consumerScenarioWebDAV,
	}, nil, int64(len(ciphertext)))
	if !ok {
		t.Fatal("expected V2 probe success")
	}
	if !meta.IsV2() || meta.PlainSize != int64(len(plain)) {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if len(gotProbePaths) != 1 || gotProbePaths[0] != "/raw/demo.bin" {
		t.Fatalf("gotProbePaths=%v", gotProbePaths)
	}
}

func TestInvalidatePlaybackStatePreservesEncPathOnUpstream4xx(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	fileDAO.SetEncPathMapping("/demo.mp4", "/enc/demo.bin")
	if err := fileDAO.Set(&dao.FileInfo{
		Path:              "/demo.mp4",
		EncryptedPath:     "/enc/demo.bin",
		Name:              "demo.mp4",
		Size:              4096,
		RawURL:            "https://cdn.example/demo.bin",
		UpstreamFetchedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed file info: %v", err)
	}

	invalidatePlaybackState(decryptPlaybackRequest{
		FileDAO: fileDAO,
		FileItem: FileItem{
			DisplayPath:   "/demo.mp4",
			EncryptedPath: "/enc/demo.bin",
		},
	}, "upstream_4xx")

	encPath, ok := fileDAO.GetEncPath("/demo.mp4")
	if !ok || encPath != "/enc/demo.bin" {
		t.Fatalf("encPath=%q ok=%v", encPath, ok)
	}
	info, ok := fileDAO.Get("/demo.mp4")
	if !ok || info == nil {
		t.Fatal("expected display path entry to remain cached")
	}
	if info.RawURL != "" || info.Size != 0 {
		t.Fatalf("expected volatile fields cleared, got raw_url=%q size=%d", info.RawURL, info.Size)
	}
}

func TestInvalidatePlaybackStatePreservesPlaybackMetaOnClientAbort(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	nonce := bytes.Repeat([]byte{7}, 16)
	if err := fileDAO.Set(&dao.FileInfo{
		Path:              "/demo.mp4",
		EncryptedPath:     "/enc/demo.bin",
		Name:              "demo.mp4",
		Size:              4096,
		CiphertextSize:    4128,
		ContentVersion:    encryption.ContentVersionV2,
		HeaderLen:         encryption.ContentHeaderSize(),
		NonceField:        nonce,
		RawURL:            "https://cdn.example/demo.bin",
		UpstreamFetchedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed file info: %v", err)
	}

	for _, reason := range []string{"client_disconnect", "network_error"} {
		invalidatePlaybackState(decryptPlaybackRequest{
			FileDAO:          fileDAO,
			ConsumerScenario: consumerScenarioWebDAV,
			FileItem: FileItem{
				DisplayPath:   "/demo.mp4",
				EncryptedPath: "/enc/demo.bin",
			},
		}, reason)

		info, ok := fileDAO.Get("/demo.mp4")
		if !ok || info == nil {
			t.Fatalf("expected display path entry to remain cached after %s", reason)
		}
		if info.RawURL != "https://cdn.example/demo.bin" || info.Size != 4096 || info.ContentVersion != encryption.ContentVersionV2 {
			t.Fatalf("unexpected cached info after %s: raw_url=%q size=%d version=%d", reason, info.RawURL, info.Size, info.ContentVersion)
		}
		if !bytes.Equal(info.NonceField, nonce) {
			t.Fatalf("nonce changed after %s", reason)
		}
	}
}

func TestExecuteDecryptPlaybackWebDAVFallsBackToInternalDavOnRawURLUpstream4xx(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := proxy.NewStreamProxy(cfg)

	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("W"), int(fileSize))
	ciphertext := make([]byte, len(plain))
	copy(ciphertext, plain)

	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to build flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	var rawHits int
	var davHits int
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/raw/demo.bin":
			rawHits++
			http.Error(w, "bad raw url", http.StatusBadRequest)
		case "/d/demo.bin":
			http.NotFound(w, r)
		case "/dav/demo.bin":
			davHits++
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Length", "4096")
			if r.Header.Get("Range") != "" {
				w.Header().Set("Content-Range", "bytes 0-1023/4096")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(ciphertext[:1024])
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ciphertext)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg.AlistServer.ServerHost = strings.TrimPrefix(strings.TrimPrefix(srv.URL, "http://"), "https://")
	cfg.AlistServer.HTTPS = false
	if host, port, err := net.SplitHostPort(cfg.AlistServer.ServerHost); err == nil {
		cfg.AlistServer.ServerHost = host
		if parsedPort, convErr := strconv.Atoi(port); convErr == nil {
			cfg.AlistServer.ServerPort = parsedPort
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/dav/demo.mp4", nil)
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
			DisplayPath:   "/demo.mp4",
			EncryptedPath: "/demo.bin",
			TargetURL:     srv.URL + "/raw/demo.bin",
			FileName:      "demo.mp4",
		},
		TargetURL:        srv.URL + "/raw/demo.bin",
		ProviderKey:      ProviderKey(srv.URL+"/raw/demo.bin", "/demo.mp4"),
		Path:             "/demo.mp4",
		InitialSize:      fileSize,
		OverridePath:     "/demo.mp4",
		CompatKey:        "/encrypt",
		ConsumerScenario: consumerScenarioWebDAV,
		FailureLogMsg:    "test playback failed",
	})

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusPartialContent, rr.Body.String())
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if !bytes.Equal(body, plain[:1024]) {
		t.Fatal("decrypted fallback payload mismatch")
	}
	if rawHits == 0 {
		t.Fatal("expected raw_url attempt before fallback")
	}
	if davHits == 0 {
		t.Fatal("expected internal /dav fallback")
	}
}
