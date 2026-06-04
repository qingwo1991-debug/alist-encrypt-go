package handler

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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
