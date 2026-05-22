package handler

import (
	"bytes"
	"io"
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

func TestHandleDownloadFallsBackToFsLinkMetadataWhenFsGetIsNotUseful(t *testing.T) {
	cfg := config.Get()
	original := cfg.AlistServer
	t.Cleanup(func() {
		cfg.AlistServer = original
	})

	passwd := config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
		EncName:  false,
		EncPath:  []string{"/encrypt/*"},
	}
	cfg.AlistServer.PasswdList = []config.PasswdInfo{passwd}

	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("M"), int(fileSize))
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc(passwd.Password, passwd.EncType, fileSize)
	if err != nil {
		t.Fatalf("create flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	var fsGetCalls, fsLinkCalls int
	var backendURL string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			fsGetCalls++
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"name":    "movie.mp4",
					"size":    float64(0),
					"raw_url": "",
					"is_dir":  false,
				},
			})
		case "/api/fs/link":
			fsLinkCalls++
			writeJSONResponse(w, map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"name":    "movie.mp4",
					"size":    float64(fileSize),
					"raw_url": backendURL + "/raw/movie.mp4",
					"is_dir":  false,
				},
			})
		case "/raw/movie.mp4":
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(ciphertext)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer backend.Close()
	backendURL = backend.URL

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

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	fileDAO := dao.NewFileDAO(store)
	passwdDAO := dao.NewPasswdDAO(store)
	streamProxy := proxy.NewStreamProxy(cfg)
	handler := NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/d/encrypt/movie.mp4", nil)
	rec := httptest.NewRecorder()

	handler.HandleDownload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, plain) {
		t.Fatalf("decrypted body mismatch: got %d bytes", len(body))
	}
	if fsGetCalls == 0 {
		t.Fatal("expected fs/get to be attempted first")
	}
	if fsLinkCalls == 0 {
		t.Fatal("expected fs/link fallback to be attempted")
	}

	info, ok := fileDAO.Get("/encrypt/movie.mp4")
	if !ok || info == nil {
		t.Fatal("expected cached file info for display path")
	}
	if info.Size != fileSize {
		t.Fatalf("cached size=%d, want %d", info.Size, fileSize)
	}
	if info.RawURL != backendURL+"/raw/movie.mp4" {
		t.Fatalf("cached raw_url=%q", info.RawURL)
	}
}
