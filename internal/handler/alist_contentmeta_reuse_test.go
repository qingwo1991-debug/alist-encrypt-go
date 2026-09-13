package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
)

// TestContentMetaOrProbeReusesCachedMeta verifies that fs/get reuses the
// previously probed content metadata from the fileDAO instead of issuing a
// fresh upstream header probe on every click. The upstream server counts probe
// requests; a hit must perform zero probes.
func TestContentMetaOrProbeReusesCachedMeta(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream probe request: %s", r.URL.String())
	}))
	defer backend.Close()

	handleHandler, fileDAO := newTestAlistHandler(t, backend.URL, passwd)

	displayPath := "/vip/video_001.mp4"
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	ciphertextSize := int64(1024)
	_ = fileDAO.Set(&dao.FileInfo{
		Path:            displayPath,
		EncryptedPath:   "video_001_raw.bin",
		Name:            "video_001.mp4",
		Size:            1000,
		CiphertextSize:  ciphertextSize,
		ContentVersion:  encryption.ContentVersionV2,
		HeaderLen:       encryption.ContentHeaderSize(),
		NonceField:      nonce,
		IsDir:           false,
		RawURL:          "http://should-not-be-probed/raw",
		RawURLAuthScope: "anon",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/fs/get", nil)
	meta := handleHandler.contentMetaOrProbe(req, "http://should-not-be-probed/raw", displayPath, "/vip/video_001_raw.bin", ciphertextSize, passwd)

	if !meta.IsV2() {
		t.Fatalf("expected V2 meta from cache, got version=%d", meta.Version)
	}
	if meta.HeaderLen != encryption.ContentHeaderSize() {
		t.Fatalf("expected header len %d, got %d", encryption.ContentHeaderSize(), meta.HeaderLen)
	}
	if meta.PlainSize != 1000 {
		t.Fatalf("expected plain size 1000 from cache, got %d", meta.PlainSize)
	}
	if string(meta.NonceField) != string(nonce) {
		t.Fatalf("nonce mismatch from cached meta")
	}
}

// TestContentMetaOrProbeFallsBackWhenCiphertextChanges verifies that when the
// upstream ciphertext size no longer matches the cached metadata, the handler
// performs a fresh probe instead of reusing stale content metadata.
func TestContentMetaOrProbeFallsBackWhenCiphertextChanges(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 2000, make([]byte, 16))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(header)
	}))
	defer backend.Close()

	handleHandler, fileDAO := newTestAlistHandler(t, backend.URL, passwd)

	displayPath := "/vip/old_meta.mp4"
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	_ = fileDAO.Set(&dao.FileInfo{
		Path:            displayPath,
		EncryptedPath:   "old_meta_raw.bin",
		Name:            "old_meta.mp4",
		Size:            100,
		CiphertextSize:  100,
		ContentVersion:  encryption.ContentVersionV2,
		HeaderLen:       encryption.ContentHeaderSize(),
		NonceField:      nonce,
		IsDir:           false,
		RawURL:          "",
		RawURLAuthScope: "anon",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/fs/get", nil)
	// Cached ciphertext size is 100 but the listing now reports 1024: must
	// fall through to a real probe against the backend.
	meta := handleHandler.contentMetaOrProbe(req, backend.URL+"/d/raw.bin", displayPath, "/vip/old_meta_raw.bin", 1024, passwd)

	if !meta.IsV2() {
		t.Fatalf("expected V2 meta from probe, got version=%d", meta.Version)
	}
	if meta.CiphertextSize != 1024 {
		t.Fatalf("expected probed ciphertext size 1024, got %d", meta.CiphertextSize)
	}
}

func TestContentMetaOrProbeFallsBackWhenCacheCold(t *testing.T) {
	passwd := &config.PasswdInfo{
		Password:  "testpass",
		EncType:   "aesctr",
		Enable:    true,
		EncName:   true,
		EncSuffix: "",
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 5000, make([]byte, 16))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(header)
	}))
	defer backend.Close()

	handleHandler, _ := newTestAlistHandler(t, backend.URL, passwd)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/get", nil)
	meta := handleHandler.contentMetaOrProbe(req, backend.URL+"/d/cold.bin", "/vip/cold.mp4", "/vip/cold_raw.bin", 8192, passwd)

	if !meta.IsV2() {
		t.Fatalf("expected V2 meta from cold probe, got version=%d", meta.Version)
	}
	if meta.PlainSize != 5000 {
		t.Fatalf("expected probed plain size 5000, got %d", meta.PlainSize)
	}
}
