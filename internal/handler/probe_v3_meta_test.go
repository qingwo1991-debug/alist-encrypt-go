package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// Exercise the built-in raw URL inspection path, not the callback path (which
// intentionally does not inspect content). Non-default geometry must survive
// warming so playback does not silently use the default V3 chunk/KDF values.
func TestProbeSchedulerPersistsV3CompleteContentMeta(t *testing.T) {
	const plainSize int64 = 137
	const chunkSize int64 = 73
	const kdfIterations uint32 = 12345
	nonce := bytes.Repeat([]byte{0x37}, 16)
	header, err := encryption.NewV3Header(plainSize, nonce, chunkSize, kdfIterations)
	if err != nil {
		t.Fatal(err)
	}
	ciphertextSize := encryption.V3CiphertextSize(plainSize, chunkSize)
	content := make([]byte, ciphertextSize)
	copy(content, header)
	var rawRequests atomic.Int64
	rawSrv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawRequests.Add(1)
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		http.ServeContent(w, r, "video.bin", time.Time{}, bytes.NewReader(content))
	}))
	defer rawSrv.Close()
	rawURL := rawSrv.URL + "/enc/video.bin"
	alistSrv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/fs/get" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"code":200,"data":{"raw_url":%q,"size":%d}}`, rawURL, ciphertextSize)
	}))
	defer alistSrv.Close()
	cfg := config.DefaultConfig()
	alistURL, err := url.Parse(alistSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(alistURL.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg.AlistServer.ServerHost = alistURL.Hostname()
	cfg.AlistServer.ServerPort = port
	store := newTestStore(t)
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	passwdInfo := &config.PasswdInfo{Password: "testpass", EncType: "aesctr", Enable: true, EncName: true, EncSuffix: ".bin"}
	ps := &ProbeScheduler{
		cfg: cfg, fileDAO: fileDAO, stream: proxy.NewStreamProxy(cfg),
		seen: make(map[string]time.Time), cooldown: time.Hour,
		resolver:      NewFileSizeResolver(cfg, fileDAO, nil, 1, MinMetaSize(cfg), RedirectMaxHops(cfg)),
		providerLimit: 1, providerSem: make(map[string]chan struct{}),
	}
	file := FileItem{
		DisplayPath: "/v3/video.mp4", EncryptedPath: "/v3/video_enc.bin", FileName: "video.mp4",
		TargetURL: alistSrv.URL + "/d/v3/video_enc.bin", PropfindSize: ciphertextSize,
		CompatStorageKey: buildRangeCompatStorageKey(passwdInfo, "/v3/video.mp4"), PasswdInfo: passwdInfo,
	}
	ps.runItem(probeItem{file: file, authHeaders: make(http.Header), source: probeSourceFSList, queuedAt: time.Now()})
	got, ok := fileDAO.Get(file.DisplayPath)
	if !ok || got == nil {
		t.Fatal("V3 warm metadata missing")
	}
	if got.ContentVersion != encryption.ContentVersionV3 || got.HeaderLen != encryption.V3HeaderSize || got.Size != plainSize || got.CiphertextSize != ciphertextSize {
		t.Fatalf("V3 geometry lost: %+v", got)
	}
	if got.ChunkSize != uint32(chunkSize) || got.KDFIterations != kdfIterations || !bytes.Equal(got.NonceField, nonce) {
		t.Fatalf("V3 parameters lost: chunk=%d KDF=%d nonce=%x", got.ChunkSize, got.KDFIterations, got.NonceField)
	}
	if got.RawURL != rawURL || got.UpstreamFetchedAt.IsZero() {
		t.Fatalf("raw URL metadata lost: %+v", got)
	}
	if rawRequests.Load() == 0 {
		t.Fatal("built-in content inspection was not exercised")
	}
	if ps.needsContentMeta(file) {
		t.Fatal("complete warmed V3 should retain cooldown")
	}
	legacy := *got
	legacy.Path = "/v3/old-cache.mp4"
	legacy.ChunkSize, legacy.KDFIterations = 0, 0
	if err := fileDAO.Set(&legacy); err != nil {
		t.Fatal(err)
	}
	file.DisplayPath = legacy.Path
	if !ps.needsContentMeta(file) {
		t.Fatal("incomplete old V3 must bypass cooldown for parameter repair")
	}
}
