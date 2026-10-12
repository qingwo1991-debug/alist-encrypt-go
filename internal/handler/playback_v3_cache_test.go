package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestExecuteDecryptPlaybackCachedNonDefaultV3(t *testing.T) {
	const cs = int64(64)
	const iterations = uint32(1234)
	const password = "v3-cached-parameters"
	plain := bytes.Repeat([]byte("v3-playback-cache-"), 30)
	nonce := bytes.Repeat([]byte{5}, 16)
	cipher, err := encryption.NewV3ChunkCipher(encryption.DeriveV3Key(password, nonce, iterations), nonce)
	if err != nil {
		t.Fatal(err)
	}
	header, err := encryption.NewV3Header(0, nonce, cs, iterations)
	if err != nil {
		t.Fatal(err)
	}
	container := append([]byte(nil), header...)
	for idx, off := uint64(0), 0; off < len(plain); idx, off = idx+1, off+int(cs) {
		chunk := make([]byte, cs)
		copy(chunk, plain[off:])
		record, err := cipher.Seal(idx, chunk)
		if err != nil {
			t.Fatal(err)
		}
		container = append(container, record...)
	}
	trailer := make([]byte, 16)
	copy(trailer, "V3E4")
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(plain)))
	container = append(container, trailer...)
	var calls atomic.Int64
	srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end < start || end >= len(container) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(container)))
		w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(container[start : end+1])
	}))
	defer srv.Close()
	cfg := config.DefaultConfig()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store)
	info := &dao.FileInfo{Path: "/v3-cache.bin", Name: "v3-cache.bin", Size: int64(len(plain)), CiphertextSize: int64(len(container)), ContentVersion: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, NonceField: nonce, ChunkSize: uint32(cs), KDFIterations: iterations, RawURL: srv.URL, RawURLAuthScope: "anon"}
	if err := fileDAO.Set(info); err != nil {
		t.Fatal(err)
	}
	passwd := &config.PasswdInfo{Password: password, EncType: "aesctr", Enable: true}
	sp := proxy.NewStreamProxy(cfg)
	for i, interval := range [][2]int{{10, 29}, {61, 140}, {130, 159}} {
		before := calls.Load()
		req := httptest.NewRequest(http.MethodGet, "/d/v3-cache.bin", nil)
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", interval[0], interval[1]))
		rr := httptest.NewRecorder()
		executeDecryptPlayback(decryptPlaybackRequest{ResponseWriter: rr, Request: req, Config: cfg, StreamProxy: sp, FileDAO: fileDAO, PasswdInfo: passwd, FileItem: FileItem{DisplayPath: info.Path, TargetURL: srv.URL, FileName: info.Name}, TargetURL: srv.URL, ProviderKey: ProviderKey(srv.URL, info.Path), Path: info.Path, InitialSize: info.Size, OverridePath: info.Path, CompatKey: "/encrypt", ConsumerScenario: consumerScenarioWebDAV, FailureLogMsg: "V3 test playback failed"})
		if rr.Code != http.StatusPartialContent || !bytes.Equal(rr.Body.Bytes(), plain[interval[0]:interval[1]+1]) {
			t.Fatalf("range %v status=%d body=%q", interval, rr.Code, rr.Body.String())
		}
		wantCalls := int64(1)
		if i == 2 {
			// The second request authenticated chunk 2 in full; a distinct tiny
			// range inside it must now reuse that record, not just an output slice.
			wantCalls = 0
		}
		if got := calls.Load() - before; got != wantCalls {
			t.Fatalf("cached V3 needed %d requests, want exactly %d", got, wantCalls)
		}
	}
	// Foreground caching must also retain complete geometry, not only V2.
	cached, _ := cachedPlaybackMeta(info, "aesctr")
	cachePlaybackContentMeta(decryptPlaybackRequest{FileDAO: fileDAO, FileItem: FileItem{DisplayPath: "/foreground-v3.bin", FileName: "foreground-v3.bin"}, TargetURL: srv.URL}, cached)
	got, ok := fileDAO.Get("/foreground-v3.bin")
	if !ok || got.ChunkSize != uint32(cs) || got.KDFIterations != iterations {
		t.Fatalf("foreground V3 cache incomplete: %+v", got)
	}
	// Old V3 entries are never sufficient to suppress a seek probe.
	old := *info
	old.Path = "/old-v3.bin"
	old.ChunkSize, old.KDFIterations = 0, 0
	if err := fileDAO.Set(&old); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/d/old-v3.bin", nil)
	req.Header.Set("Range", "bytes=130-159")
	if shouldSkipHTTPContentMetaInspection(decryptPlaybackRequest{Request: req, FileDAO: fileDAO, PasswdInfo: passwd, FileItem: FileItem{DisplayPath: old.Path}, ConsumerScenario: consumerScenarioHTTP}, old.Size) {
		t.Fatal("old V3 cache suppressed mandatory reprobe")
	}
}
