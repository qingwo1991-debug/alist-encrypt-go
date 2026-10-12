package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type emptyV3PlaybackRepository struct {
	ports.FileRepository
	info *dao.FileInfo
}

func (s *emptyV3PlaybackRepository) Get(string) (*dao.FileInfo, bool) { return s.info, true }

func TestExecuteDecryptPlaybackCachedEmptyV3(t *testing.T) {
	var container bytes.Buffer
	writer, err := encryption.NewV3Writer(&container, "pw", 73)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, fixed := range []bool{false, true} {
		body := container.Bytes()
		if fixed {
			body = body[:encryption.V3HeaderSize]
		}
		for _, tc := range []struct {
			method      string
			rangeHeader string
			status      int
		}{
			{http.MethodGet, "", http.StatusOK},
			{http.MethodHead, "", http.StatusOK},
			{http.MethodGet, "bytes=0-0", http.StatusRequestedRangeNotSatisfiable},
		} {
			t.Run(fmt.Sprintf("fixed=%v/%s/range=%s", fixed, tc.method, tc.rangeHeader), func(t *testing.T) {
				var hits int
				srv := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hits++
					// Empty plaintext ranges must not be translated into a bogus
					// ciphertext chunk request: there is no record in this file.
					w.Header().Set("Content-Type", "application/octet-stream")
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					w.WriteHeader(http.StatusOK)
					if r.Method != http.MethodHead {
						_, _ = w.Write(body)
					}
				}))
				defer srv.Close()
				cfg := config.DefaultConfig()
				repository := &emptyV3PlaybackRepository{info: &dao.FileInfo{
					Path: "/empty.bin", ContentVersion: encryption.ContentVersionV3,
					Size: 0, HeaderLen: encryption.V3HeaderSize, CiphertextSize: int64(len(body)),
					NonceField: writer.NonceField(), ChunkSize: 73, KDFIterations: 600000,
				}}
				req := httptest.NewRequest(tc.method, "/empty.bin", nil)
				if tc.rangeHeader != "" {
					req.Header.Set("Range", tc.rangeHeader)
				}
				rr := httptest.NewRecorder()
				executeDecryptPlayback(decryptPlaybackRequest{
					ResponseWriter: rr, Request: req, Config: cfg, StreamProxy: proxy.NewStreamProxy(cfg),
					FileDAO: repository, FileItem: FileItem{DisplayPath: "/empty.bin"}, TargetURL: srv.URL,
					PasswdInfo:  &config.PasswdInfo{Password: "pw", EncType: "aesctr", Enable: true},
					InitialSize: int64(len(body)),
				})
				if hits != 1 || rr.Code != tc.status || rr.Body.Len() != 0 {
					t.Fatalf("hits=%d status=%d body=%q, want one request/status%d/no appended JSON", hits, rr.Code, rr.Body.Bytes(), tc.status)
				}
				if tc.status == http.StatusOK && rr.Header().Get("Content-Length") != "0" {
					t.Fatalf("empty Content-Length=%q", rr.Header().Get("Content-Length"))
				}
				if tc.status == http.StatusRequestedRangeNotSatisfiable && rr.Header().Get("Content-Range") != "bytes */0" {
					t.Fatalf("empty Content-Range=%q", rr.Header().Get("Content-Range"))
				}
			})
		}
	}
}
