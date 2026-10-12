package encrypt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	core "github.com/alist-encrypt-go/shared/encryptcore"
)

func v3RedirectFixture(t *testing.T, plain []byte, fixed bool) ([]byte, ContentMeta) {
	t.Helper()
	var buf bytes.Buffer
	writer, err := core.NewV3Writer(&buf, "redirect-test", 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), buf.Bytes()...)
	if fixed {
		data = data[:len(data)-V3TrailerSize]
		binary.BigEndian.PutUint64(data[24:32], uint64(len(plain)))
	}
	meta, recognized, err := ParseV3ContentHeader(EncTypeAESCTR, data[:V3HeaderSize], int64(len(data)))
	if err != nil || !recognized {
		t.Fatalf("parse: recognized=%v err=%v", recognized, err)
	}
	if !fixed {
		meta, err = CompleteV3ContentMeta(meta, data[len(data)-V3TrailerSize:])
		if err != nil {
			t.Fatal(err)
		}
	}
	return data, meta
}

func TestV3RedirectHTTPBridge(t *testing.T) {
	plain := bytes.Repeat([]byte("plaintext-v3:"), 19)
	for _, fixed := range []bool{false, true} {
		data, meta := v3RedirectFixture(t, plain, fixed)
		for _, known := range []bool{false, true} {
			for _, route := range []string{"redirect", "api"} {
				for _, tc := range []struct {
					method, rangeHeader string
					start, end          int
				}{
					{"GET", "", 0, len(plain)}, {"GET", "bytes=60-139", 60, 140},
					{"GET", "bytes=-7", len(plain) - 7, len(plain)}, {"GET", "bytes=90-", 90, len(plain)},
					{"HEAD", "", 0, len(plain)}, {"HEAD", "bytes=-7", len(plain) - 7, len(plain)},
				} {
					t.Run(fmt.Sprintf("fixed=%v/known=%v/%s/%s/%s", fixed, known, route, tc.method, tc.rangeHeader), func(t *testing.T) {
						probes := 0
						upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							if r.Header.Get("Range") == "bytes=0-47" {
								probes++
							}
							start, end, has, err := parseSingleRange(r.Header.Get("Range"), int64(len(data)))
							if err != nil {
								writeRangeNotSatisfiable(w, int64(len(data)))
								return
							}
							if !has {
								start, end = 0, int64(len(data)-1)
							}
							w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
							if has {
								w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
								w.WriteHeader(206)
							}
							if r.Method != "HEAD" {
								_, _ = w.Write(data[start : end+1])
							}
						}))
						defer upstream.Close()
						p := &ProxyServer{config: &ProxyConfig{StreamEngineVersion: 2, PlayFirstFallback: true}, localStore: &localStore{}, streamClient: upstream.Client()}
						p.ensureRuntimeCaches()
						info := &RedirectInfo{RedirectURL: upstream.URL + "/object?signature=exact", OriginalURL: "/enc/video.mp4", EncryptedPath: "/enc/object", FileSize: int64(len(data)), PasswdInfo: &EncryptPath{Enable: true, EncType: EncTypeAESCTR, Password: "redirect-test"}}
						if known {
							info.ContentVersion = meta.Version
							info.HeaderLen = meta.HeaderLen
							info.NonceField = cloneNonceField(meta.NonceField)
							info.FileSize = meta.PlainSize
							info.CiphertextSize = meta.CiphertextSize
							info.ChunkSize = meta.ChunkSize
							info.KDFIterations = meta.KDFIterations
						}
						p.storeRedirectCache("fixture", info)
						target := "http://proxy.local/redirect/fixture?decode=1"
						if route == "api" {
							target = "http://proxy.local/api/play/stream/fixture?decode=1"
						}
						req := httptest.NewRequest(tc.method, target, nil)
						req.Header.Set("Range", tc.rangeHeader)
						rec := httptest.NewRecorder()
						if route == "api" {
							p.handlePlayStream(rec, req)
						} else {
							newPlayOrchestrator(p).ServePlayback(rec, req)
						}
						status := 200
						if tc.rangeHeader != "" {
							status = 206
						}
						if rec.Code != status || rec.Header().Get("Content-Length") != strconv.Itoa(tc.end-tc.start) {
							t.Fatalf("status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
						}
						if tc.method == "GET" && !bytes.Equal(rec.Body.Bytes(), plain[tc.start:tc.end]) {
							t.Fatalf("wrong plaintext %q", rec.Body.Bytes())
						}
						if tc.method == "HEAD" && rec.Body.Len() != 0 {
							t.Fatal("HEAD body")
						}
						if known && probes != 0 {
							t.Fatalf("complete metadata redundantly probed %d times", probes)
						}
						if tc.rangeHeader != "" && rec.Header().Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end-1, len(plain)) {
							t.Fatalf("content range %q", rec.Header().Get("Content-Range"))
						}
					})
				}
			}
		}
	}
}

func TestV3RedirectEmptyAndRaw(t *testing.T) {
	for _, empty := range []bool{false, true} {
		plain := []byte("ciphertext passthrough")
		if empty {
			plain = nil
		}
		data, meta := v3RedirectFixture(t, plain, false)
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			if r.Method != http.MethodHead {
				_, _ = w.Write(data)
			}
		}))
		p := &ProxyServer{config: &ProxyConfig{StreamEngineVersion: 2}, localStore: &localStore{}, streamClient: upstream.Client()}
		p.ensureRuntimeCaches()
		info := &RedirectInfo{RedirectURL: upstream.URL, OriginalURL: "/enc/empty", ContentVersion: meta.Version, FileSize: meta.PlainSize,
			CiphertextSize: meta.CiphertextSize, HeaderLen: meta.HeaderLen, NonceField: meta.NonceField, ChunkSize: meta.ChunkSize,
			KDFIterations: meta.KDFIterations, PasswdInfo: &EncryptPath{Enable: true, EncType: EncTypeAESCTR, Password: "redirect-test"}}
		p.storeRedirectCache("empty", info)
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			newPlayOrchestrator(p).ServeRedirect(rec, httptest.NewRequest(method, "http://proxy.local/redirect/empty?decode=0", nil))
			if rec.Code != 200 || rec.Header().Get("Content-Length") != strconv.Itoa(len(data)) {
				t.Fatalf("raw headers: %d %v", rec.Code, rec.Header())
			}
			if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), data) {
				t.Fatal("raw ciphertext changed")
			}
			if method == http.MethodHead && rec.Body.Len() != 0 {
				t.Fatal("raw HEAD body")
			}
		}
		if empty {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := httptest.NewRecorder()
				newPlayOrchestrator(p).ServeRedirect(rec, httptest.NewRequest(method, "http://proxy.local/redirect/empty", nil))
				if rec.Code != 200 || rec.Header().Get("Content-Length") != "0" || rec.Body.Len() != 0 {
					t.Fatalf("empty: %d %v %q", rec.Code, rec.Header(), rec.Body.Bytes())
				}
			}
			req := httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/empty", nil)
			req.Header.Set("Range", "bytes=0-")
			rec := httptest.NewRecorder()
			newPlayOrchestrator(p).ServeRedirect(rec, req)
			if rec.Code != 416 || rec.Header().Get("Content-Range") != "bytes */0" {
				t.Fatalf("empty range: %d %v", rec.Code, rec.Header())
			}
		}
		upstream.Close()
	}
}

func TestV3PlaybackCacheRequiresCompleteExactURL(t *testing.T) {
	data, meta := v3RedirectFixture(t, []byte("cache identity"), true)
	cached := &FileInfo{ContentVersion: ContentVersionV3, Size: meta.PlainSize, CiphertextSize: int64(len(data)), HeaderLen: meta.HeaderLen, NonceField: meta.NonceField, ChunkSize: meta.ChunkSize, KDFIterations: meta.KDFIterations, RawURL: "https://cdn.local/object?sign=one"}
	if _, ok := playbackFileInfoContentMeta(cached, EncTypeAESCTR, cached.RawURL); !ok {
		t.Fatal("valid complete cache rejected")
	}
	for _, target := range []string{"https://cdn.local/object?sign=two", " " + cached.RawURL, ""} {
		if _, ok := playbackFileInfoContentMeta(cached, EncTypeAESCTR, target); ok {
			t.Fatalf("identity mismatch accepted %q", target)
		}
	}
	cached.ChunkSize = 0
	if _, ok := playbackFileInfoContentMeta(cached, EncTypeAESCTR, cached.RawURL); ok {
		t.Fatal("placeholder accepted")
	}
	info := &RedirectInfo{ContentVersion: ContentVersionV3, FileSize: meta.PlainSize, HeaderLen: meta.HeaderLen, CiphertextSize: meta.CiphertextSize}
	if got := redirectRawFileSize(info, meta.PlainSize); got != meta.CiphertextSize {
		t.Fatalf("raw size=%d", got)
	}
}
