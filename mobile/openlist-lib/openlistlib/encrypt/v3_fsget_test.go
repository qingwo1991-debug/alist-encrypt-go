package encrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"
)

func TestV3FsGetRepeatedTokenPlaybackAndURLIdentity(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			plain := bytes.Repeat([]byte("fs-get-plaintext:"), 13)
			if empty {
				plain = nil
			}
			data, meta := v3RedirectFixture(t, plain, false)
			second, secondMeta := v3RedirectFixture(t, plain, false)
			signature := "a"
			probes := 0
			var upstream *httptest.Server
			upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fs/get" {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"name": "movie", "size": len(data), "raw_url": upstream.URL + "/object?sig=" + signature, "is_dir": false}})
					return
				}
				if r.URL.Path != "/object" {
					http.NotFound(w, r)
					return
				}
				body := data
				if r.URL.Query().Get("sig") == "b" {
					body = second
				}
				if r.Header.Get("Range") == "bytes=0-47" {
					probes++
				}
				start, end, has, err := parseSingleRange(r.Header.Get("Range"), int64(len(body)))
				if err != nil {
					writeRangeNotSatisfiable(w, int64(len(body)))
					return
				}
				if !has {
					start, end = 0, int64(len(body)-1)
				}
				w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
				if has {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
					w.WriteHeader(206)
				}
				_, _ = w.Write(body[start : end+1])
			}))
			defer upstream.Close()
			u, _ := url.Parse(upstream.URL)
			port, _ := strconv.Atoi(u.Port())
			p := &ProxyServer{config: &ProxyConfig{AlistHost: u.Hostname(), AlistPort: port, StreamEngineVersion: 2,
				EncryptPaths: []*EncryptPath{{Path: "/enc/*", Enable: true, EncType: EncTypeAESCTR, Password: "redirect-test", regex: regexp.MustCompile(`^/enc/`)}}}, httpClient: upstream.Client(), streamClient: upstream.Client()}
			p.ensureRuntimeCaches()
			p.storageDriverMap = map[string]string{"/enc": "test"}
			for attempt := 0; attempt < 3; attempt++ {
				if attempt == 2 {
					signature = "b"
					meta = secondMeta
				}
				before := probes
				rec := httptest.NewRecorder()
				p.handleFsGet(rec, httptest.NewRequest("POST", "http://proxy.local/api/fs/get", bytes.NewBufferString(`{"path":"/enc/movie"}`)))
				if rec.Code != 200 {
					t.Fatalf("fs/get=%d %s", rec.Code, rec.Body.String())
				}
				var result struct {
					Data struct {
						RawURL string `json:"raw_url"`
						Size   int64  `json:"size"`
					}
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Data.Size != int64(len(plain)) {
					t.Fatalf("wrong plaintext size %d", result.Data.Size)
				}
				cached, ok := p.loadFileCacheInMem("/enc/movie")
				if !ok || !fileInfoHasCompleteV3(cached) || !bytes.Equal(cached.NonceField, meta.NonceField) {
					t.Fatalf("cached metadata downgraded: %+v", cached)
				}
				if attempt == 1 && probes != before {
					t.Fatal("same-URL complete cache needlessly reprobed")
				}
				if attempt == 2 && probes == before {
					t.Fatal("new URL did not refresh header identity")
				}
				play := httptest.NewRecorder()
				newPlayOrchestrator(p).ServePlayback(play, httptest.NewRequest("GET", result.Data.RawURL, nil))
				if play.Code != 200 || !bytes.Equal(play.Body.Bytes(), plain) {
					t.Fatalf("attempt%d playback=%d body=%q", attempt, play.Code, play.Body.Bytes())
				}
			}
			p.config.EncryptPaths[0].Enable = false
			raw := httptest.NewRecorder()
			p.handleFsGet(raw, httptest.NewRequest("POST", "http://proxy.local/api/fs/get", bytes.NewBufferString(`{"path":"/enc/movie"}`)))
			var result struct {
				Data struct {
					RawURL string `json:"raw_url"`
					Size   int    `json:"size"`
				}
			}
			if err := json.Unmarshal(raw.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if raw.Code != 200 || result.Data.RawURL != upstream.URL+"/object?sig=b" || result.Data.Size != len(data) {
				t.Fatalf("disabled encryption changed raw metadata: %s", raw.Body.String())
			}
		})
	}
}

func TestV3FsGetFailedProbeDoesNotCreateLegacyToken(t *testing.T) {
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fs/get" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"size": 128, "raw_url": upstream.URL + "/object"}})
			return
		}
		http.Error(w, "unavailable", http.StatusBadGateway)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	port, _ := strconv.Atoi(u.Port())
	p := &ProxyServer{config: &ProxyConfig{AlistHost: u.Hostname(), AlistPort: port, EncryptPaths: []*EncryptPath{{Path: "/enc/*", Enable: true, EncType: EncTypeAESCTR, Password: "redirect-test", regex: regexp.MustCompile(`^/enc/`)}}}, httpClient: upstream.Client(), streamClient: upstream.Client()}
	p.ensureRuntimeCaches()
	p.storeFileCacheList("/enc/movie", &FileInfo{ContentVersion: ContentVersionV3, RawURL: upstream.URL + "/object", HeaderLen: V3HeaderSize})
	rec := httptest.NewRecorder()
	p.handleFsGet(rec, httptest.NewRequest("POST", "http://proxy.local/api/fs/get", bytes.NewBufferString(`{"path":"/enc/movie"}`)))
	if rec.Code != http.StatusBadGateway || !json.Valid(rec.Body.Bytes()) || p.redirectCache.Len() != 0 {
		t.Fatalf("failed probe issued legacy token: status=%d tokens=%d body=%s", rec.Code, p.redirectCache.Len(), rec.Body.String())
	}
	cached, _ := p.loadFileCacheInMem("/enc/movie")
	if cached.ContentVersion != ContentVersionV3 {
		t.Fatalf("recognized V3 downgraded: %+v", cached)
	}
}
