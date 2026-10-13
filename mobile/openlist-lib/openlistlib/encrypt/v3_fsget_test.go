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
	"time"
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
			originHeads, originEmptyGets := 0, 0
			revoked := false
			const bearer = "Bearer fs-get-origin"
			const cookie = "session=fs-get-origin"
			var upstream *httptest.Server
			upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fs/get" {
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"name": "movie", "size": len(data), "raw_url": upstream.URL + "/object?sig=" + signature, "is_dir": false}})
					return
				}
				// Local empty/full-cache responses still perform a real origin
				// authorization operation. This is not a metadata prefix probe.
				if r.URL.Path == "/dav/enc/movie" {
					if r.Header.Get("Authorization") != bearer || r.Header.Get("Cookie") != cookie {
						t.Errorf("origin credentials lost: authorization=%q cookie=%q", r.Header.Get("Authorization"), r.Header.Get("Cookie"))
						http.Error(w, "unauthorized", http.StatusUnauthorized)
						return
					}
					switch {
					case r.Method == http.MethodHead && r.Header.Get("Range") == "":
						originHeads++
					case r.Method == http.MethodGet && r.Header.Get("Range") == "bytes=0-0":
						originEmptyGets++
					default:
						t.Errorf("unexpected DAV operation: method=%s range=%q", r.Method, r.Header.Get("Range"))
						http.Error(w, "unexpected DAV operation", http.StatusBadRequest)
						return
					}
					if revoked {
						http.Error(w, "revoked", http.StatusForbidden)
						return
					}
					body := data
					if signature == "b" {
						body = second
					}
					w.Header().Set("ETag", `"cipher-`+signature+`"`)
					http.ServeContent(w, r, "movie", time.Time{}, bytes.NewReader(body))
					return
				}
				if r.URL.Path != "/object" {
					http.NotFound(w, r)
					return
				}
				// The fixture media URL shares the configured origin, so its
				// credentials stay local (external-CDN isolation has separate tests).
				if r.Header.Get("Authorization") != bearer || r.Header.Get("Cookie") != cookie {
					t.Errorf("same-origin media credentials lost: %v", r.Header)
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
			// Use the actual loopback mobile proxy authority. A synthetic public
			// Host would intentionally rewrite the loopback fixture raw URL to
			// that authority, which has no listening server in this test.
			for attempt := 0; attempt < 3; attempt++ {
				if attempt == 2 {
					signature = "b"
					meta = secondMeta
				}
				before := probes
				rec := httptest.NewRecorder()
				getReq := httptest.NewRequest("POST", "http://127.0.0.1:5344/api/fs/get", bytes.NewBufferString(`{"path":"/enc/movie"}`))
				getReq.Header.Set("Authorization", bearer)
				getReq.Header.Set("Cookie", cookie)
				p.handleFsGet(rec, getReq)
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
				playReq := httptest.NewRequest("GET", result.Data.RawURL, nil)
				playReq.Header.Set("Authorization", bearer)
				playReq.Header.Set("Cookie", cookie)
				beforePlaybackProbes := probes
				beforeHeads, beforeEmptyGets := originHeads, originEmptyGets
				newPlayOrchestrator(p).ServePlayback(play, playReq)
				if play.Code != 200 || !bytes.Equal(play.Body.Bytes(), plain) {
					t.Fatalf("attempt%d playback=%d body=%q", attempt, play.Code, play.Body.Bytes())
				}
				if probes != beforePlaybackProbes {
					t.Fatalf("attempt%d playback added metadata prefix probe", attempt)
				}
				if empty && originEmptyGets != beforeEmptyGets+1 {
					t.Fatalf("attempt%d empty playback origin GETs=%d want=%d", attempt, originEmptyGets, beforeEmptyGets+1)
				}
				if !empty && attempt == 1 && originHeads != beforeHeads+1 {
					t.Fatalf("cached playback origin HEADs=%d want=%d", originHeads, beforeHeads+1)
				}
				if attempt == 1 {
					// Cached plaintext/empty geometry never grants permission by
					// itself: a revoked origin must deny this otherwise valid token.
					revoked = true
					denied := httptest.NewRecorder()
					newPlayOrchestrator(p).ServePlayback(denied, playReq.Clone(playReq.Context()))
					revoked = false
					if denied.Code != http.StatusForbidden {
						t.Fatalf("revoked cached token returned %d body=%q", denied.Code, denied.Body.Bytes())
					}
					if probes != beforePlaybackProbes {
						t.Fatal("revoked cached token triggered metadata prefix probe")
					}
				}
			}
			p.config.EncryptPaths[0].Enable = false
			raw := httptest.NewRecorder()
			p.handleFsGet(raw, httptest.NewRequest("POST", "http://127.0.0.1:5344/api/fs/get", bytes.NewBufferString(`{"path":"/enc/movie"}`)))
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
	p.handleFsGet(rec, httptest.NewRequest("POST", "http://127.0.0.1:5344/api/fs/get", bytes.NewBufferString(`{"path":"/enc/movie"}`)))
	if rec.Code != http.StatusBadGateway || !json.Valid(rec.Body.Bytes()) || p.redirectCache.Len() != 0 {
		t.Fatalf("failed probe issued legacy token: status=%d tokens=%d body=%s", rec.Code, p.redirectCache.Len(), rec.Body.String())
	}
	cached, _ := p.loadFileCacheInMem("/enc/movie")
	if cached.ContentVersion != ContentVersionV3 {
		t.Fatalf("recognized V3 downgraded: %+v", cached)
	}
}
