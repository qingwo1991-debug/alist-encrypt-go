package encrypt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"
	"time"
)

func TestShouldRetryPropfind404(t *testing.T) {
	cases := []struct {
		name      string
		depth     string
		path      string
		expectRet bool
	}{
		{name: "depth0 file", depth: "0", path: "/dav/folder/a.mp4", expectRet: true},
		{name: "depth0 noext file", depth: "0", path: "/dav/folder/abc", expectRet: true},
		{name: "depth1 list", depth: "1", path: "/dav/folder/", expectRet: false},
		{name: "infinity list", depth: "infinity", path: "/dav/folder/", expectRet: false},
		{name: "empty depth ext path", depth: "", path: "/dav/folder/a.mkv", expectRet: true},
		{name: "empty depth dir path", depth: "", path: "/dav/folder/", expectRet: false},
		{name: "root", depth: "0", path: "/", expectRet: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRetryPropfind404(tc.depth, tc.path)
			if got != tc.expectRet {
				t.Fatalf("shouldRetryPropfind404(%q,%q)=%v expect %v", tc.depth, tc.path, got, tc.expectRet)
			}
		})
	}
}

func TestShouldPreferEncryptedPropfindForKnownSubtitles(t *testing.T) {
	cases := []struct {
		name      string
		depth     string
		filePath  string
		expectRet bool
	}{
		{name: "srt depth zero", depth: "0", filePath: "/dav/media/movie.srt", expectRet: true},
		{name: "uppercase ass", depth: "", filePath: "/dav/media/movie.ASS", expectRet: true},
		{name: "subtitle directory listing", depth: "1", filePath: "/dav/media/movie.vtt", expectRet: false},
		{name: "video metadata", depth: "0", filePath: "/dav/media/movie.mkv", expectRet: false},
		{name: "unknown extension", depth: "0", filePath: "/dav/media/movie.nfo", expectRet: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldPreferEncryptedPropfind(tc.depth, tc.filePath); got != tc.expectRet {
				t.Fatalf("shouldPreferEncryptedPropfind(%q,%q)=%v want=%v", tc.depth, tc.filePath, got, tc.expectRet)
			}
		})
	}
}

func TestBuildPropfindRetryCandidatesSubtitleIsBounded(t *testing.T) {
	ClearShowNameCache()
	t.Cleanup(ClearShowNameCache)
	ep := &EncryptPath{
		Password:  "123456",
		EncType:   EncTypeAESCTR,
		EncName:   true,
		EncSuffix: ".bin",
	}
	filePath := "/dav/media/movie.srt"
	encryptedPath := path.Join(path.Dir(filePath), convertRealNameByRule(ep, filePath))

	if candidates := buildPropfindRetryCandidates(ep, filePath, filePath, encryptedPath); len(candidates) != 0 {
		t.Fatalf("canonical subtitle miss must not fan out, got %+v", candidates)
	}

	candidates := buildPropfindRetryCandidates(ep, filePath, filePath, filePath)
	if len(candidates) != 1 {
		t.Fatalf("plaintext-start subtitle should have one encrypted fallback, got %+v", candidates)
	}
	if candidates[0].path != encryptedPath || candidates[0].stage != "fallback-encrypted-with-suffix" {
		t.Fatalf("unexpected subtitle candidate: %+v wantPath=%q", candidates[0], encryptedPath)
	}
	for _, candidate := range candidates {
		if candidate.path == filePath {
			t.Fatalf("subtitle candidates must not fall back to plaintext: %+v", candidates)
		}
	}
}

func TestBuildPropfindRetryCandidatesKeepsNonSubtitleCompatibility(t *testing.T) {
	ClearShowNameCache()
	t.Cleanup(ClearShowNameCache)
	ep := &EncryptPath{
		Password:  "123456",
		EncType:   EncTypeAESCTR,
		EncName:   true,
		EncSuffix: ".bin",
	}
	filePath := "/dav/media/movie.mkv"
	withSuffix := path.Join(path.Dir(filePath), convertRealNameByRule(ep, filePath))
	withoutSuffix := path.Join(path.Dir(filePath), ConvertRealNameWithSuffix(ep.Password, ep.EncType, filePath, ""))

	candidates := buildPropfindRetryCandidates(ep, filePath, filePath, withSuffix)
	if len(candidates) != 2 {
		t.Fatalf("expected bounded legacy and original fallbacks, got %+v", candidates)
	}
	if candidates[0].path != withoutSuffix || candidates[0].stage != "fallback-encrypted-no-suffix" {
		t.Fatalf("unexpected first compatibility candidate: %+v", candidates[0])
	}
	if candidates[1].path != filePath || candidates[1].stage != "fallback-original-path" {
		t.Fatalf("unexpected final compatibility candidate: %+v", candidates[1])
	}
}

func TestBuildPropfindRetryCandidatesSubtitleUsesCachedLegacyName(t *testing.T) {
	ClearShowNameCache()
	t.Cleanup(ClearShowNameCache)
	ep := &EncryptPath{
		Password:  "123456",
		EncType:   EncTypeAESCTR,
		EncName:   true,
		EncSuffix: ".bin",
	}
	filePath := "/dav/media/movie.srt"
	legacyRealName := "legacy-encrypted-subtitle"
	CacheNameMapping(path.Dir(filePath), path.Base(filePath), legacyRealName)

	candidates := buildPropfindRetryCandidates(ep, filePath, filePath, filePath)
	if len(candidates) != 1 {
		t.Fatalf("expected one cached exact candidate, got %+v", candidates)
	}
	if want := path.Join(path.Dir(filePath), legacyRealName); candidates[0].path != want {
		t.Fatalf("cached candidate=%q want=%q", candidates[0].path, want)
	}
}

func TestSubtitlePropfindUsesSingleEncryptedProbeAndNegativeCache(t *testing.T) {
	ClearShowNameCache()
	t.Cleanup(ClearShowNameCache)
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	var requestPaths []string
	p.httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestPaths = append(requestPaths, req.URL.Path)
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     http.Header{"Content-Type": []string{"application/xml"}},
				Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><multistatus xmlns="DAV:"/>`)),
				Request:    req,
			}, nil
		}),
	}

	filePath := "/dav/enc/movie.srt"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("PROPFIND", "http://proxy.local"+filePath, nil)
		req.Header.Set("Depth", "0")
		rr := httptest.NewRecorder()
		p.handleWebDAVLegacy(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("request %d status=%d want=%d body=%q", i+1, rr.Code, http.StatusNotFound, rr.Body.String())
		}
	}

	if len(requestPaths) != 1 {
		t.Fatalf("expected one upstream probe across repeated misses, got %d paths=%v", len(requestPaths), requestPaths)
	}
	ep := p.findEncryptPath("/enc/movie.srt")
	wantPath := path.Join(path.Dir(filePath), convertRealNameByRule(ep, filePath))
	if requestPaths[0] != wantPath {
		t.Fatalf("upstream path=%q want encrypted=%q", requestPaths[0], wantPath)
	}
}

func TestPropfindRetryTimeoutClamp(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{ProbeTimeoutSeconds: 20}}
	if got := p.propfindRetryTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("expected 1500ms cap, got %v", got)
	}

	p = &ProxyServer{config: &ProxyConfig{ProbeTimeoutSeconds: 1}}
	if got := p.propfindRetryTimeout(); got != 1*time.Second {
		t.Fatalf("expected 1s passthrough, got %v", got)
	}

	p = &ProxyServer{config: &ProxyConfig{ProbeTimeoutSeconds: 0}}
	if got := p.propfindRetryTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("expected default capped 1500ms, got %v", got)
	}
}

func TestProcessPropfindResponseCachesResolvedRealName(t *testing.T) {
	ClearShowNameCache()
	p := &ProxyServer{}
	ep := &EncryptPath{
		Path:      "/enc/*",
		Password:  "123456",
		EncType:   EncTypeAESCTR,
		EncName:   true,
		EncSuffix: ".bin",
		Enable:    true,
	}
	realName := ConvertRealNameWithSuffix(ep.Password, ep.EncType, "/enc/MFCW-019.mp4", "")
	xmlBody := `<?xml version="1.0" encoding="utf-8"?><multistatus><response><href>/enc/` + realName + `</href><propstat><prop><displayname>` + realName + `</displayname><getcontentlength>123</getcontentlength></prop></propstat></response></multistatus>`
	var out bytes.Buffer
	if err := p.processPropfindResponse(strings.NewReader(xmlBody), &out, ep); err != nil {
		t.Fatalf("process propfind: %v", err)
	}
	if got, ok := GetCachedRealName("/enc", "MFCW-019.mp4"); !ok || got != realName {
		t.Fatalf("cached real name=%q ok=%v want=%q", got, ok, realName)
	}
}

func TestWebDAVFullGetUsesEncryptedDAVDespiteCachedRawURL(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	p.storeFileCache("/dav/enc/MFCW-019.mp4", &FileInfo{
		Name:   "MFCW-019.mp4",
		Size:   1024,
		IsDir:  false,
		Path:   "/dav/enc/MFCW-019.mp4",
		RawURL: "http://cdn.example/video",
	})
	hitURL := ""
	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hitURL = req.URL.String()
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
				Request:    req,
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	rr := httptest.NewRecorder()
	p.handleWebDAVLegacy(rr, req)

	encPath := p.findEncryptPath("/enc/MFCW-019.mp4")
	encryptedName := convertRealNameByRule(encPath, "/dav/enc/MFCW-019.mp4")
	wantURL := "http://alist.local:5244/dav/enc/" + encryptedName
	if hitURL != wantURL {
		t.Fatalf("hitURL=%q want=%q", hitURL, wantURL)
	}
	if strings.Contains(hitURL, "MFCW-019.mp4") {
		t.Fatalf("full GET leaked plaintext filename upstream: %q", hitURL)
	}
}

func TestWebDAVFirstFrameRangeUsesCachedRawURL(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	p.storeFileCache("/dav/enc/MFCW-019.mp4", &FileInfo{
		Name:           "MFCW-019.mp4",
		Size:           4096,
		CiphertextSize: 4128,
		ContentVersion: ContentVersionV2,
		HeaderLen:      32,
		NonceField:     bytes.Repeat([]byte{1}, 16),
		IsDir:          false,
		Path:           "/dav/enc/MFCW-019.mp4",
		RawURL:         "http://cdn.example/video",
	})
	hitURL := ""
	hitRange := ""
	hitAuthorization := ""
	hitCookie := ""
	hitProxyAuthorization := ""
	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hitURL = req.URL.String()
			hitRange = req.Header.Get("Range")
			hitAuthorization = req.Header.Get("Authorization")
			hitCookie = req.Header.Get("Cookie")
			hitProxyAuthorization = req.Header.Get("Proxy-Authorization")
			return &http.Response{
				StatusCode: http.StatusTeapot,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("sentinel")),
				Request:    req,
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	req.Header.Set("Range", "bytes=0-1023")
	req.Header.Set("Authorization", "Bearer local-only")
	req.Header.Set("Cookie", "session=local-only")
	req.Header.Set("Proxy-Authorization", "Basic proxy-local-only")
	rr := httptest.NewRecorder()
	p.handleWebDAVLegacy(rr, req)

	if hitURL != "http://cdn.example/video" {
		t.Fatalf("hitURL=%q", hitURL)
	}
	if hitRange != "bytes=32-1055" {
		t.Fatalf("upstream Range=%q want=%q", hitRange, "bytes=32-1055")
	}
	if hitAuthorization != "" || hitCookie != "" || hitProxyAuthorization != "" {
		t.Fatalf("CDN received local credentials: Authorization=%q Cookie=%q Proxy-Authorization=%q",
			hitAuthorization, hitCookie, hitProxyAuthorization)
	}
}

func TestWebDAVRangeValidatesStartAndSupportsShortWindow(t *testing.T) {
	const (
		password = "123456"
		rawURL   = "http://cdn.example/range-window"
		cacheKey = "/dav/enc/range-window.mp4"
	)
	plain := bytes.Repeat([]byte("range-window-payload-"), 256)
	contentEnc, err := NewLatestContentEncryptor(password, string(EncTypeAESCTR), int64(len(plain)))
	if err != nil {
		t.Fatalf("new content encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	tests := []struct {
		name           string
		upstreamStart  int64
		upstreamLength int64
		wantStatus     int
		wantBody       []byte
		wantRange      string
	}{
		{
			name:           "short window",
			upstreamStart:  contentEnc.Meta.HeaderLen,
			upstreamLength: 256,
			wantStatus:     http.StatusPartialContent,
			wantBody:       plain[:256],
			wantRange:      fmt.Sprintf("bytes 0-255/%d", len(plain)),
		},
		{
			name:           "wrong start",
			upstreamStart:  contentEnc.Meta.HeaderLen + 1,
			upstreamLength: 256,
			wantStatus:     http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ClearShowNameCache()
			p, err := NewProxyServer(&ProxyConfig{
				AlistHost:                       "alist.local",
				AlistPort:                       5244,
				ProxyPort:                       5344,
				AlistHttps:                      false,
				ProviderCatalogEnabled:          false,
				ProviderCatalogTTLMinutes:       1,
				ProviderCatalogBootstrapOnStart: false,
				EncryptPaths: []*EncryptPath{
					{
						Path:     "/enc/*",
						Password: password,
						EncType:  EncTypeAESCTR,
						Enable:   true,
					},
				},
			})
			if err != nil {
				t.Fatalf("new proxy server: %v", err)
			}
			defer p.stopRangeProbeLoop()
			defer p.stopCacheCleanup()
			defer p.closeLocalStore()

			p.storeFileCache(cacheKey, &FileInfo{
				Name:           path.Base(cacheKey),
				Size:           int64(len(plain)),
				CiphertextSize: int64(len(ciphertext)),
				ContentVersion: ContentVersionV2,
				HeaderLen:      contentEnc.Meta.HeaderLen,
				NonceField:     cloneNonceField(contentEnc.Meta.NonceField),
				IsDir:          false,
				Path:           cacheKey,
				RawURL:         rawURL,
			})

			upstreamEnd := tt.upstreamStart + tt.upstreamLength - 1
			var upstreamRange string
			p.streamClient = &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					upstreamRange = req.Header.Get("Range")
					return &http.Response{
						StatusCode: http.StatusPartialContent,
						Header: http.Header{
							"Content-Range": []string{
								fmt.Sprintf("bytes %d-%d/%d", tt.upstreamStart, upstreamEnd, len(ciphertext)),
							},
							"Content-Length": []string{fmt.Sprintf("%d", tt.upstreamLength)},
						},
						Body:    io.NopCloser(bytes.NewReader(ciphertext[tt.upstreamStart : upstreamEnd+1])),
						Request: req,
					}, nil
				}),
			}

			req := httptest.NewRequest(http.MethodGet, "http://proxy.local"+cacheKey, nil)
			req.Header.Set("Range", "bytes=0-1023")
			rr := httptest.NewRecorder()
			p.handleWebDAVLegacy(rr, req)

			if upstreamRange != fmt.Sprintf("bytes=%d-%d", contentEnc.Meta.HeaderLen, contentEnc.Meta.HeaderLen+1023) {
				t.Fatalf("upstream Range=%q", upstreamRange)
			}
			if rr.Code != tt.wantStatus {
				t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
			}
			if tt.wantStatus != http.StatusPartialContent {
				if bytes.Contains(rr.Body.Bytes(), tt.wantBody) && len(tt.wantBody) > 0 {
					t.Fatal("unsafe decrypted payload was returned after invalid Content-Range")
				}
				return
			}
			if got := rr.Header().Get("Content-Range"); got != tt.wantRange {
				t.Fatalf("Content-Range=%q want=%q", got, tt.wantRange)
			}
			if got := rr.Header().Get("Content-Length"); got != fmt.Sprintf("%d", len(tt.wantBody)) {
				t.Fatalf("Content-Length=%q want=%d", got, len(tt.wantBody))
			}
			if !bytes.Equal(rr.Body.Bytes(), tt.wantBody) {
				t.Fatalf("decrypted short window mismatch: got=%d want=%d", rr.Body.Len(), len(tt.wantBody))
			}
		})
	}
}

func TestWebDAVDeepSeekUsesEncryptedDAVAndShiftsV2Range(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	p.storeFileCache("/dav/enc/MFCW-019.mp4", &FileInfo{
		Name:           "MFCW-019.mp4",
		Size:           32 * 1024 * 1024,
		CiphertextSize: 32*1024*1024 + 32,
		ContentVersion: ContentVersionV2,
		HeaderLen:      32,
		NonceField:     bytes.Repeat([]byte{2}, 16),
		IsDir:          false,
		Path:           "/dav/enc/MFCW-019.mp4",
		RawURL:         "http://cdn.example/video",
	})
	hitURL := ""
	hitRange := ""
	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hitURL = req.URL.String()
			hitRange = req.Header.Get("Range")
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
				Request:    req,
			}, nil
		}),
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	req.Header.Set("Range", "bytes=10485760-10486783")
	rr := httptest.NewRecorder()
	p.handleWebDAVLegacy(rr, req)

	encPath := p.findEncryptPath("/enc/MFCW-019.mp4")
	encryptedName := convertRealNameByRule(encPath, "/dav/enc/MFCW-019.mp4")
	wantURL := "http://alist.local:5244/dav/enc/" + encryptedName
	if hitURL != wantURL {
		t.Fatalf("hitURL=%q want=%q", hitURL, wantURL)
	}
	if hitRange != "bytes=10485792-10486815" {
		t.Fatalf("upstream Range=%q", hitRange)
	}
	if strings.Contains(hitURL, "MFCW-019.mp4") {
		t.Fatalf("deep seek leaked plaintext filename upstream: %q", hitURL)
	}
}

func TestWebDAVGetResolvesRawURLViaFsGetOnCacheMiss(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	requests := make([]string, 0, 4)
	fsGetPath := ""
	p.httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests = append(requests, req.URL.String())
			if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/api/fs/get") {
				var payload map[string]string
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Fatalf("decode strict fs/get request: %v", err)
				}
				fsGetPath = payload["path"]
				body := `{"code":200,"data":{"name":"GUigmo3YcGdyIf03s.mp4","size":123,"raw_url":"http://cdn.example/fresh"}}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusTeapot,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("sentinel")),
				Request:    req,
			}, nil
		}),
	}
	p.streamClient = p.httpClient

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	req.Header.Set("Range", "bytes=0-1023")
	rr := httptest.NewRecorder()
	p.handleWebDAVLegacy(rr, req)

	var sawFsGet, sawRaw bool
	for _, reqURL := range requests {
		if strings.Contains(reqURL, "/api/fs/get") {
			sawFsGet = true
		}
		if reqURL == "http://cdn.example/fresh" {
			sawRaw = true
		}
	}
	if !sawFsGet || !sawRaw {
		t.Fatalf("requests=%v sawFsGet=%v sawRaw=%v", requests, sawFsGet, sawRaw)
	}
	if fsGetPath == "" || strings.Contains(fsGetPath, "MFCW-019.mp4") {
		t.Fatalf("strict fs/get used plaintext path: %q", fsGetPath)
	}
	encPath := p.findEncryptPath("/enc/MFCW-019.mp4")
	encryptedName := convertRealNameByRule(encPath, "/dav/enc/MFCW-019.mp4")
	if want := "/enc/" + encryptedName; fsGetPath != want {
		t.Fatalf("strict fs/get path=%q want=%q", fsGetPath, want)
	}
}

func TestWebDAVRawURL404RefreshesThenFallsBackToEncryptedDAV(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	const (
		staleRaw = "http://cdn.example/stale"
		freshRaw = "http://cdn.example/refreshed"
	)
	p.storeFileCache("/dav/enc/MFCW-019.mp4", &FileInfo{
		Name:           "MFCW-019.mp4",
		Size:           4096,
		CiphertextSize: 4128,
		ContentVersion: ContentVersionV2,
		HeaderLen:      32,
		NonceField:     bytes.Repeat([]byte{3}, 16),
		IsDir:          false,
		Path:           "/dav/enc/MFCW-019.mp4",
		RawURL:         staleRaw,
	})

	type requestRecord struct {
		method        string
		url           string
		body          string
		authorization string
		cookie        string
		proxyAuth     string
	}
	var requests []requestRecord
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		record := requestRecord{
			method:        req.Method,
			url:           req.URL.String(),
			authorization: req.Header.Get("Authorization"),
			cookie:        req.Header.Get("Cookie"),
			proxyAuth:     req.Header.Get("Proxy-Authorization"),
		}
		if req.Body != nil {
			body, readErr := io.ReadAll(req.Body)
			if readErr != nil {
				t.Fatalf("read request body: %v", readErr)
			}
			record.body = string(body)
		}
		requests = append(requests, record)
		switch {
		case req.Method == http.MethodPost && req.URL.Path == "/api/fs/get":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body: io.NopCloser(strings.NewReader(
					`{"code":200,"data":{"size":4128,"raw_url":"` + freshRaw + `"}}`,
				)),
				Request: req,
			}, nil
		case req.URL.String() == staleRaw:
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("expired")),
				Request:    req,
			}, nil
		case req.URL.String() == freshRaw:
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("expired")),
				Request:    req,
			}, nil
		case strings.HasPrefix(req.URL.String(), "http://alist.local:5244/dav/enc/"):
			return &http.Response{
				StatusCode: http.StatusFound,
				Header:     http.Header{"Location": []string{"http://cdn.example/from-dav"}},
				Body:       io.NopCloser(strings.NewReader("redirect")),
				Request:    req,
			}, nil
		case req.Method == http.MethodGet && req.URL.Path == "/api/admin/storage/list":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"code":200,"data":{"content":[]}}`)),
				Request:    req,
			}, nil
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
			return nil, nil
		}
	})
	noRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	p.httpClient = &http.Client{Transport: transport, CheckRedirect: noRedirect}
	p.streamClient = &http.Client{Transport: transport, CheckRedirect: noRedirect}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	req.Header.Set("Range", "bytes=0-1023")
	req.Header.Set("Authorization", "Bearer local-only")
	req.Header.Set("Cookie", "session=local-only")
	req.Header.Set("Proxy-Authorization", "Basic proxy-local-only")
	rr := httptest.NewRecorder()
	p.handleWebDAVLegacy(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%q requests=%v", rr.Code, rr.Body.String(), requests)
	}
	if location := rr.Header().Get("Location"); !strings.HasPrefix(location, "/redirect/") {
		t.Fatalf("proxy redirect Location=%q", location)
	}
	var sawStale, sawFresh, sawEncryptedDAV bool
	for _, record := range requests {
		if strings.Contains(record.url, "MFCW-019.mp4") || strings.Contains(record.body, "MFCW-019.mp4") {
			t.Fatalf("plaintext OriginalURL was requested: %+v", record)
		}
		switch {
		case record.url == staleRaw:
			if record.authorization != "" || record.cookie != "" || record.proxyAuth != "" {
				t.Fatalf("stale CDN received local credentials: %+v", record)
			}
			sawStale = true
		case record.url == freshRaw:
			if record.authorization != "" || record.cookie != "" || record.proxyAuth != "" {
				t.Fatalf("refreshed CDN received local credentials: %+v", record)
			}
			sawFresh = true
		case strings.HasPrefix(record.url, "http://alist.local:5244/dav/enc/"):
			if record.authorization != "Bearer local-only" ||
				record.cookie != "session=local-only" ||
				record.proxyAuth != "" {
				t.Fatalf("encrypted /dav fallback lost credentials: %+v", record)
			}
			sawEncryptedDAV = true
		}
	}
	if !sawStale || !sawFresh || !sawEncryptedDAV {
		t.Fatalf("requests=%v stale=%v fresh=%v encryptedDAV=%v", requests, sawStale, sawFresh, sawEncryptedDAV)
	}
	if !p.rawURLFailureBlocked(staleRaw) || !p.rawURLFailureBlocked(freshRaw) {
		t.Fatalf("failed raw URLs were not placed in cooldown: stale=%v fresh=%v",
			p.rawURLFailureBlocked(staleRaw), p.rawURLFailureBlocked(freshRaw))
	}
	if cached, ok := p.loadFileCache("/dav/enc/MFCW-019.mp4"); !ok {
		t.Fatal("playback cache missing after fallback")
	} else if isInternalAlistTarget(cached.RawURL, p.getAlistURL()) {
		t.Fatalf("internal /dav was cached as RawURL and would suppress future refresh: %q", cached.RawURL)
	}

	beforeSecond := len(requests)
	secondReq := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	secondReq.Header.Set("Range", "bytes=0-1023")
	secondReq.Header.Set("Authorization", "Bearer local-only")
	secondReq.Header.Set("Cookie", "session=local-only")
	secondReq.Header.Set("Proxy-Authorization", "Basic proxy-local-only")
	secondRR := httptest.NewRecorder()
	p.handleWebDAVLegacy(secondRR, secondReq)
	if secondRR.Code != http.StatusFound {
		t.Fatalf("second status=%d body=%q", secondRR.Code, secondRR.Body.String())
	}
	for _, record := range requests[beforeSecond:] {
		if record.url == staleRaw || record.url == freshRaw {
			t.Fatalf("cooldown retried a known-bad raw URL: %+v", record)
		}
	}
}

func TestWebDAVGetKeepsDavPathWhenNoRawURL(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:                       "alist.local",
		AlistPort:                       5244,
		ProxyPort:                       5344,
		AlistHttps:                      false,
		ProviderCatalogEnabled:          false,
		ProviderCatalogTTLMinutes:       1,
		ProviderCatalogBootstrapOnStart: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:      "/enc/*",
				Password:  "123456",
				EncType:   EncTypeAESCTR,
				EncName:   true,
				EncSuffix: ".bin",
				Enable:    true,
			},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	requests := make([]string, 0, 2)
	p.httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requests = append(requests, req.URL.String())
			if req.Method == http.MethodPost && strings.Contains(req.URL.Path, "/api/fs/get") {
				body := `{"code":404,"message":"object not found"}`
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
				Request:    req,
			}, nil
		}),
	}
	p.streamClient = p.httpClient

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/dav/enc/MFCW-019.mp4", nil)
	rr := httptest.NewRecorder()
	p.handleWebDAVLegacy(rr, req)

	sawDavPath := false
	for _, reqURL := range requests {
		if strings.HasPrefix(reqURL, "http://alist.local:5244/dav/enc/") && !strings.Contains(reqURL, "/d/enc/") {
			sawDavPath = true
			break
		}
	}
	if !sawDavPath {
		t.Fatalf("requests=%v", requests)
	}
}
