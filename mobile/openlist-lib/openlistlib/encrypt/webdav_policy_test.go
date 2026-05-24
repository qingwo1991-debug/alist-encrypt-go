package encrypt

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestWebDAVGetUsesCachedRawURL(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:  "alist.local",
		AlistPort:  5244,
		ProxyPort:  5344,
		AlistHttps: false,
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

	if hitURL != "http://cdn.example/video" {
		t.Fatalf("hitURL=%q", hitURL)
	}
}

func TestWebDAVGetResolvesRawURLViaFsGetOnCacheMiss(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:  "alist.local",
		AlistPort:  5244,
		ProxyPort:  5344,
		AlistHttps: false,
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
				body := `{"code":200,"data":{"name":"GUigmo3YcGdyIf03s.mp4","size":123,"raw_url":"http://cdn.example/fresh"}}`
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
}

func TestWebDAVGetKeepsDavPathWhenNoRawURL(t *testing.T) {
	ClearShowNameCache()
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:  "alist.local",
		AlistPort:  5244,
		ProxyPort:  5344,
		AlistHttps: false,
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

	hitURL := ""
	p.httpClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hitURL = req.URL.String()
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

	if !strings.HasPrefix(hitURL, "http://alist.local:5244/dav/enc/") || strings.Contains(hitURL, "/d/enc/") {
		t.Fatalf("hitURL=%q", hitURL)
	}
}
