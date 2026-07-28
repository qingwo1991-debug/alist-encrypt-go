package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestParseSingleRangeRFC7233(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		size     int64
		start    int64
		end      int64
		hasRange bool
	}{
		{name: "absent", size: 1000},
		{name: "bounded", header: "bytes=100-199", size: 1000, start: 100, end: 199, hasRange: true},
		{name: "open ended", header: "bytes=900-", size: 1000, start: 900, end: 999, hasRange: true},
		{name: "suffix", header: "bytes=-100", size: 1000, start: 900, end: 999, hasRange: true},
		{name: "suffix larger than representation", header: "bytes=-2000", size: 1000, start: 0, end: 999, hasRange: true},
		{name: "end is clamped", header: "bytes=900-2000", size: 1000, start: 900, end: 999, hasRange: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, hasRange, err := parseSingleRange(tt.header, tt.size)
			if err != nil {
				t.Fatalf("parseSingleRange(%q, %d): %v", tt.header, tt.size, err)
			}
			if start != tt.start || end != tt.end || hasRange != tt.hasRange {
				t.Fatalf("parseSingleRange(%q, %d)=(%d,%d,%v), want (%d,%d,%v)",
					tt.header, tt.size, start, end, hasRange, tt.start, tt.end, tt.hasRange)
			}
		})
	}

	invalid := []string{
		"items=0-1",
		"bytes=",
		"bytes=-",
		"bytes=-0",
		"bytes=abc-def",
		"bytes=100-99",
		"bytes=1000-",
		"bytes=0-1,4-5",
		"bytes=0-1-2",
	}
	for _, header := range invalid {
		t.Run("invalid_"+header, func(t *testing.T) {
			if _, _, _, err := parseSingleRange(header, 1000); err == nil {
				t.Fatalf("parseSingleRange(%q) unexpectedly succeeded", header)
			}
		})
	}
}

func TestParseContentRangeReturnsCompleteInterval(t *testing.T) {
	parsed, ok := parseContentRange("bytes 1056-1567/4128")
	if !ok {
		t.Fatal("valid Content-Range was rejected")
	}
	if parsed.Start != 1056 || parsed.End != 1567 || parsed.Total != 4128 || !parsed.TotalKnown {
		t.Fatalf("parsed Content-Range=%+v", parsed)
	}
	if _, ok := parseContentRange("bytes 1056-4128/4128"); ok {
		t.Fatal("Content-Range ending at total size was accepted")
	}
}

func TestPlayV2RedirectRejectsInvalidOrUnsupportedRanges(t *testing.T) {
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort:         5344,
		PlayFirstFallback: true,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	upstreamCalls := 0
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": []string{"1000"}},
			Body:       io.NopCloser(bytes.NewReader(make([]byte, 1000))),
			Request:    req,
		}, nil
	})}

	invalid := []string{
		"bytes=-0",
		"bytes=1000-",
		"bytes=100-99",
		"bytes=0-1,4-5",
		"items=0-1",
	}
	for i, rangeHeader := range invalid {
		t.Run(rangeHeader, func(t *testing.T) {
			key := "invalid-range-" + strconv.Itoa(i)
			p.storeRedirectCache(key, &RedirectInfo{
				RedirectURL: "http://upstream.local/encrypted",
				PasswdInfo: &EncryptPath{
					Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true,
				},
				FileSize:    1000,
				OriginalURL: "/enc/demo.mp4",
			})

			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
			req.Header.Set("Range", rangeHeader)
			rr := httptest.NewRecorder()
			newPlayOrchestrator(p).ServeRedirect(rr, req)

			if rr.Code != http.StatusRequestedRangeNotSatisfiable {
				t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("Content-Range"); got != "bytes */1000" {
				t.Fatalf("content-range=%q", got)
			}
		})
	}
	if upstreamCalls != 0 {
		t.Fatalf("invalid ranges reached upstream %d times", upstreamCalls)
	}
}

func TestPlayV2RedirectSuffixRange(t *testing.T) {
	password := "123456"
	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("S"), int(fileSize))
	flow, err := NewFlowEncryptor(password, EncTypeAESCTR, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	encrypted, err := flow.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	var ranges []string
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rangeHeader := req.Header.Get("Range")
		ranges = append(ranges, rangeHeader)
		switch rangeHeader {
		case "bytes=0-31":
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				Header: http.Header{
					"Content-Range":  []string{"bytes 0-31/4096"},
					"Content-Length": []string{"32"},
				},
				Body: io.NopCloser(bytes.NewReader(encrypted[:32])), Request: req,
			}, nil
		case "bytes=-64":
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				Header: http.Header{
					"Content-Range":  []string{"bytes 4032-4095/4096"},
					"Content-Length": []string{"64"},
				},
				Body: io.NopCloser(bytes.NewReader(encrypted[4032:])), Request: req,
			}, nil
		default:
			t.Fatalf("unexpected range header %q", rangeHeader)
			return nil, nil
		}
	})}

	key := "suffix-range"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: "http://upstream.local/suffix",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:    fileSize,
		OriginalURL: "/enc/demo.mp4",
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=-64")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%q ranges=%v", rr.Code, rr.Body.String(), ranges)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 4032-4095/4096" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain[4032:]) {
		t.Fatalf("suffix body mismatch: got=%d want=64", len(got))
	}
}

func TestPlayV2RedirectV2SuffixLargerThanPlainSizeExcludesHeader(t *testing.T) {
	password := "123456"
	fileSize := int64(128)
	plain := bytes.Repeat([]byte("V"), int(fileSize))
	contentEnc, err := NewLatestContentEncryptor(password, string(EncTypeAESCTR), fileSize)
	if err != nil {
		t.Fatalf("new latest content encryptor: %v", err)
	}
	reader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Range"); got != "bytes=32-159" {
			t.Fatalf("upstream range=%q, want payload-only ciphertext range", got)
		}
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header: http.Header{
				"Content-Range":  []string{"bytes 32-159/160"},
				"Content-Length": []string{"128"},
			},
			Body: io.NopCloser(bytes.NewReader(ciphertext[32:])), Request: req,
		}, nil
	})}

	key := "v2-large-suffix"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: "http://upstream.local/v2-suffix",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:       fileSize,
		CiphertextSize: contentEnc.Meta.CiphertextSize,
		ContentVersion: ContentVersionV2,
		HeaderLen:      contentEnc.Meta.HeaderLen,
		NonceField:     cloneNonceField(contentEnc.Meta.NonceField),
		OriginalURL:    "/enc/demo.mp4",
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=-256")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-127/128" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain) {
		t.Fatalf("body mismatch: got=%d want=%d", len(got), len(plain))
	}
}

func TestPlayV2FullStrategyHonorsBoundedV2Range(t *testing.T) {
	password := "123456"
	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("F"), int(fileSize))
	contentEnc, err := NewLatestContentEncryptor(password, string(EncTypeAESCTR), fileSize)
	if err != nil {
		t.Fatalf("new latest content encryptor: %v", err)
	}
	reader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("Range"); got != "" {
			t.Fatalf("full strategy sent range %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": []string{strconv.Itoa(len(ciphertext))}},
			Body:       io.NopCloser(bytes.NewReader(ciphertext)),
			Request:    req,
		}, nil
	})}

	info := &RedirectInfo{
		RedirectURL: "http://upstream.local/v2-full",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:       fileSize,
		CiphertextSize: contentEnc.Meta.CiphertextSize,
		ContentVersion: ContentVersionV2,
		HeaderLen:      contentEnc.Meta.HeaderLen,
		NonceField:     cloneNonceField(contentEnc.Meta.NonceField),
		OriginalURL:    "/enc/demo.mp4",
	}
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/full?decode=1", nil)
	req.Header.Set("Range", "bytes=100-199")
	rr := httptest.NewRecorder()
	outcome := newPlayOrchestrator(p).proxyDownloadDecryptWithStrategy(rr, req, "", info, fileSize, StreamStrategyFull)

	if outcome == nil || outcome.Err != nil {
		t.Fatalf("outcome=%+v", outcome)
	}
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 100-199/4096" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Header().Get("Content-Length"); got != "100" {
		t.Fatalf("content-length=%q", got)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain[100:200]) {
		t.Fatalf("bounded body mismatch: got=%d want=100", len(got))
	}
}

func TestPlayV2DecodeDoesNotPassthroughWhenSizeUnknown(t *testing.T) {
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort:         5344,
		PlayFirstFallback: true,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	key := "unknown-size"
	p.storeRedirectCache(key, &RedirectInfo{
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true,
		},
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestPlayV2DecodeRangeFailureDoesNotPassthroughCiphertext(t *testing.T) {
	password := "123456"
	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("R"), int(fileSize))
	flow, err := NewFlowEncryptor(password, EncTypeAESCTR, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	ciphertext, err := flow.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort:         5344,
		PlayFirstFallback: true,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	rangeCalls := 0
	fullCalls := 0
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Range") == "bytes=100-199" {
			rangeCalls++
		} else if req.Header.Get("Range") == "" {
			fullCalls++
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Length": []string{strconv.Itoa(len(ciphertext))}},
			Body:       io.NopCloser(bytes.NewReader(ciphertext)),
			Request:    req,
		}, nil
	})}

	key := "range-failure"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: "http://upstream.local/no-range",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: password, EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:       fileSize,
		CiphertextSize: fileSize,
		ContentVersion: ContentVersionV1,
		OriginalURL:    "/enc/demo.mp4",
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=100-199")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body_len=%d", rr.Code, rr.Body.Len())
	}
	if rangeCalls != 1 || fullCalls != 1 {
		t.Fatalf("upstream calls: range=%d full=%d, want one Range attempt plus one chunked fallback", rangeCalls, fullCalls)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain[100:200]) {
		t.Fatalf("fallback body mismatch: got=%d want=%d", len(got), len(plain[100:200]))
	}
	if bytes.Equal(rr.Body.Bytes(), ciphertext) {
		t.Fatal("encrypted ciphertext was returned to a decode request")
	}
}

func TestPlayV2ResolveAndStream(t *testing.T) {
	password := "123456"
	encType := EncTypeAESCTR
	plainPath := "/enc/demo-video.mp4"
	plainContent := []byte("play-v2 stream payload")
	fileSize := int64(len(plainContent))

	flow, err := NewFlowEncryptor(password, encType, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	encryptedContent, err := flow.Encrypt(plainContent)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}
	encryptedName := ConvertRealName(password, encType, plainPath)
	encryptedPath := "/enc/" + encryptedName

	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/fs/get":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["path"] != encryptedPath {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":404,"message":"object not found"}`))
				return
			}
			resp := map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"name":    encryptedName,
					"size":    fileSize,
					"raw_url": upstream.URL + "/d/enc/" + encryptedName,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		case "/d/enc/" + encryptedName:
			w.Header().Set("Content-Type", "video/mp4")
			w.Header().Set("Content-Length", strconv.Itoa(len(encryptedContent)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(encryptedContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream url: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())
	p, err := NewProxyServer(&ProxyConfig{
		AlistHost:  u.Hostname(),
		AlistPort:  port,
		ProxyPort:  5344,
		AlistHttps: false,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  encType,
				EncName:  true,
				Enable:   true,
			},
		},
		ProbeOnDownload: true,
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	resolveBody := []byte(`{"path":"/enc/demo-video.mp4"}`)
	resolveReq := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/play/resolve", bytes.NewReader(resolveBody))
	resolveReq.Header.Set("Content-Type", "application/json")
	resolveResp := httptest.NewRecorder()
	p.handlePlayResolve(resolveResp, resolveReq)
	if resolveResp.Code != http.StatusOK {
		t.Fatalf("resolve status=%d body=%s", resolveResp.Code, resolveResp.Body.String())
	}

	var resolvePayload map[string]interface{}
	if err := json.Unmarshal(resolveResp.Body.Bytes(), &resolvePayload); err != nil {
		t.Fatalf("unmarshal resolve payload: %v", err)
	}
	data, _ := resolvePayload["data"].(map[string]interface{})
	rawURL, _ := data["raw_url"].(string)
	playToken, _ := data["play_token"].(string)
	if !strings.Contains(rawURL, "/api/play/stream/") || strings.TrimSpace(playToken) == "" {
		t.Fatalf("unexpected resolve payload: %s", resolveResp.Body.String())
	}

	streamURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse stream url: %v", err)
	}
	streamReq := httptest.NewRequest(http.MethodGet, streamURL.String(), nil)
	streamResp := httptest.NewRecorder()
	p.handlePlayStream(streamResp, streamReq)
	if streamResp.Code != http.StatusOK {
		t.Fatalf("stream status=%d body=%s", streamResp.Code, streamResp.Body.String())
	}
	if got := streamResp.Body.Bytes(); string(got) != string(plainContent) {
		t.Fatalf("stream mismatch: got=%q want=%q", string(got), string(plainContent))
	}
}

func TestPlayV2RedirectDecodeDisabledFallsBackToRawUpstream4xx(t *testing.T) {
	password := "123456"
	encType := EncTypeAESCTR
	redirectURL := "http://upstream.local/missing"

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  encType,
				EncName:  true,
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

	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.URL.String() != redirectURL {
				t.Fatalf("unexpected redirect url: %s", req.URL.String())
			}
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
				Request:    req,
			}, nil
		}),
	}

	key := "redirect-key"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: redirectURL,
		PasswdInfo: &EncryptPath{
			Path:     "/enc/*",
			Password: password,
			EncType:  encType,
			EncName:  true,
			Enable:   true,
		},
		FileSize:    1024,
		OriginalURL: "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=0", nil)
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "unauthorized") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}

func TestRefreshRedirectInfoPreservesV2PlainSize(t *testing.T) {
	const (
		displayPath    = "/enc/demo.mp4"
		plainSize      = int64(4096)
		headerLen      = int64(32)
		ciphertextSize = plainSize + headerLen
		expiredURL     = "http://media.local/expired-signed-url"
		freshURL       = "http://media.local/fresh-signed-url"
	)
	plain := bytes.Repeat([]byte{0x31}, int(plainSize))
	plain[len(plain)-1] = 0x7f
	contentEnc, err := NewLatestContentEncryptor("123456", string(EncTypeAESCTR), plainSize)
	if err != nil {
		t.Fatalf("new latest content encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if int64(len(ciphertext)) != ciphertextSize {
		t.Fatalf("ciphertext size=%d, want %d", len(ciphertext), ciphertextSize)
	}

	p, err := NewProxyServer(&ProxyConfig{
		AlistHost: "upstream.local",
		AlistPort: 80,
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()
	p.mutex.Lock()
	p.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var response map[string]interface{}
		switch r.URL.Path {
		case "/api/fs/get":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode fs/get request: %v", err)
			}
			if got := body["path"]; got != displayPath {
				t.Fatalf("fs/get path=%q, want %q", got, displayPath)
			}
			response = map[string]interface{}{
				"code":    200,
				"message": "success",
				"data": map[string]interface{}{
					"name":    "demo.mp4",
					"size":    ciphertextSize,
					"raw_url": freshURL,
				},
			}
		case "/api/admin/storage/list":
			response = map[string]interface{}{
				"code": 200,
				"data": map[string]interface{}{"content": []interface{}{}},
			}
		default:
			t.Fatalf("unexpected upstream path=%q", r.URL.Path)
		}
		payload, err := json.Marshal(response)
		if err != nil {
			t.Fatalf("marshal fs/get response: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Request:    r,
		}, nil
	})}
	p.mutex.Unlock()

	nonce := cloneNonceField(contentEnc.Meta.NonceField)
	p.storeFileCache(displayPath, &FileInfo{
		Name:           "demo.mp4",
		Size:           plainSize,
		CiphertextSize: ciphertextSize,
		ContentVersion: ContentVersionV2,
		HeaderLen:      headerLen,
		NonceField:     nonce,
		Path:           displayPath,
		RawURL:         expiredURL,
	})

	const redirectKey = "refresh-v2-size"
	original := &RedirectInfo{
		RedirectURL:    expiredURL,
		PasswdInfo:     &EncryptPath{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		FileSize:       plainSize,
		CiphertextSize: ciphertextSize,
		ContentVersion: ContentVersionV2,
		HeaderLen:      headerLen,
		NonceField:     nonce,
		OriginalURL:    displayPath,
	}
	refreshed, ok := p.refreshRedirectInfo(context.Background(), redirectKey, nil, original)
	if !ok {
		t.Fatal("refreshRedirectInfo failed")
	}
	if got := refreshed.RedirectURL; got != freshURL {
		t.Fatalf("redirect url=%q", got)
	}
	if got := refreshed.FileSize; got != plainSize {
		t.Fatalf("plain size=%d, want %d", got, plainSize)
	}
	if got := refreshed.CiphertextSize; got != ciphertextSize {
		t.Fatalf("ciphertext size=%d, want %d", got, ciphertextSize)
	}
	if got := original.FileSize; got != plainSize {
		t.Fatalf("original redirect metadata was mutated: size=%d", got)
	}
	cached, ok := p.loadRedirectCache(redirectKey)
	if !ok {
		t.Fatal("refreshed redirect was not cached")
	}
	if cached.FileSize != plainSize || cached.CiphertextSize != ciphertextSize {
		t.Fatalf("cached sizes=(%d,%d), want (%d,%d)", cached.FileSize, cached.CiphertextSize, plainSize, ciphertextSize)
	}

	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if got := req.URL.String(); got != freshURL {
			t.Fatalf("stream URL=%q, want refreshed URL", got)
		}
		if got := req.Header.Get("Range"); got != "bytes=4127-4127" {
			t.Fatalf("tail upstream Range=%q", got)
		}
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header: http.Header{
				"Content-Type":   []string{"video/mp4"},
				"Content-Length": []string{"1"},
				"Content-Range":  []string{"bytes 4127-4127/4128"},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext[len(ciphertext)-1:])),
			Request: req,
		}, nil
	})}
	tailReq := httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/"+redirectKey+"?decode=1", nil)
	tailReq.Header.Set("Range", "bytes=4095-4095")
	tailRec := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(tailRec, tailReq)
	if tailRec.Code != http.StatusPartialContent {
		t.Fatalf("tail status=%d body=%q", tailRec.Code, tailRec.Body.String())
	}
	if got := tailRec.Header().Get("Content-Range"); got != "bytes 4095-4095/4096" {
		t.Fatalf("tail Content-Range=%q", got)
	}
	if got := tailRec.Body.Bytes(); !bytes.Equal(got, plain[len(plain)-1:]) {
		t.Fatalf("tail body=%x, want %x", got, plain[len(plain)-1:])
	}
}

func TestPlayV2RejectsInvalidUpstreamContentRangeCoverage(t *testing.T) {
	const (
		plainSize   = int64(4096)
		redirectURL = "http://upstream.local/v2-range-mismatch"
		displayPath = "/enc/demo.mp4"
	)
	tests := []struct {
		name          string
		contentRange  string
		contentLength int
	}{
		{name: "wrong start", contentRange: "bytes 0-511/4128", contentLength: 512},
		{name: "same start but short end", contentRange: "bytes 1056-1500/4128", contentLength: 445},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProxyServer(&ProxyConfig{
				ProxyPort:              5344,
				EnableRangeCompatCache: true,
				RangeCompatMinFailures: 1,
				EncryptPaths: []*EncryptPath{
					{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
				},
			})
			if err != nil {
				t.Fatalf("new proxy server: %v", err)
			}
			defer p.stopRangeProbeLoop()
			defer p.stopCacheCleanup()
			defer p.closeLocalStore()
			p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Get("Range"); got != "bytes=1056-1567" {
					t.Fatalf("upstream Range=%q, want shifted V2 range", got)
				}
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Type":   []string{"video/mp4"},
						"Content-Length": []string{strconv.Itoa(tt.contentLength)},
						"Content-Range":  []string{tt.contentRange},
					},
					Body:    io.NopCloser(bytes.NewReader(make([]byte, tt.contentLength))),
					Request: req,
				}, nil
			})}

			info := &RedirectInfo{
				RedirectURL: redirectURL,
				PasswdInfo: &EncryptPath{
					Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true,
				},
				FileSize:       plainSize,
				CiphertextSize: plainSize + ContentHeaderSize(),
				ContentVersion: ContentVersionV2,
				HeaderLen:      ContentHeaderSize(),
				NonceField:     bytes.Repeat([]byte{0x4d}, 16),
				OriginalURL:    displayPath,
			}
			req := httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/mismatch?decode=1", nil)
			req.Header.Set("Range", "bytes=1024-1535")
			rec := httptest.NewRecorder()
			outcome := newPlayOrchestrator(p).proxyDownloadDecryptWithStrategy(
				rec, req, "", info, plainSize, StreamStrategyRange,
			)

			if outcome.Err == nil || outcome.FailureReason != "range_unsupported" || !outcome.Retryable {
				t.Fatalf("outcome=%+v, want retryable range rejection", outcome)
			}
			if outcome.ResponseStarted {
				t.Fatal("invalid upstream range must be rejected before response starts")
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("invalid range leaked %d response bytes", rec.Body.Len())
			}
			if !p.shouldSkipRange(redirectURL, displayPath) {
				t.Fatal("invalid Content-Range was learned as compatible")
			}
		})
	}
}

func TestPlayV2NonFirstRangeFallsBackToChunkedBeforeResponseStarts(t *testing.T) {
	const fileSize = int64(16)
	plain := []byte("0123456789abcdef")
	flow, err := NewFlowEncryptor("123456", EncTypeAESCTR, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	ciphertext, err := flow.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort:         5344,
		RangeSkipMaxBytes: fileSize,
		PlayFirstFallback: false,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	var upstreamRanges []string
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamRanges = append(upstreamRanges, req.Header.Get("Range"))
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"video/mp4"},
				"Content-Length": []string{strconv.FormatInt(fileSize, 10)},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext)),
			Request: req,
		}, nil
	})}

	const key = "non-first-range-fallback"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: "http://upstream.local/range-ignored",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:       fileSize,
		CiphertextSize: fileSize,
		ContentVersion: ContentVersionV1,
		OriginalURL:    "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=8-11")
	rec := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 8-11/16" {
		t.Fatalf("Content-Range=%q", got)
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, plain[8:12]) {
		t.Fatalf("body=%q, want %q", got, plain[8:12])
	}
	if len(upstreamRanges) != 2 || upstreamRanges[0] != "bytes=8-11" || upstreamRanges[1] != "" {
		t.Fatalf("upstream ranges=%q, want Range attempt then chunked fallback", upstreamRanges)
	}
}

func TestPlayV2ChunkedFallbackRefusesOversizedDiscard(t *testing.T) {
	const fileSize = int64(16)
	plain := []byte("0123456789abcdef")
	flow, err := NewFlowEncryptor("123456", EncTypeAESCTR, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	ciphertext, err := flow.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort:         5344,
		RangeSkipMaxBytes: 4,
		PlayFirstFallback: false,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	upstreamCalls := 0
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"video/mp4"},
				"Content-Length": []string{strconv.FormatInt(fileSize, 10)},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext)),
			Request: req,
		}, nil
	})}

	const key = "oversized-chunked-fallback"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: "http://upstream.local/range-ignored",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:       fileSize,
		CiphertextSize: fileSize,
		ContentVersion: ContentVersionV1,
		OriginalURL:    "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=8-11")
	rec := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if upstreamCalls != 2 {
		t.Fatalf("upstream calls=%d, want one Range attempt plus one bounded chunked attempt and no full download", upstreamCalls)
	}
	if !strings.Contains(rec.Body.String(), "chunked seek offset too large") {
		t.Fatalf("unexpected error body=%q", rec.Body.String())
	}
}

func TestPlayV2DecodeDisabledV2RangePassesCiphertextThroughExactly(t *testing.T) {
	const (
		plainSize      = int64(64)
		headerLen      = int64(32)
		ciphertextSize = plainSize + headerLen
	)
	ciphertext := make([]byte, ciphertextSize)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}

	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true},
		},
	})
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}
	defer p.stopRangeProbeLoop()
	defer p.stopCacheCleanup()
	defer p.closeLocalStore()

	var upstreamMethods []string
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		upstreamMethods = append(upstreamMethods, req.Method)
		if got := req.Header.Get("Range"); got != "bytes=70-79" {
			t.Fatalf("upstream Range=%q, want unshifted ciphertext range", got)
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Fatalf("client Authorization leaked upstream: %q", got)
		}
		if got := req.Header.Get("Referer"); got != "" {
			t.Fatalf("client Referer leaked upstream: %q", got)
		}
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header: http.Header{
				"Accept-Ranges":  []string{"bytes"},
				"Content-Length": []string{"10"},
				"Content-Range":  []string{"bytes 70-79/96"},
				"Content-Type":   []string{"application/octet-stream"},
				"ETag":           []string{`"cipher-etag"`},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext[70:80])),
			Request: req,
		}, nil
	})}

	const key = "raw-v2-range"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: "http://upstream.local/v2-ciphertext",
		PasswdInfo: &EncryptPath{
			Path: "/enc/*", Password: "123456", EncType: EncTypeAESCTR, Enable: true,
		},
		FileSize:       plainSize,
		CiphertextSize: ciphertextSize,
		ContentVersion: ContentVersionV2,
		HeaderLen:      headerLen,
		NonceField:     bytes.Repeat([]byte{0x4d}, 16),
		OriginalURL:    "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/"+key+"?decode=0", nil)
	req.Header.Set("Range", "bytes=70-79")
	req.Header.Set("Authorization", "Bearer must-not-leak")
	req.Header.Set("Referer", "https://private.example/player")
	rec := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rec, req)

	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 70-79/96" {
		t.Fatalf("Content-Range=%q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "10" {
		t.Fatalf("Content-Length=%q", got)
	}
	if got := rec.Header().Get("ETag"); got != `"cipher-etag"` {
		t.Fatalf("ETag=%q", got)
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, ciphertext[70:80]) {
		t.Fatalf("ciphertext body=%x, want %x", got, ciphertext[70:80])
	}

	headReq := httptest.NewRequest(http.MethodHead, "http://proxy.local/redirect/"+key+"?decode=0", nil)
	headReq.Header.Set("Range", "bytes=70-79")
	headRec := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(headRec, headReq)
	if headRec.Code != http.StatusPartialContent {
		t.Fatalf("HEAD status=%d", headRec.Code)
	}
	if got := headRec.Header().Get("Content-Range"); got != "bytes 70-79/96" {
		t.Fatalf("HEAD Content-Range=%q", got)
	}
	if got := headRec.Header().Get("Content-Length"); got != "10" {
		t.Fatalf("HEAD Content-Length=%q", got)
	}
	if headRec.Body.Len() != 0 {
		t.Fatalf("HEAD unexpectedly returned %d body bytes", headRec.Body.Len())
	}
	if len(upstreamMethods) != 2 || upstreamMethods[0] != http.MethodGet || upstreamMethods[1] != http.MethodHead {
		t.Fatalf("upstream methods=%v, want GET then HEAD passthrough", upstreamMethods)
	}
}

func TestPlayV2RedirectRangePreserves206Headers(t *testing.T) {
	password := "123456"
	encType := EncTypeAESCTR
	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("A"), int(fileSize))
	flow, err := NewFlowEncryptor(password, encType, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	encrypted, err := flow.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	redirectURL := "http://upstream.local/range"
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  encType,
				EncName:  true,
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

	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				Header: http.Header{
					"Content-Range":  []string{"bytes 0-4095/4096"},
					"Content-Length": []string{"4096"},
					"Content-Type":   []string{"video/mp4"},
				},
				Body:    io.NopCloser(bytes.NewReader(encrypted)),
				Request: req,
			}, nil
		}),
	}

	key := "range-key"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: redirectURL,
		PasswdInfo: &EncryptPath{
			Path:     "/enc/*",
			Password: password,
			EncType:  encType,
			EncName:  true,
			Enable:   true,
		},
		FileSize:    fileSize,
		OriginalURL: "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-4095/4096" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Header().Get("Content-Length"); got != "4096" {
		t.Fatalf("content-length=%q", got)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain) {
		t.Fatalf("decrypted body mismatch: got=%d", len(got))
	}
}

func TestPlayV2RedirectRangePreserves206HeadersForV2(t *testing.T) {
	password := "123456"
	fileSize := int64(4096)
	plain := bytes.Repeat([]byte("C"), int(fileSize))
	contentEnc, err := NewLatestContentEncryptor(password, string(EncTypeAESCTR), fileSize)
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	reader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	redirectURL := "http://upstream.local/range-v2"
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  EncTypeAESCTR,
				EncName:  true,
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

	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Range") == "bytes=0-31" {
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Range":  []string{"bytes 0-31/4128"},
						"Content-Length": []string{"32"},
						"Content-Type":   []string{"application/octet-stream"},
					},
					Body:    io.NopCloser(bytes.NewReader(ciphertext[:32])),
					Request: req,
				}, nil
			}
			if req.Header.Get("Range") == "bytes=32-" {
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Range":  []string{"bytes 32-4127/4128"},
						"Content-Length": []string{"4096"},
						"Content-Type":   []string{"video/mp4"},
					},
					Body:    io.NopCloser(bytes.NewReader(ciphertext[32:])),
					Request: req,
				}, nil
			}
			t.Fatalf("unexpected range header: %q", req.Header.Get("Range"))
			return nil, nil
		}),
	}

	key := "range-key-v2"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: redirectURL,
		PasswdInfo: &EncryptPath{
			Path:     "/enc/*",
			Password: password,
			EncType:  EncTypeAESCTR,
			EncName:  true,
			Enable:   true,
		},
		FileSize:    int64(len(ciphertext)),
		OriginalURL: "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-4095/4096" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Header().Get("Content-Length"); got != "4096" {
		t.Fatalf("content-length=%q", got)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain) {
		t.Fatalf("decrypted body mismatch: got=%d", len(got))
	}
}

func TestPlayV2RedirectIgnoresV1CacheForEncryptedV2Path(t *testing.T) {
	password := "123456"
	fileSize := int64(2048)
	plain := bytes.Repeat([]byte("D"), int(fileSize))
	contentEnc, err := NewLatestContentEncryptor(password, string(EncTypeAESCTR), fileSize)
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	reader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	redirectURL := "http://upstream.local/v2-with-stale-v1-cache"
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  EncTypeAESCTR,
				EncName:  true,
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

	var ranges []string
	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			ranges = append(ranges, req.Header.Get("Range"))
			switch req.Header.Get("Range") {
			case "bytes=0-31":
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Range":  []string{"bytes 0-31/2080"},
						"Content-Length": []string{"32"},
					},
					Body:    io.NopCloser(bytes.NewReader(ciphertext[:32])),
					Request: req,
				}, nil
			case "bytes=32-47":
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Range":  []string{"bytes 32-47/2080"},
						"Content-Length": []string{"16"},
					},
					Body:    io.NopCloser(bytes.NewReader(ciphertext[32:48])),
					Request: req,
				}, nil
			default:
				t.Fatalf("unexpected range header: %q", req.Header.Get("Range"))
			}
			return nil, nil
		}),
	}

	p.storeFileCache("/enc/demo.mp4", &FileInfo{
		Name:           "demo.mp4",
		Size:           int64(len(ciphertext)),
		ContentVersion: ContentVersionV1,
		IsDir:          false,
		Path:           "/enc/demo.mp4",
	})

	key := "stale-v1-cache-key"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: redirectURL,
		PasswdInfo: &EncryptPath{
			Path:     "/enc/*",
			Password: password,
			EncType:  EncTypeAESCTR,
			EncName:  true,
			Enable:   true,
		},
		FileSize:      int64(len(ciphertext)),
		OriginalURL:   "/enc/demo.mp4",
		EncryptedPath: "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-15")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%s ranges=%v", rr.Code, rr.Body.String(), ranges)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-15/2048" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Body.Bytes(); !bytes.Equal(got, plain[:16]) {
		t.Fatalf("decrypted body mismatch: got=%q", string(got))
	}
	if len(ranges) < 2 || ranges[0] != "bytes=0-31" || ranges[1] != "bytes=32-47" {
		t.Fatalf("expected v2 probe then shifted range, got %v", ranges)
	}
}

func TestPlayV2RedirectPreservesOpenEndedRange(t *testing.T) {
	password := "123456"
	fileSize := int64(3 * 1024 * 1024)
	plain := bytes.Repeat([]byte("E"), int(fileSize))
	contentEnc, err := NewLatestContentEncryptor(password, string(EncTypeAESCTR), fileSize)
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	reader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	redirectURL := "http://upstream.local/large-v2"
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  EncTypeAESCTR,
				EncName:  true,
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

	expectedPlainLen := fileSize
	expectedUpstreamRange := "bytes=32-"
	var ranges []string
	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			ranges = append(ranges, req.Header.Get("Range"))
			switch req.Header.Get("Range") {
			case "bytes=0-31":
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Range":  []string{"bytes 0-31/" + strconv.Itoa(len(ciphertext))},
						"Content-Length": []string{"32"},
					},
					Body:    io.NopCloser(bytes.NewReader(ciphertext[:32])),
					Request: req,
				}, nil
			case expectedUpstreamRange:
				end := 32 + expectedPlainLen
				return &http.Response{
					StatusCode: http.StatusPartialContent,
					Header: http.Header{
						"Content-Range":  []string{"bytes 32-" + strconv.FormatInt(end-1, 10) + "/" + strconv.Itoa(len(ciphertext))},
						"Content-Length": []string{strconv.FormatInt(expectedPlainLen, 10)},
					},
					Body:    io.NopCloser(bytes.NewReader(ciphertext[32:int(end)])),
					Request: req,
				}, nil
			default:
				t.Fatalf("unexpected range header: %q", req.Header.Get("Range"))
			}
			return nil, nil
		}),
	}

	key := "large-v2-key"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: redirectURL,
		PasswdInfo: &EncryptPath{
			Path:     "/enc/*",
			Password: password,
			EncType:  EncTypeAESCTR,
			EncName:  true,
			Enable:   true,
		},
		FileSize:    int64(len(ciphertext)),
		OriginalURL: "/enc/large.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body_len=%d ranges=%v", rr.Code, rr.Body.Len(), ranges)
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 0-3145727/3145728" {
		t.Fatalf("content-range=%q", got)
	}
	if got := rr.Header().Get("Content-Length"); got != strconv.FormatInt(expectedPlainLen, 10) {
		t.Fatalf("content-length=%q", got)
	}
	if rr.Body.Len() != int(expectedPlainLen) {
		t.Fatalf("body len=%d", rr.Body.Len())
	}
	if len(ranges) < 2 || ranges[1] != expectedUpstreamRange {
		t.Fatalf("expected open-ended shifted upstream range %q, got %v", expectedUpstreamRange, ranges)
	}
}

func TestPlayV2DoesNotOverwriteStartedResponseOnStreamFailure(t *testing.T) {
	password := "123456"
	encType := EncTypeAESCTR
	fileSize := int64(1024)
	plain := bytes.Repeat([]byte("B"), int(fileSize))
	flow, err := NewFlowEncryptor(password, encType, fileSize)
	if err != nil {
		t.Fatalf("new flow encryptor: %v", err)
	}
	encrypted, err := flow.Encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt payload: %v", err)
	}

	redirectURL := "http://upstream.local/range"
	p, err := NewProxyServer(&ProxyConfig{
		ProxyPort: 5344,
		EncryptPaths: []*EncryptPath{
			{
				Path:     "/enc/*",
				Password: password,
				EncType:  encType,
				EncName:  true,
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

	p.streamClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				Header: http.Header{
					"Content-Range":  []string{"bytes 0-1023/1024"},
					"Content-Length": []string{"1024"},
					"Content-Type":   []string{"video/mp4"},
				},
				Body:    io.NopCloser(bytes.NewReader(encrypted[:128])),
				Request: req,
			}, nil
		}),
	}

	key := "range-key-fail"
	p.storeRedirectCache(key, &RedirectInfo{
		RedirectURL: redirectURL,
		PasswdInfo: &EncryptPath{
			Path:     "/enc/*",
			Password: password,
			EncType:  encType,
			EncName:  true,
			Enable:   true,
		},
		FileSize:    fileSize,
		OriginalURL: "/enc/demo.mp4",
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=0-")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
