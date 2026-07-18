package encrypt

import (
	"bytes"
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
	p.streamClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Range") == "bytes=100-199" {
			rangeCalls++
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
		FileSize:    fileSize,
		OriginalURL: "/enc/demo.mp4",
	})
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
	req.Header.Set("Range", "bytes=100-199")
	rr := httptest.NewRecorder()
	newPlayOrchestrator(p).ServeRedirect(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body_len=%d", rr.Code, rr.Body.Len())
	}
	if rangeCalls != 1 {
		t.Fatalf("range request reached upstream %d times; raw fallback likely leaked ciphertext", rangeCalls)
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
