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

func TestPlayV2RedirectFallsBackToRawUpstream4xxWhenEnabled(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/redirect/"+key+"?decode=1", nil)
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
