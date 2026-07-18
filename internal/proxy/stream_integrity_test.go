package proxy

import (
	"bytes"
	stderrors "errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

type closeTrackingBody struct {
	io.Reader
	closeCount int
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

func (b *closeTrackingBody) Close() error {
	b.closeCount++
	return nil
}

func TestDiscardBytesReturnsUnexpectedEOFOnShortInput(t *testing.T) {
	tests := []struct {
		name      string
		requested int64
		available int
	}{
		{name: "copy-n path", requested: 32, available: 16},
		{name: "pooled buffer path", requested: 8192, available: 4097},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := discardBytes(bytes.NewReader(make([]byte, tt.available)), tt.requested)
			if !stderrors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("error=%v, want io.ErrUnexpectedEOF", err)
			}
		})
	}
}

func TestDecryptStreamTreatsShortUpstreamBodyAsTruncatedWithoutRangeSuccess(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	cfg.AlistServer.EnableRangeCompatCache = true
	sp := NewStreamProxy(cfg)

	const fileSize int64 = 16
	plain := []byte("0123456789abcdef")
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	flow.Encrypt(ciphertext)

	targetURL := "http://upstream.local/file"
	storageKey := "/encrypt"
	compatKey := sp.rangeCompatKey(targetURL, storageKey)
	if err := sp.compatStore.Upsert(compatKey, RangeCompatState{
		ConsecutiveFailures: 1,
		LastReason:          "previous_failure",
	}); err != nil {
		t.Fatalf("seed range compatibility state: %v", err)
	}

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header: http.Header{
				"Content-Type":   []string{"video/mp4"},
				"Content-Length": []string{"10"},
				"Content-Range":  []string{"bytes 0-9/16"},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext[:5])),
			Request: r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/test.bin", nil)
	req.Header.Set("Range", "bytes=0-9")
	result := sp.ProxyDownloadDecryptWithStrategyForStorage(
		httptest.NewRecorder(),
		req,
		targetURL,
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		fileSize,
		StreamStrategyRange,
		storageKey,
	)

	if !stderrors.Is(result.Err, io.ErrUnexpectedEOF) {
		t.Fatalf("error=%v, want io.ErrUnexpectedEOF", result.Err)
	}
	if result.FailureReason != "upstream_truncated" {
		t.Fatalf("failure reason=%q, want upstream_truncated", result.FailureReason)
	}
	if !result.NoLearning {
		t.Fatal("truncated response must not be learned as a successful playback")
	}
	if !result.Retryable {
		t.Fatal("truncated upstream response should allow a fresh retry")
	}
	if result.BytesWritten != 5 || result.ExpectedBytes != 10 {
		t.Fatalf("bytes written/expected=%d/%d, want 5/10", result.BytesWritten, result.ExpectedBytes)
	}

	state, ok, err := sp.compatStore.Get(compatKey)
	if err != nil || !ok {
		t.Fatalf("read range compatibility state: ok=%v err=%v", ok, err)
	}
	if state.ConsecutiveSuccesses != 0 || state.ConsecutiveFailures != 1 {
		t.Fatalf("truncated response changed range success state: %#v", state)
	}
}

func TestV2DecryptRejectsInvalidUpstreamContentRangeCoverage(t *testing.T) {
	const plainSize = int64(4096)
	meta := encryption.ContentMeta{
		EncType:        encryption.EncTypeAESCTR,
		Version:        encryption.ContentVersionV2,
		HeaderLen:      encryption.ContentHeaderSize(),
		PlainSize:      plainSize,
		CiphertextSize: plainSize + encryption.ContentHeaderSize(),
		NonceField:     bytes.Repeat([]byte{0x4d}, 16),
	}
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
			cfg := config.DefaultConfig()
			cfg.AlistServer.EnableSniff = false
			cfg.AlistServer.EnableRangeCompatCache = true
			sp := NewStreamProxy(cfg)
			targetURL := "http://upstream.local/v2-file"
			storageKey := "/encrypt"
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("Range"); got != "bytes=1056-1567" {
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
					Request: r,
				}, nil
			})

			req := httptest.NewRequest(http.MethodGet, "/d/v2-file", nil)
			req.Header.Set("Range", "bytes=1024-1535")
			req = req.WithContext(WithContentMeta(req.Context(), meta))
			rec := httptest.NewRecorder()
			result := sp.ProxyDownloadDecryptWithStrategyForStorage(
				rec,
				req,
				targetURL,
				&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
				plainSize,
				StreamStrategyRange,
				storageKey,
			)

			if result.Err == nil || result.FailureReason != "range_unsupported" || !result.Retryable {
				t.Fatalf("outcome=%+v, want retryable range rejection", result)
			}
			if result.ResponseStarted {
				t.Fatal("invalid upstream range must be rejected before response starts")
			}
			if rec.Body.Len() != 0 {
				t.Fatalf("invalid range leaked %d response bytes", rec.Body.Len())
			}
			state, ok, err := sp.compatStore.Get(sp.rangeCompatKey(targetURL, storageKey))
			if err != nil || !ok {
				t.Fatalf("read range compatibility state: ok=%v err=%v", ok, err)
			}
			if state.ConsecutiveSuccesses != 0 || state.ConsecutiveFailures != 1 || state.LastReason != "range_unsupported" {
				t.Fatalf("unexpected range compatibility state: %#v", state)
			}
		})
	}
}

func TestFollowRedirectDecryptClosesFinalResponseBodyOnEveryReturnPath(t *testing.T) {
	const fileSize int64 = 16
	plain := []byte("0123456789abcdef")
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	flow.Encrypt(ciphertext)

	tests := []struct {
		name       string
		method     string
		statusCode int
		body       []byte
		wantErr    bool
	}{
		{name: "successful get", method: http.MethodGet, statusCode: http.StatusOK, body: ciphertext},
		{name: "head", method: http.MethodHead, statusCode: http.StatusOK},
		{name: "upstream error", method: http.MethodGet, statusCode: http.StatusNotFound, body: []byte("not found"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AlistServer.EnableSniff = false
			sp := NewStreamProxy(cfg)
			finalBody := &closeTrackingBody{Reader: bytes.NewReader(tt.body)}
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("Authorization"); got != "Basic test" {
					t.Fatalf("same-host redirect authorization=%q, want preserved", got)
				}
				if got := r.Header.Get("Cookie"); got != "sid=1" {
					t.Fatalf("same-host redirect cookie=%q, want preserved", got)
				}
				return &http.Response{
					StatusCode: tt.statusCode,
					Header: http.Header{
						"Content-Type":   []string{"video/mp4"},
						"Content-Length": []string{strconv.Itoa(len(tt.body))},
					},
					Body:    finalBody,
					Request: r,
				}, nil
			})

			upstreamURL, err := url.Parse("http://upstream.local/original")
			if err != nil {
				t.Fatalf("parse upstream URL: %v", err)
			}
			initialResp := &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"/final"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    &http.Request{URL: upstreamURL},
			}
			req := httptest.NewRequest(tt.method, "http://proxy.local/d/test.bin", nil)
			req.Header.Set("Authorization", "Basic test")
			req.Header.Set("Cookie", "sid=1")
			result := sp.followRedirectDecrypt(
				httptest.NewRecorder(),
				req,
				initialResp,
				&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
				fileSize,
				encryption.LegacyContentMeta(encryption.EncTypeAESCTR, fileSize),
				"",
				StreamStrategyFull,
				upstreamURL.String(),
				"/encrypt",
			)

			if (result.Err != nil) != tt.wantErr {
				t.Fatalf("error=%v, wantErr=%v", result.Err, tt.wantErr)
			}
			if finalBody.closeCount != 1 {
				t.Fatalf("final response body close count=%d, want 1", finalBody.closeCount)
			}
		})
	}
}

func TestSanitizeRedirectHeadersStripsCredentialsAcrossOrigins(t *testing.T) {
	originalURL, err := url.Parse("http://upstream.local/original")
	if err != nil {
		t.Fatalf("parse original URL: %v", err)
	}

	for _, targetURL := range []string{
		"https://cdn.example/final",
		"https://upstream.local/final",
	} {
		t.Run(targetURL, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, targetURL, nil)
			req.Header.Set("Authorization", "Basic test")
			req.Header.Set("Cookie", "sid=1")
			req.Header.Set("Depth", "1")

			sanitizeRedirectHeaders(req, originalURL, req.URL.String())

			if got := req.Header.Get("Authorization"); got != "" {
				t.Fatalf("cross-origin authorization=%q, want stripped", got)
			}
			if got := req.Header.Get("Cookie"); got != "" {
				t.Fatalf("cross-origin cookie=%q, want stripped", got)
			}
			if got := req.Header.Get("Depth"); got != "" {
				t.Fatalf("redirected WebDAV Depth=%q, want stripped", got)
			}
		})
	}
}

func TestFullStrategyHonorsExactClientRange(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	sp := NewStreamProxy(cfg)

	plain := []byte("0123456789abcdef")
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	flow.Encrypt(ciphertext)

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Range"); got != "" {
			t.Fatalf("full strategy forwarded Range=%q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"application/octet-stream"},
				"Content-Length": []string{strconv.Itoa(len(ciphertext))},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext)),
			Request: r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/file.bin", nil)
	req.Header.Set("Range", "bytes=4-7")
	rec := httptest.NewRecorder()
	result := sp.ProxyDownloadDecryptWithStrategyForStorage(
		rec,
		req,
		"http://upstream.local/file.bin",
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		int64(len(plain)),
		StreamStrategyFull,
		"/encrypt",
	)
	if result.Err != nil {
		t.Fatalf("full range decrypt: %v", result.Err)
	}
	if rec.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want 206", rec.Code)
	}
	if got := rec.Header().Get("Content-Range"); got != "bytes 4-7/16" {
		t.Fatalf("Content-Range=%q", got)
	}
	if got := rec.Header().Get("Content-Length"); got != "4" {
		t.Fatalf("Content-Length=%q", got)
	}
	if got := rec.Body.String(); got != "4567" {
		t.Fatalf("body=%q, want exact requested range", got)
	}
}

func TestRedirectChainDoesNotReintroduceCredentialsAfterCrossOriginHop(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableSniff = false
	sp := NewStreamProxy(cfg)

	plain := []byte("0123456789abcdef")
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	flow.Encrypt(ciphertext)

	call := 0
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		call++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("redirect call %d leaked Authorization=%q", call, got)
		}
		if got := r.Header.Get("Cookie"); got != "" {
			t.Fatalf("redirect call %d leaked Cookie=%q", call, got)
		}
		if call == 1 {
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header:     http.Header{"Location": []string{"/final"}},
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    r,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type":   []string{"application/octet-stream"},
				"Content-Length": []string{strconv.Itoa(len(ciphertext))},
			},
			Body:    io.NopCloser(bytes.NewReader(ciphertext)),
			Request: r,
		}, nil
	})

	upstreamURL, err := url.Parse("http://upstream.local/original")
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	initialResp := &http.Response{
		StatusCode: http.StatusTemporaryRedirect,
		Header:     http.Header{"Location": []string{"https://cdn.example/step-one"}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    &http.Request{URL: upstreamURL},
	}
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/d/file.bin", nil)
	req.Header.Set("Authorization", "Basic secret")
	req.Header.Set("Cookie", "sid=secret")
	result := sp.followRedirectDecrypt(
		httptest.NewRecorder(),
		req,
		initialResp,
		&config.PasswdInfo{Password: "123456", EncType: "aesctr", Enable: true},
		int64(len(plain)),
		encryption.LegacyContentMeta(encryption.EncTypeAESCTR, int64(len(plain))),
		"",
		StreamStrategyFull,
		upstreamURL.String(),
		"/encrypt",
	)
	if result.Err != nil {
		t.Fatalf("redirect decrypt: %v", result.Err)
	}
	if call != 2 {
		t.Fatalf("redirect calls=%d, want 2", call)
	}
}
