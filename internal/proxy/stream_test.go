package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(fn roundTripFunc) *Client {
	return &Client{Client: &http.Client{Transport: fn}}
}

func TestClassifyStreamErrorTimeout(t *testing.T) {
	reason, retryable := classifyStreamError(context.DeadlineExceeded)
	if reason != "timeout" {
		t.Fatalf("expected timeout reason, got %q", reason)
	}
	if retryable {
		t.Fatalf("expected retryable=false for timeout")
	}

	var err net.Error = timeoutErr{}
	reason, retryable = classifyStreamError(err)
	if reason != "timeout" {
		t.Fatalf("expected timeout reason for net.Error, got %q", reason)
	}
	if retryable {
		t.Fatalf("expected retryable=false for net.Error timeout")
	}
}

func TestProxyUploadEncryptUsesStartOffsetForChunkedUpload(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	fileSize := int64(64)
	start := int64(17)
	chunk := []byte("chunk-data-for-offset")

	fullPlain := make([]byte, fileSize)
	copy(fullPlain[start:], chunk)
	fullEncrypted := make([]byte, len(fullPlain))
	copy(fullEncrypted, fullPlain)

	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to create flow enc: %v", err)
	}
	flow.Encrypt(fullEncrypted)
	expectedChunk := fullEncrypted[start : start+int64(len(chunk))]

	var received []byte
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		received = append([]byte(nil), body...)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader(string(chunk)))
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}
	if err := sp.ProxyUploadEncrypt(rr, req, "http://upstream.local/put", passwd, fileSize, start); err != nil {
		t.Fatalf("ProxyUploadEncrypt failed: %v", err)
	}
	if string(received) != string(expectedChunk) {
		t.Fatalf("encrypted chunk mismatch")
	}
}

func TestDecryptRequestForcesIdentityEncoding(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	var acceptEncoding string
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		acceptEncoding = r.Header.Get("Accept-Encoding")
		headers := make(http.Header)
		headers.Set("Content-Length", "16")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     headers,
			Body:       io.NopCloser(strings.NewReader("0123456789abcdef")),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/test.bin", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}
	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.local/file", passwd, 16, StreamStrategyFull, "/")
	if result.Err != nil {
		t.Fatalf("unexpected stream error: %v", result.Err)
	}
	if acceptEncoding != "identity" {
		t.Fatalf("Accept-Encoding=%q, want identity", acceptEncoding)
	}
}

func TestNormalizePlainFileSizeUsesCiphertextTotalForV2(t *testing.T) {
	meta := encryption.ContentMeta{
		EncType:        encryption.EncTypeAESCTR,
		Version:        encryption.ContentVersionV2,
		HeaderLen:      encryption.ContentHeaderSize(),
		CiphertextSize: 1833849240,
	}
	got := normalizePlainFileSize(1833849240, &meta, "bytes 32-1833849239/1833849240")
	want := int64(1833849208)
	if got != want {
		t.Fatalf("plain size mismatch: got=%d want=%d", got, want)
	}
	if meta.PlainSize != want {
		t.Fatalf("meta plain size mismatch: got=%d want=%d", meta.PlainSize, want)
	}
}

func TestDecryptRequestUsesDisplayNameFromContext(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	fileSize := int64(16)
	plain := []byte("0123456789abcdef")
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to create flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		headers := make(http.Header)
		headers.Set("Content-Length", "16")
		headers.Set("Content-Type", "video/mp4")
		headers.Set("Content-Disposition", `attachment; filename="I6O1l9Hp5V+YO0--P.bin"`)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     headers,
			Body:       io.NopCloser(bytes.NewReader(ciphertext)),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/test.bin", nil)
	req = req.WithContext(WithDisplayName(req.Context(), "oceans.mp4"))
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
		EncName:  true,
	}
	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.local/file", passwd, fileSize, StreamStrategyFull, "/")
	if result.Err != nil {
		t.Fatalf("unexpected stream error: %v", result.Err)
	}
	if got := rr.Header().Get("Content-Disposition"); !strings.Contains(got, "oceans.mp4") {
		t.Fatalf("Content-Disposition=%q, want rewritten display name", got)
	}
}

func TestProxyUploadEncryptMultiChunkOffsetsRebuildFullCiphertext(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	fileSize := int64(80)
	firstStart := int64(0)
	firstChunk := []byte("first-segment-plain")
	secondStart := int64(len(firstChunk))
	secondChunk := []byte("second-segment-plain-data")

	fullPlain := make([]byte, fileSize)
	copy(fullPlain[firstStart:], firstChunk)
	copy(fullPlain[secondStart:], secondChunk)

	received := map[int][]byte{}
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		parsed, _ := url.Parse(r.URL.String())
		part := parsed.Query().Get("part")
		receivedPart := 1
		if part == "2" {
			receivedPart = 2
		}
		received[receivedPart] = append([]byte(nil), body...)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    r,
		}, nil
	})

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	req1 := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader(string(firstChunk)))
	rr1 := httptest.NewRecorder()
	if err := sp.ProxyUploadEncrypt(rr1, req1, "http://upstream.local/put?part=1", passwd, fileSize, firstStart); err != nil {
		t.Fatalf("first chunk upload failed: %v", err)
	}

	req2 := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader(string(secondChunk)))
	rr2 := httptest.NewRecorder()
	if err := sp.ProxyUploadEncrypt(rr2, req2, "http://upstream.local/put?part=2", passwd, fileSize, secondStart); err != nil {
		t.Fatalf("second chunk upload failed: %v", err)
	}

	meta, ok, err := encryption.ParseContentHeader(encryption.EncTypeAESCTR, received[1], int64(len(received[1])+len(received[2])))
	if err != nil || !ok {
		t.Fatalf("expected v2 header, ok=%v err=%v", ok, err)
	}
	if meta.PlainSize != fileSize {
		t.Fatalf("plainSize=%d want=%d", meta.PlainSize, fileSize)
	}
	reader, _, err := encryption.AutoDecryptReader("123456", encryption.EncTypeAESCTR, bytes.NewReader(received[1]), int64(len(received[1])))
	if err != nil {
		t.Fatalf("auto decrypt reader: %v", err)
	}
	decryptedFirst, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read decrypted: %v", err)
	}
	if !bytes.Equal(decryptedFirst, firstChunk) {
		t.Fatalf("first decrypted chunk mismatch")
	}
	cipher2, err := encryption.NewCipherV2(encryption.EncTypeAESCTR, "123456", meta.PlainSize, meta.NonceField)
	if err != nil {
		t.Fatalf("new v2 cipher: %v", err)
	}
	if err := cipher2.SetPosition(secondStart); err != nil {
		t.Fatalf("set position: %v", err)
	}
	secondCipher := append([]byte(nil), received[2]...)
	cipher2.Decrypt(secondCipher)
	if !bytes.Equal(secondCipher, secondChunk) {
		t.Fatalf("second decrypted chunk mismatch")
	}
}

func TestRangeSeekSkipsSniffForMidstreamBinaryPayload(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	fileSize := int64(2048)
	plain := bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 128)
	if int64(len(plain)) != fileSize {
		t.Fatalf("plain length=%d, want %d", len(plain), fileSize)
	}
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to create flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	rangeStart := int64(1024)
	rangeEnd := int64(1535)
	expected := plain[rangeStart : rangeEnd+1]

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Range"); got != "bytes=1024-1535" {
			t.Fatalf("upstream Range=%q", got)
		}
		headers := make(http.Header)
		headers.Set("Content-Type", "application/octet-stream")
		headers.Set("Content-Range", "bytes 1024-1535/2048")
		headers.Set("Content-Length", "512")
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     headers,
			Body:       io.NopCloser(bytes.NewReader(ciphertext[rangeStart : rangeEnd+1])),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/test.bin", nil)
	req.Header.Set("Range", "bytes=1024-1535")
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.local/file", passwd, fileSize, StreamStrategyRange, "/encrypt/test.bin")
	if result.Err != nil {
		t.Fatalf("unexpected stream error: %v", result.Err)
	}
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusPartialContent)
	}
	if body := rr.Body.Bytes(); !bytes.Equal(body, expected) {
		t.Fatalf("decrypted range mismatch: got %d bytes", len(body))
	}
	if got := rr.Header().Get("Content-Range"); got != "bytes 1024-1535/2048" {
		t.Fatalf("Content-Range=%q", got)
	}
}

func TestMediaContentTypeSkipsSniffAtStart(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	fileSize := int64(1024)
	plain := bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7}, 128)
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("failed to create flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		headers := make(http.Header)
		headers.Set("Content-Type", "video/mp2t")
		headers.Set("Content-Length", "1024")
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     headers,
			Body:       io.NopCloser(bytes.NewReader(ciphertext)),
			Request:    r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/test.ts", nil)
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.local/file", passwd, fileSize, StreamStrategyFull, "/encrypt/test.ts")
	if result.Err != nil {
		t.Fatalf("unexpected stream error: %v", result.Err)
	}
	if body := rr.Body.Bytes(); !bytes.Equal(body, plain) {
		t.Fatalf("decrypted body mismatch: got %d bytes", len(body))
	}
}
