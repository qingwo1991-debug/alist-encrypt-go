package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type netStringErr string

func (e netStringErr) Error() string   { return string(e) }
func (e netStringErr) Timeout() bool   { return false }
func (e netStringErr) Temporary() bool { return false }

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

func TestClassifyStreamErrorClientDisconnectBeforeGenericNetError(t *testing.T) {
	var err net.Error = netStringErr("write tcp 127.0.0.1:5344->127.0.0.1:50000: write: broken pipe")
	reason, retryable := classifyStreamError(err)
	if reason != "client_disconnect" {
		t.Fatalf("expected client_disconnect reason, got %q", reason)
	}
	if retryable {
		t.Fatalf("expected retryable=false for client disconnect")
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

func TestSniffDecryptedRejectsHighEntropyShortSample(t *testing.T) {
	sample := make([]byte, 256)
	for i := range sample {
		sample[i] = byte(i)
	}
	reader, ok := sniffDecrypted(bytes.NewReader(sample))
	if ok {
		t.Fatal("expected short high-entropy sample to be rejected")
	}
	if reader != nil {
		t.Fatal("expected nil reader when sample is rejected")
	}
}

func TestSniffDecryptedAcceptsHighEntropyMP4Plaintext(t *testing.T) {
	sample := make([]byte, 512)
	copy(sample, []byte("\x00\x00\x00 ftypisom\x00\x00\x02\x00isomiso2avc1mp41\x00\x00\x00\x08free\x00\xfc9Nmdat"))
	for i := 64; i < len(sample); i++ {
		sample[i] = byte((i*37 + 11) % 251)
	}
	reader, ok := sniffDecrypted(bytes.NewReader(sample))
	if !ok {
		t.Fatal("expected MP4 plaintext to pass sniffing even with high-entropy media payload")
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read sniffed data: %v", err)
	}
	if !bytes.Equal(got, sample) {
		t.Fatal("sniff reader did not preserve the consumed bytes")
	}
}
func TestInspectEncryptedContentFollowsRedirectForV2Probe(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}
	plain := bytes.Repeat([]byte("redirect-v2-plain"), 32)
	contentEnc, err := encryption.NewLatestContentEncryptor(passwd.Password, passwd.EncType, int64(len(plain)))
	if err != nil {
		t.Fatalf("new latest encryptor: %v", err)
	}
	cipherReader, err := contentEnc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatalf("encrypt reader: %v", err)
	}
	ciphertext, err := io.ReadAll(cipherReader)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "http://openalist:5244/dav/demo.bin":
			if got := r.Header.Get("Authorization"); got != "Basic test" {
				t.Fatalf("authorization=%q", got)
			}
			return &http.Response{
				StatusCode: http.StatusFound,
				Header: http.Header{
					"Location": []string{"https://cdn.example/demo.bin"},
				},
				Body:    io.NopCloser(strings.NewReader("")),
				Request: r,
			}, nil
		case "https://cdn.example/demo.bin":
			if got := r.Header.Get("Authorization"); got != "" {
				t.Fatalf("redirected probe should strip auth, got %q", got)
			}
			if got := r.Header.Get("Range"); got != "bytes=0-31" {
				t.Fatalf("range=%q", got)
			}
			return &http.Response{
				StatusCode: http.StatusPartialContent,
				Header: http.Header{
					"Content-Range":  []string{"bytes 0-31/" + strconv.Itoa(len(ciphertext))},
					"Content-Length": []string{"32"},
				},
				Body:    io.NopCloser(bytes.NewReader(ciphertext[:32])),
				Request: r,
			}, nil
		default:
			t.Fatalf("unexpected url: %s", r.URL.String())
			return nil, nil
		}
	})

	headers := make(http.Header)
	headers.Set("Authorization", "Basic test")
	meta := sp.InspectEncryptedContent(context.Background(), "http://openalist:5244/dav/demo.bin", headers, passwd, int64(len(ciphertext)))
	if !meta.IsV2() {
		t.Fatalf("expected v2 meta, got version=%d", meta.Version)
	}
	if meta.PlainSize != int64(len(plain)) {
		t.Fatalf("plain size=%d want=%d", meta.PlainSize, len(plain))
	}
}

func TestDecryptRequestFollowsTemporaryRedirect(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.FollowRedirectForDecrypt = true
	sp := NewStreamProxy(cfg)

	fileSize := int64(64)
	plain := bytes.Repeat([]byte("R"), int(fileSize))
	ciphertext := append([]byte(nil), plain...)
	flow, err := encryption.NewFlowEnc("123456", "aesctr", fileSize)
	if err != nil {
		t.Fatalf("new flow enc: %v", err)
	}
	flow.Encrypt(ciphertext)

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "http://openalist:5244/dav/demo.bin":
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Header: http.Header{
					"Location": []string{"https://cdn.example/demo.bin"},
				},
				Body:    io.NopCloser(strings.NewReader("")),
				Request: r,
			}, nil
		case "https://cdn.example/demo.bin":
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":   []string{"video/mp4"},
					"Content-Length": []string{strconv.FormatInt(fileSize, 10)},
				},
				Body:    io.NopCloser(bytes.NewReader(ciphertext)),
				Request: r,
			}, nil
		default:
			t.Fatalf("unexpected url: %s", r.URL.String())
			return nil, nil
		}
	})

	req := httptest.NewRequest(http.MethodGet, "/dav/demo.mp4", nil)
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}
	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://openalist:5244/dav/demo.bin", passwd, fileSize, StreamStrategyRange, "/encrypt")
	if result.Err != nil {
		t.Fatalf("unexpected stream error: %v", result.Err)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusOK)
	}
	if !bytes.Equal(rr.Body.Bytes(), plain) {
		t.Fatal("decrypted redirect body mismatch")
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

func TestStripForeignHeadersPreservesAuthForAlistTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.ServerHost = "openalist"
	cfg.AlistServer.ServerPort = 5244
	cfg.AlistServer.HTTPS = false
	sp := NewStreamProxy(cfg)

	req := httptest.NewRequest(http.MethodGet, "http://openalist:5244/d/enc/demo.bin", nil)
	req.Header.Set("Authorization", "Basic test")
	req.Header.Set("Cookie", "sid=1")
	req.Header.Set("Referer", "http://example.com")
	req.Header.Set("Depth", "1")

	sp.StripForeignHeaders(req)

	if got := req.Header.Get("Authorization"); got != "Basic test" {
		t.Fatalf("authorization=%q", got)
	}
	if got := req.Header.Get("Cookie"); got != "sid=1" {
		t.Fatalf("cookie=%q", got)
	}
	if got := req.Header.Get("Depth"); got != "" {
		t.Fatalf("depth=%q", got)
	}
	if got := req.Header.Get("Referer"); got != "" {
		t.Fatalf("referer=%q", got)
	}
}

func TestStripForeignHeadersStripsAuthForCDNTargets(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.ServerHost = "openalist"
	cfg.AlistServer.ServerPort = 5244
	cfg.AlistServer.HTTPS = false
	sp := NewStreamProxy(cfg)

	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/demo.bin", nil)
	req.Header.Set("Authorization", "Basic test")
	req.Header.Set("Cookie", "sid=1")
	req.Header.Set("Referer", "http://example.com")
	req.Header.Set("Depth", "1")

	sp.StripForeignHeaders(req)

	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("authorization=%q", got)
	}
	if got := req.Header.Get("Cookie"); got != "sid=1" {
		t.Fatalf("cookie=%q", got)
	}
	if got := req.Header.Get("Depth"); got != "" {
		t.Fatalf("depth=%q", got)
	}
	if got := req.Header.Get("Referer"); got != "" {
		t.Fatalf("referer=%q", got)
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
