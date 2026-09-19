package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// buildV3Container builds an in-memory V3 container plus the ContentMeta the
// proxy needs to decrypt it over the wire.
func buildV3Container(t *testing.T, password string, chunkSize int64, plain []byte) ([]byte, encryption.ContentMeta) {
	t.Helper()
	var buf bytes.Buffer
	w, err := encryption.NewV3Writer(&buf, password, chunkSize)
	if err != nil {
		t.Fatalf("NewV3Writer: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	meta := encryption.ContentMeta{
		EncType:        encryption.EncTypeAESCTR,
		Version:        encryption.ContentVersionV3,
		HeaderLen:      encryption.V3HeaderSize,
		PlainSize:      int64(len(plain)),
		CiphertextSize: int64(buf.Len()),
		NonceField:     w.NonceField(),
		ChunkSize:      uint32(chunkSize),
		KDFIterations:  600000,
	}
	return buf.Bytes(), meta
}

// rangeAwareRoundTripper serves a byte slice honoring HTTP Range the way a
// real object store does (206 + Content-Range, or the whole body when the
// request is Range-less).
func rangeAwareRoundTripper(body []byte) roundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		headers := make(http.Header)
		headers.Set("Accept-Ranges", "bytes")
		headers.Set("Content-Type", "application/octet-stream")
		rangeHeader := req.Header.Get("Range")
		if rangeHeader == "" {
			headers.Set("Content-Length", strconv.Itoa(len(body)))
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     headers,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Request:    req,
			}, nil
		}
		spec := strings.TrimPrefix(rangeHeader, "bytes=")
		if spec == rangeHeader {
			return &http.Response{StatusCode: http.StatusBadRequest, Header: headers, Body: io.NopCloser(strings.NewReader("bad range")), Request: req}, nil
		}
		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return &http.Response{StatusCode: http.StatusBadRequest, Header: headers, Body: io.NopCloser(strings.NewReader("bad range")), Request: req}, nil
		}
		start, err1 := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
		end, err2 := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err1 != nil || err2 != nil || start < 0 || end < start || end >= int64(len(body)) {
			headers.Set("Content-Range", fmt.Sprintf("bytes */%d", len(body)))
			return &http.Response{
				StatusCode: http.StatusRequestedRangeNotSatisfiable,
				Header:     headers,
				Body:       io.NopCloser(bytes.NewReader(nil)),
				Request:    req,
			}, nil
		}
		chunk := body[start : end+1]
		headers.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(body)))
		headers.Set("Content-Length", strconv.Itoa(len(chunk)))
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     headers,
			Body:       io.NopCloser(bytes.NewReader(chunk)),
			Request:    req,
		}, nil
	}
}

func TestStreamV3RangePlayback(t *testing.T) {
	const cs = int64(64)
	payload := bytes.Repeat([]byte("0123456789abcdef-xyz"), 48) // 960 bytes, ~15 records
	container, meta := buildV3Container(t, "v3-playback-pw", cs, payload)
	passwd := &config.PasswdInfo{Password: "v3-playback-pw", EncType: "aesctr", Enable: true}

	cases := []struct {
		name        string
		rangeHeader string
		wantSliced  []byte
		wantStatus  int
	}{
		{"within-chunk", "bytes=10-39", payload[10:40], http.StatusPartialContent},
		{"cross-chunk", "bytes=127-190", payload[127:191], http.StatusPartialContent},
		{"chunk-boundary", "bytes=64-77", payload[64:78], http.StatusPartialContent},
		{"suffix", "bytes=-24", payload[len(payload)-24:], http.StatusPartialContent},
		{"no-range-full", "", nil, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			sp.client = newTestClient(rangeAwareRoundTripper(container))
			req := httptest.NewRequest(http.MethodGet, "/d/test.mp4", nil)
			if tc.rangeHeader != "" {
				req.Header.Set("Range", tc.rangeHeader)
			}
			req = req.WithContext(WithContentMeta(req.Context(), meta))
			rr := httptest.NewRecorder()
			result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.local/file", passwd, meta.PlainSize, StreamStrategyRange, "/encrypt")
			if result.Err != nil {
				t.Fatalf("stream error: %v", result.Err)
			}
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d, want %d", rr.Code, tc.wantStatus)
			}
			if tc.wantSliced == nil {
				if !bytes.Equal(rr.Body.Bytes(), payload) {
					t.Fatalf("full body mismatch: got %d bytes", rr.Body.Len())
				}
			} else if !bytes.Equal(rr.Body.Bytes(), tc.wantSliced) {
				t.Fatalf("range body mismatch: got %d bytes, want %d\n got head: %x\nwant head: %x",
					rr.Body.Len(), len(tc.wantSliced), firstN(rr.Body.Bytes(), 8), firstN(tc.wantSliced, 8))
			}
		})
	}
}

func TestStreamV3WrongPasswordFails(t *testing.T) {
	payload := bytes.Repeat([]byte{0x7c}, 300)
	container, meta := buildV3Container(t, "right-password", 64, payload)
	passwd := &config.PasswdInfo{Password: "wrong-password", EncType: "aesctr", Enable: true}

	sp := NewStreamProxy(config.DefaultConfig())
	sp.client = newTestClient(rangeAwareRoundTripper(container))
	req := httptest.NewRequest(http.MethodGet, "/d/test.mp4", nil)
	req.Header.Set("Range", "bytes=0-63")
	req = req.WithContext(WithContentMeta(req.Context(), meta))
	rr := httptest.NewRecorder()
	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.test/file", passwd, int64(len(payload)), StreamStrategyRange, "/v3")
	if result.Err == nil {
		t.Fatal("wrong password must fail V3 stream decrypt")
	}
}

func firstN(b []byte, n int) []byte {
	if len(b) > n {
		b = b[:n]
	}
	return b
}

func TestInspectEncryptedContentRecognizesV3(t *testing.T) {
	const cs = int64(64)
	payload := bytes.Repeat([]byte("probe-test-v3"), 200)
	container, _ := buildV3Container(t, "pw", cs, payload)
	passwd := &config.PasswdInfo{Password: "pw", EncType: "aesctr", Enable: true}

	sp := NewStreamProxy(config.DefaultConfig())
	sp.client = newTestClient(rangeAwareRoundTripper(container))

	meta, confirmed := sp.inspectEncryptedContentConfirmed(nil, "http://upstream.test/v3.bin", nil, passwd, int64(len(container)))
	if meta.IsV3() && confirmed {
		if meta.ChunkSize != uint32(cs) {
			t.Fatalf("chunk size=%d, want %d", meta.ChunkSize, cs)
		}
		if len(meta.NonceField) != 16 {
			t.Fatalf("nonce len=%d, want 16", len(meta.NonceField))
		}
		// Stream-written V3 containers keep the plaintext size in the trailer,
		// not in the 48-byte header; the probe only certifies the version,
		// nonce, chunk size and ciphertext size.
		if meta.CiphertextSize != int64(len(container)) {
			t.Fatalf("ciphertext size=%d, want %d", meta.CiphertextSize, len(container))
		}
		return
	}
	t.Fatalf("V3 prefix not recognized: version=%d confirmed=%v", meta.Version, confirmed)
}

func TestInspectEncryptedContentStillV2ForLegacy(t *testing.T) {
	payload := bytes.Repeat([]byte{0x11, 0x22}, 300)

	// Build a legacy V2 container by encrypting the full payload with the
	// latest (V2) content encryptor.
	enc, err := encryption.NewLatestContentEncryptor("pw", "aesctr", int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := enc.EncryptReader(bytes.NewReader(payload), 0)
	if err != nil {
		t.Fatal(err)
	}
	container, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}

	passwd := &config.PasswdInfo{Password: "pw", EncType: "aesctr", Enable: true}
	sp := NewStreamProxy(config.DefaultConfig())
	sp.client = newTestClient(rangeAwareRoundTripper(container))
	meta, confirmed := sp.inspectEncryptedContentConfirmed(nil, "http://upstream.test/v2.bin", nil, passwd, int64(len(container)))
	if !confirmed {
		t.Fatalf("V2 not confirmed")
	}
	if meta.IsV2() && meta.Version == 2 {
		return
	}
	t.Fatalf("expected V2 legacy meta, got version=%d", meta.Version)
}
