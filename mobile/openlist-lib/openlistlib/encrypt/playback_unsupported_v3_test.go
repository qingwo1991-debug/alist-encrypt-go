package encrypt

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A recognized V3 header is deliberately paired with unauthenticated records.
// Supporting V3 must not turn malformed/truncated containers into legacy streams.
func unsupportedV3Fixture() []byte {
	header := make([]byte, 48)
	copy(header, "V3GCM3")
	header[6] = 3
	copy(header[8:24], []byte("0123456789abcdef"))
	binary.BigEndian.PutUint64(header[24:32], 4096)
	binary.BigEndian.PutUint32(header[32:36], 4096)
	binary.BigEndian.PutUint32(header[36:40], 16)
	binary.BigEndian.PutUint32(header[40:44], 1)
	return append(header, bytes.Repeat([]byte{0xa5}, 4096+16)...)
}

func TestInspectMalformedV3NeverFallsBackToLegacy(t *testing.T) {
	for _, encType := range []EncryptionType{EncTypeAESCTR, EncTypeChaCha20, EncTypeRC4} {
		for _, prefixLen := range []int{6, 31, 32} {
			t.Run(fmt.Sprintf("%s/%d", encType, prefixLen), func(t *testing.T) {
				calls := 0
				p := &ProxyServer{config: &ProxyConfig{AlistHost: "alist.local", AlistPort: 5244}, streamClient: &http.Client{Transport: v2ProbeRoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.URL.Host != "cdn.local" || req.Header.Get("Range") != "bytes=0-47" {
						t.Fatalf("malformed V3 attempted fallback: %s range=%q", req.URL, req.Header.Get("Range"))
					}
					return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {"bytes 0-47/4160"}}, Body: io.NopCloser(bytes.NewReader(unsupportedV3Fixture()[:prefixLen])), Request: req}, nil
				})}}
				meta, confirmed := p.inspectEncryptedContentWithFallbackConfirmed(context.Background(), "http://cdn.local/video", nil, &EncryptPath{Enable: true, EncType: encType}, 4160, "/video")
				if !confirmed || !meta.IsV3() || meta.IsV2() || calls != 1 || ValidateV3ContentMeta(meta) == nil {
					t.Fatalf("meta=%+v confirmed=%v calls=%d", meta, confirmed, calls)
				}
			})
		}
	}
}

func TestV3AuthenticationFailureNeverStreamsCiphertext(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{StreamEngineVersion: 2}}
	p.ensureRuntimeCaches()
	fixture := unsupportedV3Fixture()
	calls := 0
	p.streamClient = &http.Client{Transport: v2ProbeRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls++
		var start, end int
		switch req.Header.Get("Range") {
		case "bytes=0-47":
			start, end = 0, 47
		case "bytes=48-4159":
			start, end = 48, 4159
		default:
			t.Fatalf("unexpected fallback request: %s range=%q", req.URL, req.Header.Get("Range"))
		}
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes %d-%d/%d", start, end, len(fixture))}, "Content-Length": {fmt.Sprint(end - start + 1)}}, ContentLength: int64(end - start + 1), Body: io.NopCloser(bytes.NewReader(fixture[start : end+1])), Request: req}, nil
	})}
	info := &RedirectInfo{RedirectURL: "http://cdn.local/video", OriginalURL: "/enc/demo.mp4", EncryptedPath: "/enc/object", FileSize: int64(len(fixture)), PasswdInfo: &EncryptPath{Path: "/enc/*", Enable: true, EncType: EncTypeAESCTR, Password: "test"}}
	p.storeRedirectCache("invalid-v3", info)
	rec := httptest.NewRecorder()
	newPlayOrchestrator(p).ServePlayback(rec, httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/invalid-v3?decode=1", nil))
	if rec.Code < 400 || rec.Body.Len() != 0 || bytes.Contains(rec.Body.Bytes(), fixture[:6]) || calls != 2 {
		t.Fatalf("status=%d body=%q calls=%d", rec.Code, rec.Body.String(), calls)
	}
}
