package encrypt

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Match shared/encryptcore's real 48-byte V3 header layout. Playback's 32-byte
// probe cannot parse the whole header, but must still recognize its magic.
func unsupportedV3Fixture() []byte {
	header := make([]byte, 48)
	copy(header, "V3GCM3")
	header[6] = 3
	copy(header[8:24], []byte("0123456789abcdef"))
	binary.BigEndian.PutUint64(header[24:32], 4096)
	binary.BigEndian.PutUint32(header[32:36], 4096)
	binary.BigEndian.PutUint32(header[36:40], 16)
	binary.BigEndian.PutUint32(header[40:44], 600000)
	return append(header, bytes.Repeat([]byte{0xa5}, 4096+16)...)
}

func TestInspectUnsupportedV3NeverFallsBackToLegacy(t *testing.T) {
	for _, encType := range []EncryptionType{EncTypeAESCTR, EncTypeChaCha20, EncTypeRC4} {
		for _, prefixLen := range []int{6, 31, 32} {
			t.Run(fmt.Sprintf("%s/%d", encType, prefixLen), func(t *testing.T) {
				calls := 0
				p := &ProxyServer{
					config: &ProxyConfig{AlistHost: "alist.local", AlistPort: 5244},
					streamClient: &http.Client{Transport: v2ProbeRoundTripper(func(req *http.Request) (*http.Response, error) {
						calls++
						if req.URL.Host != "cdn.local" || req.Header.Get("Range") != "bytes=0-31" {
							t.Fatalf("unsupported V3 attempted fallback: %s range=%q", req.URL, req.Header.Get("Range"))
						}
						body := unsupportedV3Fixture()[:prefixLen]
						return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {"bytes 0-31/4160"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
					})},
				}
				meta, confirmed := p.inspectEncryptedContentWithFallbackConfirmed(context.Background(), "http://cdn.local/video", nil, &EncryptPath{Enable: true, EncType: encType}, 4160, "/video")
				if !confirmed || meta.Version != ContentVersionV3 || meta.IsV2() || meta.PlainSize != 0 || calls != 1 {
					t.Fatalf("meta=%+v confirmed=%v calls=%d", meta, confirmed, calls)
				}
			})
		}
	}
}

func TestServePlaybackRejectsUnsupportedV3BeforeStreaming(t *testing.T) {
	for _, mode := range []string{"probe", "old-partial-v1-cache", "redirect-v3", "file-cache-v3"} {
		t.Run(mode, func(t *testing.T) {
			p, err := NewProxyServer(&ProxyConfig{ProxyPort: 5344, PlayFirstFallback: true})
			if err != nil {
				t.Fatal(err)
			}
			defer p.stopRangeProbeLoop()
			defer p.stopCacheCleanup()
			defer p.closeLocalStore()
			fixture := unsupportedV3Fixture()
			calls := 0
			p.streamClient = &http.Client{Transport: v2ProbeRoundTripper(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.Header.Get("Range") != "bytes=0-31" {
					t.Fatalf("V3 payload streaming attempted: %s range=%q", req.URL, req.Header.Get("Range"))
				}
				return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": {fmt.Sprintf("bytes 0-31/%d", len(fixture))}}, Body: io.NopCloser(bytes.NewReader(fixture[:32])), Request: req}, nil
			})}
			info := &RedirectInfo{RedirectURL: "http://cdn.local/video", OriginalURL: "/enc/demo.mp4", EncryptedPath: "/enc/object", FileSize: int64(len(fixture)), PasswdInfo: &EncryptPath{Path: "/enc/*", Enable: true, EncType: EncTypeAESCTR, Password: "test"}}
			wantCalls := 1
			switch mode {
			case "old-partial-v1-cache":
				p.storeFileCache(info.OriginalURL, &FileInfo{ContentVersion: ContentVersionV1, Size: int64(len(fixture))})
			case "redirect-v3":
				info.ContentVersion = ContentVersionV3
				info.FileSize = 0 // Rejection must not require valid V2 metadata or size.
				wantCalls = 0
			case "file-cache-v3":
				p.storeFileCache(info.OriginalURL, &FileInfo{ContentVersion: ContentVersionV3})
				wantCalls = 0
			}
			p.storeRedirectCache("unsupported-v3", info)
			rec := httptest.NewRecorder()
			newPlayOrchestrator(p).ServePlayback(rec, httptest.NewRequest(http.MethodGet, "http://proxy.local/redirect/unsupported-v3?decode=1", nil))
			if rec.Code != http.StatusUnsupportedMediaType || rec.Body.String() != unsupportedV3Playback+"\n" {
				t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
			}
			if calls != wantCalls || strings.Contains(rec.Header().Get("Content-Type"), "video") || bytes.Contains(rec.Body.Bytes(), fixture[:6]) {
				t.Fatalf("calls=%d want=%d headers=%v body=%q", calls, wantCalls, rec.Header(), rec.Body.String())
			}
		})
	}
}

func TestUnsupportedV3OutcomeDoesNotRetryOrLearn(t *testing.T) {
	rec := httptest.NewRecorder()
	outcome := rejectUnsupportedV3Playback(rec)
	if outcome.Err == nil || outcome.Retryable || !outcome.ResponseStarted || outcome.StatusCode != 415 || outcome.FailureReason != "unsupported_content_version" {
		t.Fatalf("outcome=%+v", outcome)
	}
	// The strategy selector only learns success when Err == nil, or failures
	// when Retryable && !ResponseStarted; neither applies to this outcome.
}
