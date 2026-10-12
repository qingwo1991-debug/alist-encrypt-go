package proxy

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

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3ColdProbeResolvesTrailerAndGeometry(t *testing.T) {
	container, want := buildV3Container(t, "pw", 73, bytes.Repeat([]byte("xyz"), 79))
	sp := NewStreamProxy(config.DefaultConfig())
	var ranges []string
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		ranges = append(ranges, r.Header.Get("Range"))
		if r.Header.Get("Authorization") != "Bearer probe" || r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatal("probe auth/encoding not retained")
		}
		return rangeAwareRoundTripper(container)(r)
	})
	result := sp.inspectEncryptedContentResult(context.Background(), "http://upstream.test/file", http.Header{"Authorization": {"Bearer probe"}}, &config.PasswdInfo{Enable: true, EncType: "aesctr"}, 0)
	if !result.Confirmed || !result.Meta.IsV3() || result.Meta.PlainSize != want.PlainSize || result.Meta.ChunkSize != 73 || result.Meta.CiphertextSize != int64(len(container)) {
		t.Fatalf("cold probe=%+v", result)
	}
	if len(ranges) != 3 || ranges[0] != "bytes=0-31" || ranges[1] != "bytes=32-47" || ranges[2] != fmt.Sprintf("bytes=%d-%d", len(container)-16, len(container)-1) {
		t.Fatalf("ranges=%v", ranges)
	}
}

func TestV3FixedHeaderProbeDoesNotReadTrailer(t *testing.T) {
	container, meta := buildV3Container(t, "pw", 73, bytes.Repeat([]byte("abc"), 79))
	container = append([]byte(nil), container[:len(container)-16]...)
	binary.BigEndian.PutUint64(container[24:32], uint64(meta.PlainSize))
	binary.BigEndian.PutUint32(container[40:44], 12345)
	sp := NewStreamProxy(config.DefaultConfig())
	calls := 0
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 2 {
			t.Fatal("fixed container must not read EOF trailer")
		}
		return rangeAwareRoundTripper(container)(r)
	})
	result := sp.inspectEncryptedContentResult(context.Background(), "http://upstream.test/file", nil, &config.PasswdInfo{Enable: true, EncType: "aesctr"}, 0)
	if !result.Confirmed || result.Meta.PlainSize != meta.PlainSize || result.Meta.KDFIterations != 12345 || calls != 2 {
		t.Fatalf("fixed probe=%+v calls=%d", result, calls)
	}
}

type unreadV3ProbeBody struct{ t *testing.T }

func (b unreadV3ProbeBody) Read([]byte) (int, error) {
	b.t.Fatal("must not read ignored Range full body")
	return 0, io.EOF
}
func (b unreadV3ProbeBody) Close() error { return nil }

func TestV3TrailerProbeFailuresAreNotConfirmed(t *testing.T) {
	container, _ := buildV3Container(t, "pw", 73, bytes.Repeat([]byte("abc"), 79))
	for _, mode := range []string{"status", "ignored-range", "short", "wrong-window", "changed-total", "magic", "geometry", "overflow", "cancel", "header-ignored-range"} {
		t.Run(mode, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 2 && mode == "header-ignored-range" {
					return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: unreadV3ProbeBody{t}, Request: r}, nil
				}
				if calls < 3 {
					if calls == 2 && mode == "cancel" {
						cancel()
					}
					return rangeAwareRoundTripper(container)(r)
				}
				if mode == "cancel" {
					if r.Context().Err() != context.Canceled {
						t.Fatal("trailer request lost parent cancellation")
					}
					return nil, r.Context().Err()
				}
				resp, err := rangeAwareRoundTripper(container)(r)
				if err != nil {
					return nil, err
				}
				switch mode {
				case "status":
					resp.StatusCode = http.StatusForbidden
				case "ignored-range":
					resp.StatusCode = http.StatusOK
					resp.Body = unreadV3ProbeBody{t}
				case "wrong-window":
					resp.Header.Set("Content-Range", fmt.Sprintf("bytes 0-15/%d", len(container)))
				case "changed-total":
					resp.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(container)-16, len(container)-1, len(container)+1))
				default:
					tail := append([]byte(nil), container[len(container)-16:]...)
					switch mode {
					case "short":
						tail = tail[:15]
					case "magic":
						tail[0] ^= 1
					case "geometry":
						binary.BigEndian.PutUint64(tail[8:], 1)
					case "overflow":
						binary.BigEndian.PutUint64(tail[8:], ^uint64(0))
					}
					resp.Body = io.NopCloser(bytes.NewReader(tail))
				}
				return resp, nil
			})
			result := sp.inspectEncryptedContentResult(ctx, "http://upstream.test/file", nil, &config.PasswdInfo{Enable: true, EncType: "aesctr"}, 0)
			if result.Confirmed {
				t.Fatalf("failed %s probe incorrectly confirmed: %+v", mode, result)
			}
		})
	}
}

func TestV3EmptyProbeAndPlaybackPreserveZeroPlainSize(t *testing.T) {
	container, _ := buildV3Container(t, "pw", 73, nil)
	for _, fixed := range []bool{false, true} {
		body := container
		if fixed {
			body = body[:encryption.V3HeaderSize]
		}
		sp := NewStreamProxy(config.DefaultConfig())
		sp.client = newTestClient(rangeAwareRoundTripper(body))
		passwd := &config.PasswdInfo{Enable: true, EncType: "aesctr", Password: "pw"}
		got := sp.inspectEncryptedContentResult(context.Background(), "http://upstream.test/file", nil, passwd, 0)
		if !got.Confirmed || !got.Meta.IsV3() || got.Meta.PlainSize != 0 {
			t.Fatalf("fixed=%v empty probe=%+v", fixed, got)
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			req := httptest.NewRequest(method, "/empty", nil)
			req = req.WithContext(WithContentMeta(req.Context(), got.Meta))
			rr := httptest.NewRecorder()
			outcome := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.test/file", passwd, 0, StreamStrategyFull, "")
			if outcome.Err != nil || !outcome.ResponseStarted || rr.Code != http.StatusOK || rr.Header().Get("Content-Length") != "0" || rr.Body.Len() != 0 {
				t.Fatalf("fixed=%v method=%s empty outcome=%+v status=%d body=%q", fixed, method, outcome, rr.Code, rr.Body.Bytes())
			}
		}
	}
}

func TestV3ProbeRejectsMalformedHeaderGeometry(t *testing.T) {
	container, _ := buildV3Container(t, "pw", 73, []byte(strings.Repeat("x", 100)))
	for _, offset := range []int{32, 36} {
		bad := append([]byte(nil), container...)
		binary.BigEndian.PutUint32(bad[offset:offset+4], 0)
		sp := NewStreamProxy(config.DefaultConfig())
		sp.client = newTestClient(rangeAwareRoundTripper(bad))
		if got := sp.inspectEncryptedContentResult(context.Background(), "http://upstream.test/file", nil, &config.PasswdInfo{Enable: true}, 0); got.Confirmed {
			t.Fatalf("malformed header offset %d confirmed: %+v", offset, got)
		}
	}
}
