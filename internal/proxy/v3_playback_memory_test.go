package proxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestV3ResourceFailureClearsEarlierFallbackHeaders(t *testing.T) {
	payload := bytes.Repeat([]byte("memory-budget"), 20)
	container, meta := buildV3Container(t, "pw", 64, payload)
	cfg := config.DefaultConfig()
	cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 1
	sp := NewStreamProxy(cfg)
	sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
		resp, err := rangeAwareRoundTripper(container)(req)
		resp.Header.Set("ETag", "stale-etag")
		resp.Header.Set("Last-Modified", "stale-date")
		return resp, err
	})
	passwd := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
	makeRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/file", nil)
		req.Header.Set("Range", "bytes=127-190")
		return req.WithContext(WithContentMeta(req.Context(), meta))
	}
	rr := httptest.NewRecorder()
	first := sp.ProxyDownloadDecryptWithStrategy(rr, makeRequest(), "http://upstream.test/file", passwd, meta.PlainSize, StreamStrategyChunked)
	if first.FailureReason != "chunked_seek_too_large" || first.ResponseStarted || rr.Header().Get("Content-Range") == "" {
		t.Fatalf("expected uncommitted range headers from failed Chunked: %+v %v", first, rr.Header())
	}
	release, ok := sp.acquireV3Memory(v3RecordBudgetBytes)
	if !ok {
		t.Fatal("failed to reserve empty memory budget")
	}
	defer release()
	last := sp.ProxyDownloadDecryptWithStrategy(rr, makeRequest(), "http://upstream.test/file", passwd, meta.PlainSize, StreamStrategyFull)
	if rr.Code != 503 || !last.ResponseStarted || last.FailureReason != "resource_exhausted" || last.Retryable || rr.Body.Len() != 0 {
		t.Fatalf("terminal response=%+v code=%d body=%d", last, rr.Code, rr.Body.Len())
	}
	for _, name := range []string{"Content-Range", "Content-Type", "ETag", "Accept-Ranges", "Last-Modified"} {
		if value := rr.Result().Header.Get(name); value != "" {
			t.Fatalf("stale header %s=%q", name, value)
		}
	}
	if rr.Result().Header.Get("Content-Length") != "0" || rr.Result().Header.Get("Retry-After") != "2" || rr.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("terminal headers=%v", rr.Result().Header)
	}
}

func TestV3PlaybackMemoryBudgetTerminalAndRelease(t *testing.T) {
	payload := []byte("memory-budget")
	container, meta := buildV3Container(t, "pw", 64, payload)
	passwd := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
	for _, mode := range []string{"oversized", "exhausted", "success", "decrypt-error"} {
		t.Run(mode, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			sp.client = newTestClient(rangeAwareRoundTripper(container))
			requestMeta := meta
			var release func()
			switch mode {
			case "oversized":
				requestMeta.ChunkSize = uint32(v3RecordBudgetBytes)
			case "exhausted":
				var ok bool
				release, ok = sp.acquireV3Memory(v3RecordBudgetBytes)
				if !ok {
					t.Fatal("failed to reserve empty budget")
				}
				defer release()
			case "decrypt-error":
				bad := append([]byte(nil), container...)
				bad[meta.HeaderLen] ^= 1
				sp.client = newTestClient(rangeAwareRoundTripper(bad))
			}
			req := httptest.NewRequest(http.MethodGet, "/file", nil)
			req = req.WithContext(WithContentMeta(req.Context(), requestMeta))
			rr := httptest.NewRecorder()
			outcome := sp.ProxyDownloadDecryptWithStrategy(rr, req, "http://upstream.test/file", passwd, meta.PlainSize, StreamStrategyFull)
			if mode == "oversized" || mode == "exhausted" {
				if rr.Code != 503 || outcome.StatusCode != 503 || !outcome.ResponseStarted || outcome.Retryable || !outcome.NoLearning {
					t.Fatalf("memory rejection=%+v", outcome)
				}
				want := "bad_v3_metadata"
				if mode == "exhausted" {
					want = "resource_exhausted"
					release()
					release()
				}
				if string(outcome.FailureReason) != want {
					t.Fatalf("memory reason=%+v", outcome)
				}
			} else if mode == "success" && (outcome.Err != nil || !bytes.Equal(rr.Body.Bytes(), payload)) {
				t.Fatalf("stream=%+v", outcome)
			} else if mode == "decrypt-error" && outcome.Err == nil {
				t.Fatal("corrupted chunk unexpectedly decrypted")
			}
			if sp.v3Memory.used.Load() != 0 {
				t.Fatal("stream leaked V3 memory reservation")
			}
		})
	}
}
