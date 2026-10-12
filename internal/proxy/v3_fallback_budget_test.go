package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/playbacktest"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

func TestV3FallbackCipherDiscardGeometry(t *testing.T) {
	for _, chunk := range []uint32{64, 97, 1 << 20, 16 << 20} {
		meta := encryption.ContentMeta{HeaderLen: encryption.V3HeaderSize, ChunkSize: chunk}
		for _, start := range []int64{0, int64(chunk) - 1, int64(chunk), 3*int64(chunk) + 7} {
			got, err := v3FallbackCipherDiscard(meta, start)
			want := meta.HeaderLen + start/int64(chunk)*(int64(chunk)+16)
			if err != nil || got != want {
				t.Fatalf("chunk=%d start=%d discard=%d want=%d err=%v", chunk, start, got, want, err)
			}
		}
	}
	for _, tc := range []struct {
		chunk         uint32
		header, start int64
	}{
		{0, 48, 0}, {1<<30 + 1, 48, 0}, {64, 0, 0}, {64, 48, -1}, {1, 48, math.MaxInt64},
	} {
		if _, err := v3FallbackCipherDiscard(encryption.ContentMeta{ChunkSize: tc.chunk, HeaderLen: tc.header}, tc.start); err == nil {
			t.Fatalf("invalid geometry accepted: %+v", tc)
		}
	}
}

func TestV3FallbackCipherBudgetBoundaryLoopback(t *testing.T) {
	plain := bytes.Repeat([]byte("geometry"), 32)
	container, meta := buildV3Container(t, "budget-pw", 64, plain)
	const start = int64(128)
	discard, err := v3FallbackCipherDiscard(meta, start)
	if err != nil {
		t.Fatal(err)
	}
	for _, strategy := range []StreamStrategy{StreamStrategyFull, StreamStrategyChunked} {
		for _, delta := range []int64{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/cap_delta_%d", strategy, delta), func(t *testing.T) {
				up := playbacktest.New(container, playbacktest.Behavior{Range: playbacktest.RangeIgnore}, nil)
				defer up.Close()
				cfg := config.DefaultConfig()
				cfg.AlistServer.ChunkedSeekMaxDiscardBytes = discard + delta
				sp := NewStreamProxy(cfg)
				req := httptest.NewRequest(http.MethodGet, "/file", nil)
				req.Header.Set("Range", "bytes=128-129")
				req = req.WithContext(WithContentMeta(req.Context(), meta))
				rr := httptest.NewRecorder()
				out := sp.ProxyDownloadDecryptWithStrategy(rr, req, up.URL("/file"), &config.PasswdInfo{Enable: true, Password: "budget-pw", EncType: "aesctr"}, meta.PlainSize, strategy)
				if delta < 0 {
					if out.FailureReason != v3SeekBudgetExceeded || out.Retryable || !out.NoLearning || !out.ResponseStarted || rr.Code != 503 || rr.Body.Len() != 0 {
						t.Fatalf("rejection: %+v code=%d", out, rr.Code)
					}
					if snap := up.Snapshot(); snap.RequestCount != 0 || snap.BodyBytes != 0 {
						t.Fatalf("prefetch rejection fetched: %+v", snap)
					}
				} else if out.Err != nil || rr.Code != 206 || !bytes.Equal(rr.Body.Bytes(), plain[128:130]) {
					t.Fatalf("allowed boundary: %+v body=%x", out, rr.Body.Bytes())
				}
			})
		}
	}
}

// Count client Read/Close separately from fixture server Write: net/http may
// buffer upstream bytes before the proxy sees headers. No timing/KDF hook is
// used; a nil password deliberately makes any accidental KDF entry fail.
type v3BudgetCountingBody struct{ reads, closes int }

func (b *v3BudgetCountingBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *v3BudgetCountingBody) Close() error             { b.closes++; return nil }

func TestV3RejectedWindowAndBudgetBeforeBodyAndKDF(t *testing.T) {
	meta := encryption.ContentMeta{Version: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, ChunkSize: 64, NonceField: make([]byte, 16), PlainSize: 1024}
	for _, tc := range []struct {
		name         string
		status       int
		contentRange string
	}{
		{"ignored", 200, ""}, {"refused", 416, "bytes */1344"},
		{"wrong-start", 206, "bytes 49-287/1344"}, {"short", 206, "bytes 208-210/1344"},
		{"pseudo-200", 200, "bytes 208-287/1344"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sp := NewStreamProxy(config.DefaultConfig())
			body := &v3BudgetCountingBody{}
			resp := &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: body}
			resp.Header.Set("Content-Range", tc.contentRange)
			sp.client = newTestClient(func(req *http.Request) (*http.Response, error) { return resp, nil })
			req := httptest.NewRequest("GET", "/file", nil)
			req.Header.Set("Range", "bytes=128-129")
			req = req.WithContext(WithContentMeta(req.Context(), meta))
			out := sp.ProxyDownloadDecryptWithStrategy(httptest.NewRecorder(), req, "http://upstream.test/file", nil, 1024, StreamStrategyRange)
			if out.Err == nil || !out.Retryable || out.ResponseStarted || body.reads != 0 || body.closes != 1 || sp.v3Memory.used.Load() != 0 {
				t.Fatalf("window rejection: %+v reads=%d", out, body.reads)
			}
		})
	}
	for _, strategy := range []StreamStrategy{StreamStrategyFull, StreamStrategyChunked} {
		cfg := config.DefaultConfig()
		cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 207
		sp := NewStreamProxy(cfg)
		body := &v3BudgetCountingBody{}
		resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}
		rng := &httputil.Range{Start: 128, End: 129}
		active, full := rng, (*httputil.Range)(nil)
		if strategy == StreamStrategyFull {
			active, full = nil, rng
		}
		out := sp.streamV3Response(httptest.NewRecorder(), httptest.NewRequest("GET", "/file", nil), resp, nil, 1024, meta, "bytes=128-129", strategy, active, full, "http://upstream.test/file", "")
		if out.FailureReason != v3SeekBudgetExceeded || !out.ResponseStarted || body.reads != 0 || sp.v3Memory.used.Load() != 0 {
			t.Fatalf("defensive gate: %+v reads=%d", out, body.reads)
		}
	}
}

func TestV3RefusedRangeTerminalFallbackDoesNotFetchAgain(t *testing.T) {
	meta := encryption.ContentMeta{Version: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, ChunkSize: 64, NonceField: make([]byte, 16), PlainSize: 1024}
	for _, mode := range []playbacktest.RangeMode{playbacktest.RangeIgnore, playbacktest.RangeReject} {
		up := playbacktest.New(make([]byte, 1344), playbacktest.Behavior{Range: mode, StallBody: true}, nil)
		cfg := config.DefaultConfig()
		cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 207
		sp := NewStreamProxy(cfg)
		req := httptest.NewRequest("GET", "/file", nil)
		req.Header.Set("Range", "bytes=128-129")
		req = req.WithContext(WithContentMeta(req.Context(), meta))
		rr := httptest.NewRecorder()
		first := sp.ProxyDownloadDecryptWithStrategy(rr, req, up.URL("/file"), nil, 1024, StreamStrategyRange)
		if first.Err == nil || !first.Retryable || first.ResponseStarted {
			up.Close()
			t.Fatalf("first refusal: %+v", first)
		}
		last := sp.ProxyDownloadDecryptWithStrategy(rr, req, up.URL("/alternate"), nil, 1024, StreamStrategyFull)
		up.Close()
		if last.FailureReason != v3SeekBudgetExceeded || last.Retryable || !last.NoLearning || !last.ResponseStarted {
			t.Fatalf("terminal fallback: %+v", last)
		}
		if snap := up.Snapshot(); snap.RequestCount != 1 || snap.BodyBytes != 0 {
			t.Fatalf("retry fetched body/alternate URL: %+v", snap)
		}
	}
}

func TestV3HEADAndCanceledContextAvoidKDF(t *testing.T) {
	meta := encryption.ContentMeta{Version: encryption.ContentVersionV3, HeaderLen: encryption.V3HeaderSize, ChunkSize: 64, NonceField: make([]byte, 16), PlainSize: 1024}
	sp := NewStreamProxy(config.DefaultConfig())
	body := &v3BudgetCountingBody{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}
	rr := httptest.NewRecorder()
	out := sp.streamV3Response(rr, httptest.NewRequest("HEAD", "/file", nil), resp, nil, 1024, meta, "", StreamStrategyFull, nil, nil, "http://upstream.test/file", "")
	if out.Err != nil || rr.Code != 200 || rr.Header().Get("Content-Length") != "1024" || rr.Header().Get("Accept-Ranges") != "bytes" || body.reads != 0 {
		t.Fatalf("HEAD: %+v headers=%v", out, rr.Header())
	}
	empty := meta
	empty.PlainSize = 0
	empty.CiphertextSize = encryption.V3HeaderSize + 16
	rr = httptest.NewRecorder()
	out = sp.streamDecryptResponse(rr, httptest.NewRequest("GET", "/empty", nil), resp, nil, 0, empty, "", StreamStrategyFull, "http://upstream.test/empty", "")
	if out.Err != nil || rr.Code != 200 || rr.Header().Get("Content-Length") != "0" || body.reads != 0 {
		t.Fatalf("empty: %+v headers=%v", out, rr.Header())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", "/file", nil).WithContext(ctx)
	out = sp.streamV3Response(httptest.NewRecorder(), req, resp, nil, 1024, meta, "", StreamStrategyFull, nil, nil, "http://upstream.test/file", "")
	if out.Err != context.Canceled || out.ResponseStarted || !out.NoLearning || body.reads != 0 || sp.v3Memory.used.Load() != 0 {
		t.Fatalf("cancel: %+v", out)
	}
}
