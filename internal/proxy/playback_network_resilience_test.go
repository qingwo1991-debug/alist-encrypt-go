package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func TestV3NonRangeUpstreamFallbackExactPlaintext(t *testing.T) {
	payload := bytes.Repeat([]byte("fallback-plaintext-"), 30)
	container, meta := buildV3Container(t, "pw", 64, payload)
	passwd := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
	for _, strategy := range []StreamStrategy{StreamStrategyChunked, StreamStrategyFull} {
		for _, interval := range []struct {
			name, header string
			start, end   int
		}{
			{"get", "", 0, len(payload)}, {"zero", "bytes=0-31", 0, 32}, {"seek", "bytes=127-190", 127, 191}, {"suffix", "bytes=-19", len(payload) - 19, len(payload)},
		} {
			t.Run(string(strategy)+"/"+interval.name, func(t *testing.T) {
				sp := NewStreamProxy(config.DefaultConfig())
				var ranges []string
				sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
					ranges = append(ranges, req.Header.Get("Range"))
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Length": {strconv.Itoa(len(container))}, "Content-Type": {"application/octet-stream"}}, Body: io.NopCloser(bytes.NewReader(container)), Request: req}, nil
				})
				makeReq := func() *http.Request {
					req := httptest.NewRequest(http.MethodGet, "/file", nil)
					req.Header.Set("Range", interval.header)
					return req.WithContext(WithContentMeta(req.Context(), meta))
				}
				if interval.header != "" {
					outcome := sp.ProxyDownloadDecryptWithStrategy(httptest.NewRecorder(), makeReq(), "http://upstream.test/file", passwd, meta.PlainSize, StreamStrategyRange)
					if outcome.FailureReason != "range_unsupported" || outcome.ResponseStarted {
						t.Fatalf("range outcome=%+v", outcome)
					}
				}
				rr := httptest.NewRecorder()
				outcome := sp.ProxyDownloadDecryptWithStrategy(rr, makeReq(), "http://upstream.test/file", passwd, meta.PlainSize, strategy)
				if outcome.Err != nil || !bytes.Equal(rr.Body.Bytes(), payload[interval.start:interval.end]) {
					t.Fatalf("fallback outcome=%+v body length=%d", outcome, rr.Body.Len())
				}
				if ranges[len(ranges)-1] != "" {
					t.Fatalf("fallback retained upstream Range: %v", ranges)
				}
				if interval.header != "" {
					want := fmt.Sprintf("bytes %d-%d/%d", interval.start, interval.end-1, len(payload))
					if rr.Code != 206 || rr.Header().Get("Content-Range") != want {
						t.Fatalf("status/headers=%d %v", rr.Code, rr.Header())
					}
				} else if rr.Code != 200 {
					t.Fatalf("GET status=%d", rr.Code)
				}
			})
		}
	}
}

func TestDownloadRetryCancellationAndExhausted503(t *testing.T) {
	for _, mode := range []string{"cancel-backoff", "deadline-backoff", "exhausted-503", "503-recovers"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.AlistServer.CircuitBreakerThreshold = 1
			sp := NewStreamProxy(cfg)
			sp.retrier.MaxRetries = 1
			sp.retrier.Initial = 100 * time.Millisecond
			sp.retrier.Max = 100 * time.Millisecond
			sp.retrier.Jitter = 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "deadline-backoff" {
				var done context.CancelFunc
				ctx, done = context.WithTimeout(ctx, 20*time.Millisecond)
				defer done()
			}
			calls := 0
			sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
				calls++
				if mode == "cancel-backoff" {
					cancel()
				}
				status := http.StatusServiceUnavailable
				if mode == "503-recovers" && calls == 2 {
					status = http.StatusNotFound
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("unavailable")), Request: req}, nil
			})
			req := httptest.NewRequest(http.MethodGet, "/file", nil).WithContext(ctx)
			outcome := sp.ProxyDownloadDecryptWithStrategy(httptest.NewRecorder(), req, "http://upstream.test/file", nil, 100, StreamStrategyRange)
			if outcome.Err == nil || outcome.ResponseStarted {
				t.Fatalf("outcome=%+v", outcome)
			}
			switch mode {
			case "cancel-backoff", "deadline-backoff":
				if !errors.Is(outcome.Err, ctx.Err()) || calls != 1 || !sp.circuitBreakerFor("http://upstream.test/file").Allow() {
					t.Fatalf("cancellation=%+v calls=%d", outcome, calls)
				}
				if outcome.StatusCode != 0 || outcome.Retryable {
					t.Fatalf("stale retry status=%+v", outcome)
				}
			case "exhausted-503":
				if calls != 2 || outcome.StatusCode != 503 || outcome.FailureReason != "upstream_5xx" || !outcome.Retryable || !outcome.NoLearning {
					t.Fatalf("503 outcome=%+v calls=%d", outcome, calls)
				}
			case "503-recovers":
				if calls != 2 || outcome.StatusCode != 404 || outcome.FailureReason != "upstream_4xx" {
					t.Fatalf("recovery outcome=%+v", outcome)
				}
			}
		})
	}
}

// Real HTTP body reads must unblock on the probe deadline even after headers
// arrived, with a streaming client whose overall Timeout is deliberately zero.
func TestMetadataProbeStalledBodyHasTotalBudget(t *testing.T) {
	container, _ := buildV3Container(t, "pw", 64, []byte("probe"))
	for _, stall := range []string{"prefix", "header-tail", "trailer"} {
		t.Run(stall, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start, end := int64(0), int64(31)
				fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
				shouldStall := stall == "prefix" || (stall == "header-tail" && start == 32) || (stall == "trailer" && start == int64(len(container)-16))
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(container)))
				w.Header().Set("Content-Length", strconv.FormatInt(end-start+1, 10))
				w.WriteHeader(http.StatusPartialContent)
				if shouldStall {
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					return
				}
				w.Write(container[start : end+1])
			}))
			defer server.Close()
			cfg := config.DefaultConfig()
			cfg.AlistServer.RangeProbeTimeoutSeconds = 1
			sp := NewStreamProxy(cfg)
			sp.client = &Client{Client: &http.Client{Transport: http.DefaultTransport, Timeout: 0}}
			started := time.Now()
			result := sp.inspectEncryptedContentResult(context.Background(), server.URL, nil, &config.PasswdInfo{Enable: true, EncType: "aesctr"}, int64(len(container)))
			elapsed := time.Since(started)
			if result.Confirmed || elapsed < 800*time.Millisecond || elapsed > 3*time.Second {
				t.Fatalf("stalled probe result=%+v elapsed=%v", result, elapsed)
			}
		})
	}
}

func TestMetadataProbeFollowupsShareDeadline(t *testing.T) {
	container, _ := buildV3Container(t, "pw", 64, []byte("probe"))
	cfg := config.DefaultConfig()
	cfg.AlistServer.RangeProbeTimeoutSeconds = 1
	sp := NewStreamProxy(cfg)
	var deadline time.Time
	calls := 0
	sp.client = newTestClient(func(req *http.Request) (*http.Response, error) {
		calls++
		got, ok := req.Context().Deadline()
		if !ok {
			t.Fatal("probe has no independent deadline")
		}
		if deadline.IsZero() {
			deadline = got
		} else if got != deadline {
			t.Fatalf("followup extended total deadline: %v != %v", got, deadline)
		}
		return rangeAwareRoundTripper(container)(req)
	})
	result := sp.inspectEncryptedContentResult(context.Background(), "http://upstream.test/file", nil, &config.PasswdInfo{Enable: true, EncType: "aesctr"}, int64(len(container)))
	if !result.Confirmed || calls != 3 {
		t.Fatalf("probe result=%+v calls=%d", result, calls)
	}
}
