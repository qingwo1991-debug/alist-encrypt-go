package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func TestRangeCompatDowngradeAfterConsecutivePseudoRangeFailures(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.RangeReprobeMinutes = 30
	sp := NewStreamProxy(cfg)

	hits := 0
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		hits++
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Length": []string{"10"},
			},
			Body:    io.NopCloser(strings.NewReader(strings.Repeat("x", 10))),
			Request: r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/test.bin", nil)
	req.Header.Set("Range", "bytes=0-0")
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	result1 := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), req, "http://upstream.local/file", passwd, 10, StreamStrategyRange, "/encrypt")
	if result1.FailureReason != "range_unsupported" || !result1.Retryable {
		t.Fatalf("first failure reason=%q retryable=%v", result1.FailureReason, result1.Retryable)
	}

	result2 := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), req, "http://upstream.local/file", passwd, 10, StreamStrategyRange, "/encrypt")
	if result2.FailureReason != "range_unsupported" || !result2.Retryable {
		t.Fatalf("second failure reason=%q retryable=%v", result2.FailureReason, result2.Retryable)
	}

	before := hits
	result3 := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), req, "http://upstream.local/file", passwd, 10, StreamStrategyRange, "/encrypt")
	if result3.FailureReason != "range_unsupported" || !result3.Retryable {
		t.Fatalf("third failure reason=%q retryable=%v", result3.FailureReason, result3.Retryable)
	}
	if hits != before {
		t.Fatalf("expected third request to skip upstream, hits=%d before=%d", hits, before)
	}
}

func TestUpstreamNotFoundRemainsRetryableBeforeResponseStarts(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			Body:    io.NopCloser(strings.NewReader("not found")),
			Request: r,
		}, nil
	})

	req := httptest.NewRequest(http.MethodGet, "/d/missing.bin", nil)
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, "http://upstream.local/missing", passwd, 123, StreamStrategyRange, "/encrypt")
	if result.Err == nil {
		t.Fatal("expected upstream 404 error")
	}
	if !result.Retryable || result.FailureReason != "upstream_4xx" || !result.NoLearning {
		t.Fatalf("unexpected outcome: %#v", result)
	}
	if result.ResponseStarted {
		t.Fatal("404 must not commit the response before fallback")
	}
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("recorder was unexpectedly written: status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestSelectOptimalStrategyUsesChunkedForSmallSeekOnIncompatibleProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 8 * 1024 * 1024
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	err := sp.compatStore.Upsert(key, RangeCompatState{
		Incompatible: true,
		NextProbeAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to seed compat store: %v", err)
	}

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=1048576-")
	if got != StreamStrategyChunked {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyChunked)
	}
}

func TestSelectOptimalStrategyUsesFullForLargeSeekOnIncompatibleProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 1024
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	err := sp.compatStore.Upsert(key, RangeCompatState{
		Incompatible: true,
		NextProbeAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to seed compat store: %v", err)
	}

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=4096-")
	if got != StreamStrategyFull {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyFull)
	}
}

func TestSelectOptimalStrategyKeepsRangeWhenProviderCompatible(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	sp := NewStreamProxy(cfg)

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=0-1023")
	if got != StreamStrategyRange {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyRange)
	}
}

func TestClassifyRequestRangeMarksFirstFrameWindow(t *testing.T) {
	profile := classifyRequestRange(http.MethodGet, "bytes=0-1048575")
	if !profile.HasRange {
		t.Fatal("expected range profile")
	}
	if !profile.IsFirstFrameHint {
		t.Fatalf("expected first-frame hint, got %#v", profile)
	}
	if profile.EstimatedLength != 1048576 {
		t.Fatalf("estimated length=%d, want 1048576", profile.EstimatedLength)
	}
}

func TestClassifyRequestRangeMarksNearHeaderOpenRangeAsFirstFrame(t *testing.T) {
	profile := classifyRequestRange(http.MethodGet, "bytes=48-")
	if !profile.HasRange || !profile.IsFirstFrameHint {
		t.Fatalf("expected bytes=48- to be a first-frame request, got %#v", profile)
	}
}

func TestClassifyRequestRangeDoesNotMarkLargeStartAsFirstFrame(t *testing.T) {
	profile := classifyRequestRange(http.MethodGet, "bytes=2097152-4194304")
	if !profile.HasRange {
		t.Fatal("expected range profile")
	}
	if profile.IsFirstFrameHint {
		t.Fatalf("did not expect first-frame hint, got %#v", profile)
	}
}

func TestInitialPlaybackHintCoversRealPlayerRequestShapes(t *testing.T) {
	for _, rangeHeader := range []string{"", "bytes=0-", "bytes=48-", "bytes=65536-1048575"} {
		if !IsInitialPlaybackHint(http.MethodGet, rangeHeader) {
			t.Errorf("range %q was not recognized as initial playback", rangeHeader)
		}
	}
	if IsInitialPlaybackHint(http.MethodHead, "") {
		t.Fatal("HEAD must not be treated as initial playback")
	}
	if IsInitialPlaybackHint(http.MethodGet, "bytes=4194304-") {
		t.Fatal("large seek must not be treated as initial playback")
	}
}

func TestProbeRangeCompatibilityOnlyReportsDefinitiveResult(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true

	sp := NewStreamProxy(cfg)
	sp.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Header:     http.Header{"Content-Range": []string{"bytes 0-0/10"}},
			Body:       io.NopCloser(strings.NewReader("x")),
			Request:    r,
		}, nil
	})
	if !sp.ProbeRangeCompatibility(t.Context(), "https://example.test/video", nil, "/encrypt") {
		t.Fatal("expected valid 206 response to be a definitive probe")
	}

	unauthorized := NewStreamProxy(cfg)
	unauthorized.client = newTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("unauthorized")),
			Request:    r,
		}, nil
	})
	if unauthorized.ProbeRangeCompatibility(t.Context(), "https://example.test/video", nil, "/encrypt") {
		t.Fatal("401 must not be counted as a completed range probe")
	}
}

func TestSelectOptimalStrategyUsesChunkedForOpenEndedFirstFrameOnIncompatibleProvider(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 1
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	err := sp.compatStore.Upsert(key, RangeCompatState{
		Incompatible: true,
		NextProbeAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to seed compat store: %v", err)
	}

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=0-")
	if got != StreamStrategyChunked {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyChunked)
	}
}

func TestSelectOptimalStrategyReusesRecentChunkedHint(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 8 * 1024 * 1024
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	err := sp.compatStore.Upsert(key, RangeCompatState{
		Incompatible: true,
		NextProbeAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to seed compat store: %v", err)
	}
	sp.RecordPlaybackHint("https://example.com/file", "/encrypt/movie.mkv", StreamStrategyChunked)

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=1048576-2097151")
	if got != StreamStrategyChunked {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyChunked)
	}
}

func TestSelectOptimalStrategyDoesNotReuseChunkedHintForLargeSeek(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.ChunkedSeekMaxDiscardBytes = 1024
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	err := sp.compatStore.Upsert(key, RangeCompatState{
		Incompatible: true,
		NextProbeAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to seed compat store: %v", err)
	}
	sp.RecordPlaybackHint("https://example.com/file", "/encrypt/movie.mkv", StreamStrategyChunked)

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=4096-")
	if got != StreamStrategyFull {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyFull)
	}
}

func TestSelectOptimalStrategyDoesNotReuseFullHintWhenRangeCompatible(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	sp := NewStreamProxy(cfg)

	sp.RecordPlaybackHint("https://example.com/file", "/encrypt/movie.mkv", StreamStrategyFull)

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=4096-8191")
	if got != StreamStrategyRange {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyRange)
	}
}

func TestSelectOptimalStrategyDoesNotReuseFullHintForFirstFrame(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	err := sp.compatStore.Upsert(key, RangeCompatState{
		Incompatible: true,
		NextProbeAt:  time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("failed to seed compat store: %v", err)
	}
	sp.RecordPlaybackHint("https://example.com/file", "/encrypt/movie.mkv", StreamStrategyFull)

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=0-")
	if got != StreamStrategyChunked {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyChunked)
	}
}

func TestSelectOptimalStrategyIgnoresExpiredPlaybackHint(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	sp := NewStreamProxy(cfg)

	key := sp.rangeCompatKey("https://example.com/file", "/encrypt/movie.mkv")
	if key == "" {
		t.Fatal("empty compat key")
	}
	sp.playbackHints[key] = recentPlaybackHint{
		Strategy:  StreamStrategyChunked,
		UpdatedAt: time.Now().Add(-recentPlaybackHintTTL - time.Second),
	}

	got := sp.SelectOptimalStrategy("https://example.com/file", "/encrypt/movie.mkv", http.MethodGet, "bytes=1048576-2097151")
	if got != StreamStrategyRange {
		t.Fatalf("strategy=%s, want %s", got, StreamStrategyRange)
	}
}
