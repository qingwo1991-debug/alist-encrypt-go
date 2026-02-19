package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
)

func TestRangeCompatDowngradeAfterConsecutivePseudoRangeFailures(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableRangeCompatCache = true
	cfg.AlistServer.RangeReprobeMinutes = 30
	sp := NewStreamProxy(cfg)

	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", 10)))
	}))
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/test.bin", nil)
	req.Header.Set("Range", "bytes=0-0")
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	result1 := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), req, ts.URL, passwd, 10, StreamStrategyRange, "/encrypt")
	if result1.FailureReason != "range_unsupported" || !result1.Retryable {
		t.Fatalf("first failure reason=%q retryable=%v", result1.FailureReason, result1.Retryable)
	}

	result2 := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), req, ts.URL, passwd, 10, StreamStrategyRange, "/encrypt")
	if result2.FailureReason != "range_unsupported" || !result2.Retryable {
		t.Fatalf("second failure reason=%q retryable=%v", result2.FailureReason, result2.Retryable)
	}

	before := hits
	result3 := sp.ProxyDownloadDecryptWithStrategyForStorage(httptest.NewRecorder(), req, ts.URL, passwd, 10, StreamStrategyRange, "/encrypt")
	if result3.FailureReason != "range_unsupported" || !result3.Retryable {
		t.Fatalf("third failure reason=%q retryable=%v", result3.FailureReason, result3.Retryable)
	}
	if hits != before {
		t.Fatalf("expected third request to skip upstream, hits=%d before=%d", hits, before)
	}
}

func TestPassthroughStatusNoLearning(t *testing.T) {
	cfg := config.DefaultConfig()
	sp := NewStreamProxy(cfg)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer ts.Close()

	req := httptest.NewRequest(http.MethodGet, "/d/missing.bin", nil)
	rr := httptest.NewRecorder()
	passwd := &config.PasswdInfo{
		Password: "123456",
		EncType:  "aesctr",
		Enable:   true,
	}

	result := sp.ProxyDownloadDecryptWithStrategyForStorage(rr, req, ts.URL, passwd, 123, StreamStrategyRange, "/encrypt")
	if result.Err != nil {
		t.Fatalf("unexpected err: %v", result.Err)
	}
	if !result.NoLearning {
		t.Fatalf("expected no-learning=true for 404 passthrough")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNotFound)
	}
}
