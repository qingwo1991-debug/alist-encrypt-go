package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/config"
)

type proxyRoundTripFunc func(*http.Request) (*http.Response, error)

func (f proxyRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newProxyForRoundTripper(rt http.RoundTripper) *StreamProxy {
	p := NewStreamProxy(config.DefaultConfig())
	p.client = &Client{Client: &http.Client{Transport: rt}}
	p.retrier = backoff.DefaultRetrier()
	p.retrier.MaxRetries = 2
	p.retrier.Initial = time.Millisecond
	p.retrier.Max = time.Millisecond
	p.retrier.Jitter = 0
	return p
}

func TestProxyRequestDoesNotRetryConsumedBody(t *testing.T) {
	var calls atomic.Int32
	p := newProxyForRoundTripper(proxyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if string(body) != "request-body" {
			t.Fatalf("body = %q, want request-body", body)
		}
		return nil, errors.New("connection reset by peer")
	}))

	req := httptest.NewRequest(http.MethodPost, "http://proxy.test/api", bytes.NewBufferString("request-body"))
	err := p.ProxyRequest(httptest.NewRecorder(), req, "http://upstream.test/api")
	if err == nil {
		t.Fatal("expected proxy error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}

func TestProxyRequestRetriesBodylessSafeRequest(t *testing.T) {
	var calls atomic.Int32
	p := newProxyForRoundTripper(proxyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("connection reset by peer")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("ok")),
			Request:    req,
		}, nil
	}))

	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/file", nil)
	w := httptest.NewRecorder()
	if err := p.ProxyRequest(w, req, "http://upstream.test/file"); err != nil {
		t.Fatalf("ProxyRequest: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2", got)
	}
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", w.Code, w.Body.String())
	}
}

func TestProxyRequestRetriesTransientStatus(t *testing.T) {
	var calls atomic.Int32
	p := newProxyForRoundTripper(proxyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		status := http.StatusServiceUnavailable
		body := "retry"
		if calls.Add(1) > 1 {
			status = http.StatusOK
			body = "ok"
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString(body)),
			Request:    req,
		}, nil
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://proxy.test/file", nil)
	if err := p.ProxyRequest(w, req, "http://upstream.test/file"); err != nil {
		t.Fatalf("ProxyRequest: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream calls = %d, want 2", got)
	}
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("response = %d %q, want 200 ok", w.Code, w.Body.String())
	}
}

func TestProxyRequestForwardsNonRetryableStatus(t *testing.T) {
	var calls atomic.Int32
	p := newProxyForRoundTripper(proxyRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBufferString("retry later")),
			Request:    req,
		}, nil
	}))

	req := httptest.NewRequest(http.MethodPut, "http://proxy.test/file", bytes.NewBufferString("payload"))
	w := httptest.NewRecorder()
	if err := p.ProxyRequest(w, req, "http://upstream.test/file"); err != nil {
		t.Fatalf("ProxyRequest: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != "retry later" {
		t.Fatalf("response = %d %q, want 503 retry later", w.Code, w.Body.String())
	}
}
