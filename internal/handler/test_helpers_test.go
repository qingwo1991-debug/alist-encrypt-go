package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newHTTPClientFromHandler(h http.Handler) *http.Client {
	return &http.Client{
		Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			return rr.Result(), nil
		}),
	}
}

func newSocketTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Skipf("skipping test; socket listener unavailable in this environment: %v", r)
		}
	}()
	return httptest.NewServer(h)
}
