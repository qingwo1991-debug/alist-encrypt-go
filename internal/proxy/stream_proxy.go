package proxy

import (
	"fmt"
	"io"
	"net/http"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
)

// ProxyRequest forwards a request to the target and copies response
func (s *StreamProxy) ProxyRequest(w http.ResponseWriter, r *http.Request, targetURL string) error {
	if !s.cbGate.Allow() {
		return errors.NewProxyError("upstream temporarily unavailable (circuit open)")
	}

	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}

	// Retry transient network errors with jittered exponential backoff
	var resp *http.Response
	var doErr error
	_ = s.retrier.Do(r.Context(), func() error {
		resp, doErr = s.client.Do(req)
		if doErr != nil {
			if backoff.IsTransient(doErr) {
				return doErr
			}
			return nil
		}
		if backoff.IsTransientStatus(resp.StatusCode) {
			resp.Body.Close()
			doErr = fmt.Errorf("upstream status %d", resp.StatusCode)
			return doErr
		}
		return nil
	})
	if doErr != nil {
		s.cbGate.RecordFailure()
		return errors.NewProxyErrorWithCause("failed to proxy request", doErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		s.cbGate.RecordFailure()
	} else {
		s.cbGate.RecordSuccess()
	}

	// Copy response headers and write response
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Stream response body with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, resp.Body, *buf)
	return err
}
