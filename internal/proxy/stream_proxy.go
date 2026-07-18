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
	req.ContentLength = r.ContentLength
	req.GetBody = r.GetBody

	// Retry only requests that are both safe and replayable. Reusing a consumed
	// upload/PROPFIND body sends an empty or truncated second request.
	var resp *http.Response
	var doErr error
	doRequest := func() error {
		attemptReq, cloneErr := cloneProxyAttempt(req)
		if cloneErr != nil {
			doErr = cloneErr
			return nil
		}
		resp, doErr = s.client.Do(attemptReq)
		if doErr != nil {
			if backoff.IsTransient(doErr) {
				return doErr
			}
			return nil
		}
		if backoff.IsTransientStatus(resp.StatusCode) {
			resp.Body.Close()
			doErr = &backoff.HTTPStatusError{StatusCode: resp.StatusCode}
			return doErr
		}
		return nil
	}
	if canRetryProxyRequest(req) {
		_ = s.retrier.Do(r.Context(), doRequest)
	} else {
		// A single attempt preserves the original body and upstream status. In
		// particular, a non-idempotent 5xx must not trigger a second write.
		resp, doErr = s.client.Do(req)
	}
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

func canRetryProxyRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		return false
	}
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func cloneProxyAttempt(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		clone.Body = req.Body
		return clone, nil
	}
	if req.GetBody == nil {
		return nil, fmt.Errorf("request body is not replayable")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("recreate request body: %w", err)
	}
	clone.Body = body
	return clone, nil
}
