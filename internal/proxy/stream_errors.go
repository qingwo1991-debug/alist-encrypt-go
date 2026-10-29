package proxy

import (
	"context"
	stderrors "errors"
	"io"
	"net"
	"strings"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/errors"
)

// streamFetchErrorOutcome preserves structured exhausted HTTP statuses for the
// orchestrator, rather than misclassifying a retryable 503 as a network error.
func streamFetchErrorOutcome(err error) *StreamOutcome {
	reason, retryable := classifyStreamError(err)
	result := &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	var statusErr *backoff.HTTPStatusError
	if stderrors.As(err, &statusErr) {
		result.StatusCode = statusErr.StatusCode
		result.NoLearning = true
		result.Retryable = backoff.IsTransientStatus(statusErr.StatusCode)
		if statusErr.StatusCode >= 500 {
			result.FailureReason = "upstream_5xx"
		} else {
			result.FailureReason = "upstream_4xx"
		}
	}
	return result
}

// streamReadError marks errors returned by the copy's reader, not its writer.
// Keep the original error available to errors.Is/As without guessing its source
// from the message (a downstream writer can also return ErrUnexpectedEOF).
type streamReadError struct{ err error }

func (e *streamReadError) Error() string { return "stream read: " + e.err.Error() }
func (e *streamReadError) Unwrap() error { return e.err }

type streamCopyReader struct{ io.Reader }

func (r streamCopyReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		err = &streamReadError{err: err}
	}
	return n, err
}

// copyStreamBody preserves the read/write error boundary even when src or dst
// implements WriterTo/ReaderFrom. A writer failure wins over a simultaneous read
// failure, just as in io.CopyBuffer. Only a successful copy may synthesize a
// short-body error; receiving every expected byte never erases a real error.
func copyStreamBody(dst io.Writer, src io.Reader, buf []byte, expected int64) (int64, error) {
	written, err := io.CopyBuffer(struct{ io.Writer }{dst}, streamCopyReader{src}, buf)
	if err == nil && expected > 0 && written < expected {
		err = &streamReadError{err: io.ErrUnexpectedEOF}
	}
	return written, err
}

// classifyStreamCopyError is only for a failed body copy. The request's context
// wins cancellation races with transport EOF, but a transport error alone is not
// evidence that the request was canceled. Deadlines remain timeout failures.
func classifyStreamCopyError(ctx context.Context, err error) errors.FailureReason {
	if ctxErr := ctx.Err(); ctxErr != nil {
		reason, _ := classifyStreamError(ctxErr)
		return reason
	}
	var readErr *streamReadError
	if stderrors.As(err, &readErr) && stderrors.Is(readErr, io.ErrUnexpectedEOF) {
		return "upstream_truncated"
	}
	reason, _ := classifyStreamError(err)
	return reason
}

func classifyStreamError(err error) (errors.FailureReason, bool) {
	if err == nil {
		return "", false
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return errors.ReasonTimeout, false
	}
	// NetworkListOps routinely cancel the previous request when seeking. Treat
	// that as a client-side disconnect, not an upstream network failure.
	if stderrors.Is(err, context.Canceled) || stderrors.Is(err, net.ErrClosed) {
		return errors.ReasonClientDisconnect, false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer") {
		return errors.ReasonClientDisconnect, false
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) {
		if netErr.Timeout() {
			return errors.ReasonTimeout, false
		}
		return errors.ReasonNetworkError, false
	}
	if strings.Contains(msg, "timeout") {
		return errors.ReasonTimeout, false
	}
	return errors.ReasonNetworkError, false
}
