package proxy

import (
	"context"
	stderrors "errors"
	"net"
	"strings"

	"github.com/alist-encrypt-go/internal/errors"
)

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
