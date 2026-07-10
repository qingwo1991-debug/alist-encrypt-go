package proxy

import (
	"context"
	stderrors "errors"
	"net"
	"strings"
)

func classifyStreamError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return "timeout", false
	}
	// Media players routinely cancel the previous request when seeking. Treat
	// that as a client-side disconnect, not an upstream network failure.
	if stderrors.Is(err, context.Canceled) || stderrors.Is(err, net.ErrClosed) {
		return "client_disconnect", false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer") {
		return "client_disconnect", false
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout", false
		}
		return "network_error", false
	}
	if strings.Contains(msg, "timeout") {
		return "timeout", false
	}
	return "network_error", false
}
