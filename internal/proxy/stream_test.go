package proxy

import (
	"context"
	"net"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyStreamErrorTimeout(t *testing.T) {
	reason, retryable := classifyStreamError(context.DeadlineExceeded)
	if reason != "timeout" {
		t.Fatalf("expected timeout reason, got %q", reason)
	}
	if retryable {
		t.Fatalf("expected retryable=false for timeout")
	}

	var err net.Error = timeoutErr{}
	reason, retryable = classifyStreamError(err)
	if reason != "timeout" {
		t.Fatalf("expected timeout reason for net.Error, got %q", reason)
	}
	if retryable {
		t.Fatalf("expected retryable=false for net.Error timeout")
	}
}
