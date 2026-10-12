package utils

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryContextStopsBackoffAndAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	var calls atomic.Int64
	done := make(chan error, 1)
	go func() {
		done <- RetryContext(ctx, 3, time.Hour, func() error { calls.Add(1); close(entered); return errors.New("fixture") })
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("backoff not canceled")
	}
	if calls.Load() != 1 {
		t.Fatal("attempt continued after cancellation")
	}
}
func TestRetryContextPreservesAttemptsAndError(t *testing.T) {
	sentinel := errors.New("fixture")
	calls := 0
	err := RetryContext(context.Background(), 3, 0, func() error { calls++; return sentinel })
	if calls != 3 || !errors.Is(err, sentinel) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls = 0
	if err := RetryContext(ctx, 3, 0, func() error { calls++; return nil }); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal(err, calls)
	}
}
