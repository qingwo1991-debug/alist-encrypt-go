package singleflight

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDoContextWaiterCancellationKeepsSharedWork(t *testing.T) {
	var g Group[int]
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		v, err, _ := g.DoContext(context.Background(), "path", func() (int, error) {
			close(started)
			<-release
			return 42, nil
		})
		if err != nil || v != 42 {
			t.Errorf("leader: %d %v", v, err)
		}
	}()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err, shared := g.DoContext(ctx, "path", func() (int, error) {
		t.Error("duplicate work started")
		return 0, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || !shared {
		t.Fatalf("waiter: shared=%v err=%v", shared, err)
	}
	// Cancelled waiters must not forget the still-running key.
	result := g.DoChan("path", func() (int, error) { t.Error("shared work forgotten"); return 0, nil })
	close(release)
	select {
	case r := <-result:
		if r.Val != 42 || r.Err != nil || !r.Shared {
			t.Fatalf("result: %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("shared result did not arrive")
	}
	<-finished
}

func TestDoContextAlreadyCancelledDoesNotRun(t *testing.T) {
	var g Group[int]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err, _ := g.DoContext(ctx, "path", func() (int, error) { t.Fatal("ran cancelled work"); return 0, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
