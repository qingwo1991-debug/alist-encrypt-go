package mega

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type cancelDownload struct {
	entered     chan struct{}
	finishCalls atomic.Int64
	finishErr   error
}

func (d *cancelDownload) Chunks() int                           { return 1 }
func (d *cancelDownload) ChunkLocation(int) (int64, int, error) { return 0, 16, nil }
func (d *cancelDownload) DownloadChunkContext(ctx context.Context, id int) ([]byte, error) {
	close(d.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (d *cancelDownload) Finish() error { d.finishCalls.Add(1); return d.finishErr }
func TestMegaConcurrentCloseCancelsReadBeforeLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &cancelDownload{entered: make(chan struct{})}
	oo := &openObject{ctx: ctx, cancel: cancel, d: d}
	done := make(chan error, 1)
	go func() { _, err := oo.Read(make([]byte, 1)); done <- err }()
	select {
	case <-d.entered:
	case <-time.After(time.Second):
		t.Fatal("Read did not enter actual operation")
	}
	closed := make(chan error, 1)
	go func() { closed <- oo.Close() }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close waits on lock without canceling Read")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not join Read")
	}
	if err := oo.Close(); err != nil {
		t.Fatal(err)
	}
	if d.finishCalls.Load() != 1 {
		t.Fatal("Finish not idempotent")
	}
}
func TestMegaCloseDoesNotRetryMutatingMAC(t *testing.T) {
	sentinel := errors.New("MAC mismatch")
	d := &cancelDownload{finishErr: sentinel}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oo := &openObject{ctx: ctx, cancel: cancel, d: d}
	for i := 0; i < 2; i++ {
		if err := oo.Close(); !errors.Is(err, sentinel) {
			t.Fatal(err)
		}
	}
	if d.finishCalls.Load() != 1 {
		t.Fatal("MAC verification retried")
	}
}
