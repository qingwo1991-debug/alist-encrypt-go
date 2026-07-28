package handler

import (
	"context"
	"testing"
	"time"
)

func TestAlistHandlerStopCancelsAndJoinsDirSyncWork(t *testing.T) {
	h := &AlistHandler{}
	started := make(chan struct{})
	finished := make(chan struct{})
	if !h.startDirSyncWork(func(ctx context.Context) {
		close(started)
		<-ctx.Done()
		close(finished)
	}) {
		t.Fatal("failed to start directory sync work")
	}

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("directory sync work did not start")
	}
	h.Stop()
	h.Stop()

	select {
	case <-finished:
	default:
		t.Fatal("Stop returned before directory sync work finished")
	}
	if h.startDirSyncWork(func(context.Context) {}) {
		t.Fatal("directory sync work started after Stop")
	}
}
