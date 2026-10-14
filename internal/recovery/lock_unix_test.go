//go:build unix

package recovery

import (
	"context"
	"testing"
	"time"
)

func TestLifetimeOwnership(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	first, err := Acquire(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	blocked, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if l, err := Acquire(blocked, dir); err == nil {
		l.Close()
		t.Fatal("second owner admitted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	first.Close()
	next, err := Acquire(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
