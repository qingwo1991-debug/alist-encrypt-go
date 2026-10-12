package httputil

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestIdleBodyInterruptsStalledRead(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	body := NewIdleBody(r, 20*time.Millisecond)
	defer body.Close()
	done := make(chan error, 1)
	go func() { _, err := body.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		var timeout BodyIdleTimeoutError
		if !errors.As(err, &timeout) {
			t.Fatalf("expected idle timeout, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stalled read not interrupted")
	}
}

func TestIdleBodyDoesNotTimeOutBetweenReads(t *testing.T) {
	r, w := io.Pipe()
	body := NewIdleBody(r, 20*time.Millisecond)
	defer body.Close()
	defer w.Close()
	// Simulate a player doing slow processing/writing without an outstanding read.
	time.Sleep(50 * time.Millisecond)
	go func() { _, _ = w.Write([]byte("ab")) }()
	buf := make([]byte, 2)
	n, err := body.Read(buf)
	if n != 2 || err != nil || string(buf) != "ab" {
		t.Fatalf("healthy read: n=%d err=%v data=%q", n, err, buf)
	}
}

func TestIdleBodyCloseInterruptsRead(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	body := NewIdleBody(r, time.Hour)
	done := make(chan error, 1)
	go func() { _, err := body.Read(make([]byte, 1)); done <- err }()
	_ = body.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected close error")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not interrupt read")
	}
}
