package httputil

import (
	"io"
	"sync"
	"time"
)

// IdleBody bounds an individual blocked Read, not the lifetime of a video or
// time spent writing to a slow player. Closing the source interrupts net/http
// response bodies without spawning an additional reader goroutine.
type IdleBody struct {
	source    io.ReadCloser
	timeout   time.Duration
	closeOnce sync.Once
	closeErr  error
}

type BodyIdleTimeoutError struct{}

func (BodyIdleTimeoutError) Error() string {
	return "upstream response body made no progress before idle deadline"
}
func (BodyIdleTimeoutError) Timeout() bool   { return true }
func (BodyIdleTimeoutError) Temporary() bool { return true }

func NewIdleBody(source io.ReadCloser, timeout time.Duration) io.ReadCloser {
	if source == nil || timeout <= 0 {
		return source
	}
	return &IdleBody{source: source, timeout: timeout}
}
func (b *IdleBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return b.source.Read(p)
	}
	var mu sync.Mutex
	finished, expired := false, false
	timer := time.AfterFunc(b.timeout, func() {
		mu.Lock()
		if finished {
			mu.Unlock()
			return
		}
		expired = true
		mu.Unlock()
		_ = b.Close()
	})
	n, err := b.source.Read(p)
	mu.Lock()
	finished = true
	timedOut := expired
	mu.Unlock()
	timer.Stop()
	if timedOut {
		return n, BodyIdleTimeoutError{}
	}
	return n, err
}
func (b *IdleBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.source.Close() })
	return b.closeErr
}
