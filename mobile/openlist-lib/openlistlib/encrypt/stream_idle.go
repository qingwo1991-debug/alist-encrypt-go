package encrypt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// No wall-clock deadline on a video. Only a pending upstream Read can time out;
// player pauses / downstream backpressure between reads do not consume a budget.
const mobileStreamReadIdleTimeout = 30 * time.Second

type streamIdleRoundTripper struct {
	base    http.RoundTripper
	timeout time.Duration
}

func (rt *streamIdleRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet || rt.timeout <= 0 {
		return rt.base.RoundTrip(req)
	}
	ctx, cancel := context.WithCancel(req.Context())
	resp, err := rt.base.RoundTrip(req.Clone(ctx))
	if err != nil {
		cancel()
		return resp, err
	}
	if resp.Body == nil || resp.Body == http.NoBody {
		cancel()
		return resp, nil
	}
	resp.Body = &streamIdleBody{ReadCloser: resp.Body, cancel: cancel, timeout: rt.timeout}
	return resp, nil
}

type streamIdleBody struct {
	io.ReadCloser
	cancel    context.CancelFunc
	timeout   time.Duration
	closeOnce sync.Once
}

func (b *streamIdleBody) Close() error {
	b.closeOnce.Do(b.cancel)
	return b.ReadCloser.Close()
}

func (b *streamIdleBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return b.ReadCloser.Read(p)
	}
	var mu sync.Mutex
	finished, expired := false, false
	timer := time.AfterFunc(b.timeout, func() {
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			expired = true
			b.cancel()
		}
	})
	n, err := b.ReadCloser.Read(p)
	mu.Lock()
	finished = true
	timedOut := expired
	mu.Unlock()
	timer.Stop()
	if timedOut {
		return n, fmt.Errorf("upstream body read idle for %s: %w", b.timeout, context.DeadlineExceeded)
	}
	return n, err
}
