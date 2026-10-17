package mega

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"
)

// operationContext links each real request to both the caller and session.
// AfterFunc creates no goroutine while waiting; a cancellation callback only
// invokes cancel, never performs or abandons network work.
func (m *Mega) operationContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	m.lifeMu.Lock()
	if m.closed {
		m.lifeMu.Unlock()
		cancel()
		return ctx, cancel
	}
	m.opWG.Add(1)
	m.lifeMu.Unlock()
	stop := context.AfterFunc(m.lifeCtx, cancel)
	if m.lifeCtx.Err() != nil {
		cancel()
	}
	var once sync.Once
	return ctx, func() { once.Do(func() { stop(); cancel(); m.opWG.Done() }) }
}
func (m *Mega) requestContext(ctx context.Context, method, url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return m.client.Do(req)
}
func backOffContext(ctx context.Context, delay *time.Duration) error {
	timer := time.NewTimer(*delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	*delay *= 2
	if *delay > maxSleepTime {
		*delay = maxSleepTime
	}
	return ctx.Err()
}
func (m *Mega) startPoller() {
	m.lifeMu.Lock()
	defer m.lifeMu.Unlock()
	if m.closed || m.pollStarted {
		return
	}
	m.pollStarted = true
	m.pollWG.Add(1)
	go func() { defer m.pollWG.Done(); m.pollEvents() }()
}

// Close cancels actual session HTTP and joins the event poller. It never waits
// on a mutex held by network I/O, and successful login's session outlives the
// caller's login deadline until this explicit owner shutdown.
// CancelSession closes admission and cancels real I/O, without pretending to
// join it. The generation owner calls Close to join before retiring resources.
func (m *Mega) CancelSession() {
	m.lifeMu.Lock()
	m.closed = true
	m.lifeCancel()
	m.lifeMu.Unlock()
}
func (m *Mega) Close() error {
	m.CancelSession()
	m.pollWG.Wait()
	m.opWG.Wait()
	m.waitEventsFire()
	m.client.CloseIdleConnections()
	return nil
}
