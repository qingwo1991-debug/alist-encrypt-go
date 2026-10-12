package encrypt

import (
	"context"
	"net/http"
	"sync"
)

// All additions and sealing share one fence. Wait is only entered after sealing;
// no goroutine is abandoned merely because its caller stopped waiting.
type proxyLifecycle struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	sealed     bool
	background sync.WaitGroup
	handlers   sync.WaitGroup
}

func (p *ProxyServer) lifetime() *proxyLifecycle {
	p.lifecycleOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		p.lifecycle = &proxyLifecycle{ctx: ctx, cancel: cancel}
	})
	return p.lifecycle
}
func (p *ProxyServer) backgroundContext() context.Context { return p.lifetime().ctx }
func (p *ProxyServer) goBackground(fn func(context.Context)) bool {
	l := p.lifetime()
	l.mu.Lock()
	if l.sealed {
		l.mu.Unlock()
		return false
	}
	l.background.Add(1)
	l.mu.Unlock()
	go func() { defer l.background.Done(); fn(l.ctx) }()
	return true
}
func (p *ProxyServer) sealLifetime() {
	l := p.lifetime()
	l.mu.Lock()
	l.sealed = true
	l.cancel()
	l.mu.Unlock()
}
func (p *ProxyServer) lifetimeClosed() bool {
	l := p.lifetime()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sealed
}
func (p *ProxyServer) guardHandlers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := p.lifetime()
		l.mu.Lock()
		if l.sealed {
			l.mu.Unlock()
			http.Error(w, "proxy is stopping", http.StatusServiceUnavailable)
			return
		}
		l.handlers.Add(1)
		l.mu.Unlock()
		defer l.handlers.Done()
		next.ServeHTTP(w, r)
	})
}
