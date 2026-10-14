package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// endpointGeneration owns every prepared endpoint until BOTH stop and Serve have
// completed. Admission and preparation share the seal mutex: Stop cannot miss a
// socket being prepared, and no preparation is admitted after the seal.
// This file deliberately uses only the standard library for focused race tests.
type endpointGeneration struct {
	mu        sync.Mutex
	sealed    bool
	endpoints []*ownedEndpoint
}

type ownedEndpoint struct {
	name     string
	done     chan struct{}
	stop     func(context.Context) error
	stopping chan struct{}
	stopErr  error
	stopped  bool
	running  bool
}

// start registers ownership before launching Serve. prepare must not invoke user
// hooks. ready is for APIs that can only bind inside Serve (SFTP); it waits for
// that bind while admission remains locked, before Stop can observe the endpoint.
func (g *endpointGeneration) start(name string, prepare func() error, serve func() error, stop func(context.Context) error, ready func() error, notify func(error)) bool {
	g.mu.Lock()
	if g.sealed {
		g.mu.Unlock()
		return false
	}
	e := &ownedEndpoint{name: name, done: make(chan struct{}), stop: stop}
	g.endpoints = append(g.endpoints, e)
	if prepare != nil {
		if err := prepare(); err != nil {
			e.stopped = true // prepare is responsible for undoing partial allocation.
			close(e.done)
			g.mu.Unlock()
			if notify != nil {
				go notify(err)
			}
			return true
		}
	}
	e.running = true
	go func() {
		// A prepared listener or a server with a permanent Shutdown seal is
		// required: scheduling this goroutine after stop must never bind anew.
		err := serve()
		g.mu.Lock()
		e.running = false
		close(e.done)
		g.mu.Unlock()
		// Hooks may synchronously call Shutdown. Never count callbacks as Serve
		// ownership or execute them under the admission mutex.
		if notify != nil {
			go notify(err)
		}
	}()
	if ready != nil {
		if err := ready(); err != nil {
			// No socket was established. SFTP Close would dereference the
			// nil listener published after a failed bind.
			e.stopped = true
		}
	} // Serve reports the actual start error.
	g.mu.Unlock()
	return true
}

func (g *endpointGeneration) isRunning(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.endpoints {
		if e.name == name {
			return e.running
		}
	}
	return false
}

// drain seals admission, stops all captured endpoints in parallel, and joins
// Serve before success. A timeout retains the generation, including in-flight
// stop calls; a retry joins those calls rather than issuing concurrent Stop.
func (g *endpointGeneration) drain(ctx context.Context) error {
	g.mu.Lock()
	g.sealed = true
	endpoints := append([]*ownedEndpoint(nil), g.endpoints...)
	for _, e := range endpoints {
		if e.stopped {
			continue
		}
		if e.stopping != nil {
			select {
			case <-e.stopping:
				e.stopping = nil // completed failed stop: retry
			default:
				continue // still owned by the previous drain attempt
			}
		}
		e.stopping = make(chan struct{})
		go func(e *ownedEndpoint) {
			err := e.stop(ctx)
			g.mu.Lock()
			e.stopErr = err
			e.stopped = err == nil
			close(e.stopping)
			g.mu.Unlock()
		}(e)
	}
	g.mu.Unlock()
	var failures []error
	for _, e := range endpoints {
		g.mu.Lock()
		stopped, stopping := e.stopped, e.stopping
		g.mu.Unlock()
		if !stopped {
			select {
			case <-stopping:
			case <-ctx.Done():
				return ctx.Err()
			}
			g.mu.Lock()
			err := e.stopErr
			if err != nil {
				e.stopping = nil
			}
			g.mu.Unlock()
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", e.name, err))
			}
		}
		select {
		case <-e.done:
		case <-ctx.Done():
			return errors.Join(append(failures, ctx.Err())...)
		}
	}
	return errors.Join(failures...)
}
