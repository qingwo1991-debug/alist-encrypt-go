package handler

import (
	"context"
	"sync"
	"time"
)

// ForegroundTracker pauses new background work while actual playback requests
// are in flight. It does not cancel or pretend to preempt already running work.
// A nil tracker, or a disabled profile, preserves the standard pipeline.
type ForegroundTracker struct {
	mu      sync.Mutex
	active  int
	changed chan struct{}
	enabled func() bool
}

func NewForegroundTracker(enabled func() bool) *ForegroundTracker {
	return &ForegroundTracker{enabled: enabled, changed: make(chan struct{})}
}

func (f *ForegroundTracker) Enabled() bool { return f != nil && f.enabled != nil && f.enabled() }

func (f *ForegroundTracker) Begin() func() {
	if !f.Enabled() {
		return func() {}
	}
	f.mu.Lock()
	f.active++
	close(f.changed)
	f.changed = make(chan struct{})
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.active--
			close(f.changed)
			f.changed = make(chan struct{})
			f.mu.Unlock()
		})
	}
}

func (f *ForegroundTracker) state() (bool, <-chan struct{}) {
	if !f.Enabled() {
		return false, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active > 0, f.changed
}

// WaitBackground is an admission boundary, not a CPU cancellation boundary.
func (f *ForegroundTracker) WaitBackground(ctx context.Context) error {
	// A profile change does not finish an active streaming request. Recheck the
	// mode periodically so disabling this policy cannot block scans until EOF.
	// One timer per actual blocked waiter; no polling goroutine is retained.
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		busy, changed := f.state()
		if !busy {
			return nil
		}
		if timer == nil {
			timer = time.NewTimer(250 * time.Millisecond)
		} else {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(250 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		case <-timer.C:
		}
	}
}

// NewProbeScheduler starts its workers before server wiring is complete. Publish
// the tracker atomically, and wake dispatchers so replacing a busy tracker cannot
// leave them blocked on the previous tracker's change channel.
func (ps *ProbeScheduler) SetForegroundTracker(f *ForegroundTracker) {
	ps.foreground.Store(f)
	ps.queueMu.Lock()
	ps.notifyDispatchLocked()
	ps.queueMu.Unlock()
}
func (h *AlistHandler) SetForegroundTracker(f *ForegroundTracker)  { h.foreground = f }
func (h *WebDAVHandler) SetForegroundTracker(f *ForegroundTracker) { h.foreground = f }
