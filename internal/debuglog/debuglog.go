// Package debuglog hosts the process-wide log ring used by the /debug endpoints.
// The main entrypoint installs the ring when debug mode is enabled; the HTTP
// handlers read from it without knowing who installed it.
package debuglog

import (
	"sync"

	"github.com/alist-encrypt-go/internal/logring"
)

var (
	mu   sync.RWMutex
	ring *logring.Ring
)

// SetRing installs the log ring backing /debug/logs. Only the process
// entrypoint should call this (once, when debug mode is enabled).
func SetRing(r *logring.Ring) {
	mu.Lock()
	defer mu.Unlock()
	ring = r
}

// Ring returns the installed log ring (nil when debug mode is disabled).
func Ring() *logring.Ring {
	mu.RLock()
	defer mu.RUnlock()
	return ring
}

// Tail returns up to n recent log lines (newest last), or nil when no ring is
// installed.
func Tail(n int) []string {
	r := Ring()
	if r == nil {
		return nil
	}
	return r.Tail(n)
}
