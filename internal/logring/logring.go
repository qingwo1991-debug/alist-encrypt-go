// Package logring provides a small concurrency-safe in-memory ring buffer of
// the most recent log lines. It backs the debug /debug/logs endpoint so recent
// runtime log output can be pulled over HTTP for remote troubleshooting without
// touching the container filesystem.
package logring

import (
	"strings"
	"sync"
)

// Ring retains the most recent complete log lines. It is safe for concurrent
// use by the zerolog output chain and by HTTP handlers.
type Ring struct {
	mu      sync.Mutex
	lines   []string
	max     int
	pending string
}

// NewRing returns an empty ring that keeps at most maxLines recent lines.
// max <= 0 is normalized to 1 to keep the buffer trivially usable.
func NewRing(maxLines int) *Ring {
	if maxLines <= 0 {
		maxLines = 1
	}
	return &Ring{max: maxLines}
}

// Write implements io.Writer. It splits p into lines, keeping partial trailing
// input buffered until the next newline arrives, and retains the most recent
// max complete lines. ANSI escape sequences are stripped so the served text is
// clean for tooling/AI consumption.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var s string
	if r.pending != "" {
		s = r.pending + string(p)
		r.pending = ""
	} else {
		s = string(p)
	}

	lastNL := strings.LastIndexByte(s, '\n')
	if lastNL < 0 {
		// Whole write is a partial line; buffer until a newline arrives.
		r.pending = s
		return len(p), nil
	}
	for _, ln := range strings.Split(s[:lastNL], "\n") {
		ln = stripANSI(strings.TrimRight(ln, "\r"))
		if ln == "" {
			continue
		}
		r.lines = append(r.lines, ln)
	}
	if tail := s[lastNL+1:]; tail != "" {
		r.pending = tail
	}
	r.trimToMax()
	return len(p), nil
}

func (r *Ring) trimToMax() {
	if len(r.lines) > r.max {
		r.lines = append([]string(nil), r.lines[len(r.lines)-r.max:]...)
	}
}

// Tail returns up to n most recent complete lines, oldest first / newest last.
// It never mutates the ring.
func (r *Ring) Tail(n int) []string {
	if n <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) <= n {
		out := make([]string, len(r.lines))
		copy(out, r.lines)
		return out
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}

// Len reports how many complete lines are currently retained.
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lines)
}

// stripANSI removes common ANSI SGR escape sequences (colors/styles).
func stripANSI(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == ';') {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
