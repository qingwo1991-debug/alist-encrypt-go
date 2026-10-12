// Package playbacktest provides loopback-only HTTP fixtures for playback acceptance
// tests. It has no dependency on proxy or encryption implementations.
package playbacktest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RangeMode string

const (
	RangeAccept RangeMode = "accept"
	RangeReject RangeMode = "reject"
	RangeIgnore RangeMode = "ignore"
)

// Behavior is immutable after New. Gates enable event-driven tests without sleeps.
// A nil gate is open; stalls remain blocked until request cancellation or Close.
// TruncateAfter, when positive, caps the body but retains its advertised length.
// BytesPerSecond paces ChunkBytes-sized writes; every wait observes cancellation.
type Behavior struct {
	Range          RangeMode
	Status         int
	Redirect       string
	Headers        http.Header
	HeaderGate     <-chan struct{}
	BodyGate       <-chan struct{}
	StallHeaders   bool
	StallBody      bool
	HeaderLatency  time.Duration
	ChunkLatency   time.Duration
	ChunkBytes     int
	BytesPerSecond int64
	TruncateAfter  int
}

type Request struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Range     string `json:"range"`
	Status    int    `json:"status"`
	BodyBytes int64  `json:"body_bytes"` // bytes accepted by server Write, not client read
	Canceled  bool   `json:"canceled"`
}
type Snapshot struct {
	RequestCount int       `json:"request_count"`
	BodyBytes    int64     `json:"body_bytes"`
	Requests     []Request `json:"requests"`
}

type Upstream struct {
	Server      *httptest.Server
	Started     <-chan struct{}
	HeadersSent <-chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	started     chan struct{}
	headers     chan struct{}
	startOnce   sync.Once
	headerOnce  sync.Once
	closeOnce   sync.Once
	mu          sync.Mutex
	requests    []Request
}

// New copies data and headers; routes is an optional path-specific behavior map.
// Unspecified paths use fallback. Redirect may be relative to this server.
func New(data []byte, fallback Behavior, routes map[string]Behavior) *Upstream {
	data = append([]byte(nil), data...)
	clone := func(b Behavior) Behavior { b.Headers = b.Headers.Clone(); return b }
	fallback = clone(fallback)
	copied := make(map[string]Behavior, len(routes))
	for path, b := range routes {
		copied[path] = clone(b)
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := &Upstream{ctx: ctx, cancel: cancel, started: make(chan struct{}), headers: make(chan struct{})}
	u.Started, u.HeadersSent = u.started, u.headers
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := fallback
		if route, ok := copied[r.URL.Path]; ok {
			b = route
		}
		u.mu.Lock()
		index := len(u.requests)
		u.requests = append(u.requests, Request{Method: r.Method, Path: r.URL.Path, Range: r.Header.Get("Range")})
		u.mu.Unlock()
		u.startOnce.Do(func() { close(u.started) })
		markCanceled := func() {
			u.mu.Lock()
			u.requests[index].Canceled = true
			u.mu.Unlock()
		}
		if !u.wait(r.Context(), b.HeaderGate, b.StallHeaders, b.HeaderLatency) {
			markCanceled()
			// Returning before headers would let net/http synthesize an empty
			// 200 response while Close races with CloseClientConnections. Abort
			// instead: canceled header stalls must never look like success.
			panic(http.ErrAbortHandler)
		}
		for k, values := range b.Headers {
			w.Header()[k] = append([]string(nil), values...)
		}
		status := b.Status
		body := data
		if b.Redirect != "" {
			w.Header().Set("Location", b.Redirect)
			if status == 0 {
				status = http.StatusTemporaryRedirect
			}
			body = nil
		} else if status != 0 && status != http.StatusOK {
			body = nil
		} else {
			status = http.StatusOK
			h := r.Header.Get("Range")
			if h != "" && b.Range != RangeIgnore {
				start, end, ok := parseRange(h, len(data))
				if b.Range == RangeReject || !ok {
					status = http.StatusRequestedRangeNotSatisfiable
					body = nil
					w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(data)))
				} else {
					status = http.StatusPartialContent
					body = data[start:end]
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end-1, len(data)))
				}
			}
			w.Header().Set("Accept-Ranges", "bytes")
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		u.mu.Lock()
		u.requests[index].Status = status
		u.mu.Unlock()
		w.WriteHeader(status)
		// Keep small, unpaced responses atomic from the client's perspective:
		// exposing headers before the first body write would make ignored-Range
		// accounting depend on whether the proxy closes immediately after headers.
		if b.StallBody || b.BodyGate != nil || b.ChunkLatency > 0 || b.BytesPerSecond > 0 || r.Method == http.MethodHead {
			w.(http.Flusher).Flush()
		}
		u.headerOnce.Do(func() { close(u.headers) })
		if r.Method == http.MethodHead {
			return
		}
		if !u.wait(r.Context(), b.BodyGate, b.StallBody, 0) {
			markCanceled()
			return
		}
		if b.TruncateAfter > 0 && len(body) > b.TruncateAfter {
			body = body[:b.TruncateAfter]
		}
		chunk := b.ChunkBytes
		if chunk <= 0 {
			chunk = 32 * 1024
		}
		for len(body) > 0 {
			n := min(chunk, len(body))
			delay := b.ChunkLatency
			if b.BytesPerSecond > 0 {
				delay += time.Duration(int64(n) * int64(time.Second) / b.BytesPerSecond)
			}
			if !u.wait(r.Context(), nil, false, delay) {
				markCanceled()
				return
			}
			written, err := w.Write(body[:n])
			u.mu.Lock()
			u.requests[index].BodyBytes += int64(written)
			u.mu.Unlock()
			w.(http.Flusher).Flush()
			if err != nil {
				if r.Context().Err() != nil || u.ctx.Err() != nil {
					markCanceled()
				}
				return
			}
			body = body[n:]
		}
	}))
	return u
}

func (u *Upstream) wait(ctx context.Context, gate <-chan struct{}, stall bool, delay time.Duration) bool {
	if stall {
		select {
		case <-ctx.Done():
			return false
		case <-u.ctx.Done():
			return false
		}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return false
		case <-u.ctx.Done():
			return false
		}
	}
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return false
		case <-u.ctx.Done():
			return false
		}
	}
	return ctx.Err() == nil && u.ctx.Err() == nil
}

// Close releases even header/body gates before waiting for handlers to exit.
func (u *Upstream) Close() {
	u.closeOnce.Do(func() { u.cancel(); u.Server.CloseClientConnections(); u.Server.Close() })
}
func (u *Upstream) URL(path string) string { return u.Server.URL + path }
func (u *Upstream) Snapshot() Snapshot {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := Snapshot{RequestCount: len(u.requests), Requests: append([]Request(nil), u.requests...)}
	for _, r := range s.Requests {
		s.BodyBytes += r.BodyBytes
	}
	return s
}

func parseRange(h string, size int) (int, int, bool) {
	if !strings.HasPrefix(h, "bytes=") || strings.Contains(h, ",") || size == 0 {
		return 0, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(h, "bytes="), "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	if parts[0] == "" {
		n, err := strconv.Atoi(parts[1])
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		return max(0, size-n), size, true
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 || start >= size {
		return 0, 0, false
	}
	end := size - 1
	if parts[1] != "" {
		end, err = strconv.Atoi(parts[1])
		if err != nil || end < start {
			return 0, 0, false
		}
		end = min(end, size-1)
	}
	return start, end + 1, true
}

// WriteJSON writes only to an explicit absolute path, never implicitly to cwd.
// The caller owns path selection (e.g. a CI artifact directory or t.TempDir).
func WriteJSON(path string, value any) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("artifact path must be absolute: %q", path)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}
