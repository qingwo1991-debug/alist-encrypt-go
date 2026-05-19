package backoff

import (
	"context"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Retrier handles exponential backoff retries for transient failures.
type Retrier struct {
	MaxRetries int
	Initial    time.Duration
	Max        time.Duration
	Jitter     float64 // ±jitter ratio, e.g. 0.25 = ±25%
	rng        *rand.Rand
}

// DefaultRetrier creates a standard retrier: 3 retries, 200ms→800ms→2s.
func DefaultRetrier() *Retrier {
	return &Retrier{
		MaxRetries: 3,
		Initial:    200 * time.Millisecond,
		Max:        2 * time.Second,
		Jitter:     0.25,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// IsTransient checks if an error is worth retrying.
// Transient errors: timeouts, DNS failures, connection refused/reset, 5xx responses.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if isTimeoutError(err) {
		return true
	}
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "connection reset") ||
		strings.Contains(lower, "broken pipe") ||
		strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "no route to host") ||
		strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "tls handshake timeout") {
		return true
	}
	return false
}

// IsTransientStatus checks if an HTTP status code is transient (worth retrying).
func IsTransientStatus(code int) bool {
	return code >= 500 || code == 429 || code == 408
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "deadline exceeded") ||
		strings.Contains(err.Error(), "context deadline exceeded") {
		return true
	}
	return false
}

// Do executes fn with retries on transient errors.
// Returns the last error if all retries are exhausted.
func (r *Retrier) Do(ctx context.Context, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt <= r.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := r.backoff(attempt)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err
		if !IsTransient(err) {
			return err
		}
	}
	return lastErr
}

func (r *Retrier) backoff(attempt int) time.Duration {
	// Exponential: initial * 2^(attempt-1)
	backoff := float64(r.Initial) * math.Pow(2, float64(attempt-1))
	if backoff > float64(r.Max) {
		backoff = float64(r.Max)
	}
	// Apply jitter
	jitter := backoff * r.Jitter * (r.rng.Float64()*2 - 1)
	return time.Duration(backoff + jitter)
}
