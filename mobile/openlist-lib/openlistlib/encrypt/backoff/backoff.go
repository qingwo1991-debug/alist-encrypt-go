package backoff

import (
	"sync"
	"time"
)

// Gate is a circuit breaker that opens after consecutive failures and
// stays open for the cooldown duration. While open, all requests are
// rejected immediately to protect the upstream from overload.
type Gate struct {
	mu              sync.Mutex
	failCount       int
	failThreshold   int
	openUntil       time.Time
	cooldown        time.Duration
}

// NewGate creates a circuit breaker gate.
// threshold: consecutive failures before opening the circuit
// cooldown: how long the circuit stays open before resetting
func NewGate(threshold int, cooldown time.Duration) *Gate {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Gate{
		failThreshold: threshold,
		cooldown:      cooldown,
	}
}

// Allow checks if a request should be allowed through.
// Returns false if the circuit is open (should reject the request).
func (g *Gate) Allow() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.openUntil.IsZero() {
		return true
	}
	if time.Now().After(g.openUntil) {
		// Cooldown expired, reset
		g.failCount = 0
		g.openUntil = time.Time{}
		return true
	}
	return false
}

// RecordSuccess resets the failure count when a request succeeds.
func (g *Gate) RecordSuccess() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failCount = 0
	g.openUntil = time.Time{}
}

// RecordFailure increments the failure count. If it reaches the threshold,
// the circuit opens for the cooldown duration.
func (g *Gate) RecordFailure() {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.failCount++
	if g.failCount >= g.failThreshold {
		g.failCount = 0
		g.openUntil = time.Now().Add(g.cooldown)
	}
}

// State returns the current state for observability.
func (g *Gate) State() (open bool, failCount int, remaining time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.openUntil.IsZero() && time.Now().Before(g.openUntil) {
		return true, g.failCount, time.Until(g.openUntil)
	}
	return false, g.failCount, 0
}
