package proxy

import (
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/backoff"
)

const (
	defaultCircuitBreakerRegistryMaxEntries = 256
	defaultCircuitBreakerRegistryTTL        = 30 * time.Minute
)

var emergencyCircuitBreakerGate = backoff.NewGate(5, 30*time.Second)

type circuitBreakerEntry struct {
	gate     *backoff.Gate
	lastUsed time.Time
}

// circuitBreakerRegistry isolates failures by upstream origin while keeping
// the number of short-lived CDN origins bounded. The configured control-plane
// origin and malformed/relative targets use fallback so they cannot bypass the
// original safety gate or evict data-plane entries.
type circuitBreakerRegistry struct {
	mu sync.Mutex

	entries     map[string]*circuitBreakerEntry
	fallback    *backoff.Gate
	fallbackKey string
	threshold   int
	cooldown    time.Duration
	maxEntries  int
	ttl         time.Duration
	now         func() time.Time
}

func newCircuitBreakerRegistry(fallback *backoff.Gate, fallbackURL string, threshold int, cooldown time.Duration) *circuitBreakerRegistry {
	if fallback == nil {
		fallback = backoff.NewGate(threshold, cooldown)
	}
	ttl := defaultCircuitBreakerRegistryTTL
	// Keep the idle TTL at least as long as the configured cooldown, including
	// deployments that intentionally use values above the default TTL.
	if cooldown > ttl {
		ttl = cooldown
	}
	fallbackKey, _ := circuitBreakerOriginKey(fallbackURL)
	return &circuitBreakerRegistry{
		entries:     make(map[string]*circuitBreakerEntry),
		fallback:    fallback,
		fallbackKey: fallbackKey,
		threshold:   threshold,
		cooldown:    cooldown,
		maxEntries:  defaultCircuitBreakerRegistryMaxEntries,
		ttl:         ttl,
		now:         time.Now,
	}
}

func (r *circuitBreakerRegistry) gateFor(targetURL string) *backoff.Gate {
	key, ok := circuitBreakerOriginKey(targetURL)
	if !ok || key == r.fallbackKey {
		return r.fallback
	}

	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, exists := r.entries[key]; exists {
		if !circuitBreakerEntryExpired(entry, now, r.ttl) {
			entry.lastUsed = now
			return entry.gate
		}
		delete(r.entries, key)
	}

	// Misses are infrequent compared with video range requests. Pruning here
	// keeps expired origins from accumulating without adding a scan to hits.
	r.pruneExpiredLocked(now)
	if len(r.entries) >= r.maxEntries {
		r.evictOldestLocked()
	}

	gate := backoff.NewGate(r.threshold, r.cooldown)
	r.entries[key] = &circuitBreakerEntry{gate: gate, lastUsed: now}
	return gate
}

func (r *circuitBreakerRegistry) pruneExpiredLocked(now time.Time) {
	for key, entry := range r.entries {
		if circuitBreakerEntryExpired(entry, now, r.ttl) {
			delete(r.entries, key)
		}
	}
}

func (r *circuitBreakerRegistry) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for key, entry := range r.entries {
		if oldestKey == "" || entry.lastUsed.Before(oldestTime) || (entry.lastUsed.Equal(oldestTime) && key < oldestKey) {
			oldestKey = key
			oldestTime = entry.lastUsed
		}
	}
	if oldestKey != "" {
		delete(r.entries, oldestKey)
	}
}

func circuitBreakerEntryExpired(entry *circuitBreakerEntry, now time.Time, ttl time.Duration) bool {
	if entry == nil || entry.gate == nil {
		return true
	}
	if ttl <= 0 || now.Before(entry.lastUsed) {
		return false
	}
	return now.Sub(entry.lastUsed) >= ttl
}

// circuitBreakerOriginKey returns a normalized scheme+host key. Default ports
// are omitted so equivalent URLs share one breaker, while HTTP and HTTPS stay
// isolated. Relative or malformed URLs deliberately have no key.
func circuitBreakerOriginKey(rawURL string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", false
	}

	scheme := strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", false
	}
	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	host := hostname
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	return scheme + "://" + host, true
}

func (s *StreamProxy) circuitBreakerFor(targetURL string) *backoff.Gate {
	if s != nil && s.cbGates != nil {
		return s.cbGates.gateFor(targetURL)
	}
	if s != nil && s.cbGate != nil {
		return s.cbGate
	}
	// StreamProxy constructors always initialize a gate. Retain a safe gate for
	// zero-value instances instead of allowing an outbound request unprotected.
	return emergencyCircuitBreakerGate
}
