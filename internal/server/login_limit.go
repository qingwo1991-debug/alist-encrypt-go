package server

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	loginAttemptLimit  = 5
	loginAttemptWindow = time.Minute
	loginPeerLimit     = 4096
)

type loginAttemptEntry struct {
	attempts int
	expires  time.Time
}

// loginAttemptLimiter counts all attempts (including successful logins), so it
// need not inspect credentials or buffer the legacy HTTP-200 login response.
// State is per server process; replicas need a shared edge limit as well.
// Expired entries are swept lazily, without a cleanup goroutine.
type loginAttemptLimiter struct {
	mu        sync.Mutex
	entries   map[string]loginAttemptEntry
	nextSweep time.Time
}

func newLoginAttemptLimiter() *loginAttemptLimiter {
	return &loginAttemptLimiter{entries: make(map[string]loginAttemptEntry)}
}

// allow returns zero on admission, otherwise the time until a retry can succeed.
func (l *loginAttemptLimiter) allow(peer string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.nextSweep) {
		for key, entry := range l.entries {
			if !now.Before(entry.expires) {
				delete(l.entries, key)
			}
		}
		l.nextSweep = now.Add(loginAttemptWindow)
	}
	entry, exists := l.entries[peer]
	if exists && !now.Before(entry.expires) {
		delete(l.entries, peer)
		exists = false
	}
	if !exists {
		// Do not evict active peers: that would reset their attempt budgets.
		if len(l.entries) >= loginPeerLimit {
			return l.nextSweep.Sub(now)
		}
		entry = loginAttemptEntry{expires: now.Add(loginAttemptWindow)}
	}
	if entry.attempts >= loginAttemptLimit {
		return entry.expires.Sub(now)
	}
	entry.attempts++
	l.entries[peer] = entry
	return 0
}

// loginPeer uses the transport peer, never Gin.ClientIP or forwarded headers.
// Reverse proxies therefore share a budget; no implicit proxy trust is enabled.
// Non-IP transports (e.g. Unix sockets) share a single bounded fallback key.
func loginPeer(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return "unknown-peer"
}

func (l *loginAttemptLimiter) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if retry := l.allow(loginPeer(c.Request.RemoteAddr), time.Now()); retry > 0 {
			seconds := int64((retry + time.Second - 1) / time.Second)
			c.Header("Retry-After", strconv.FormatInt(seconds, 10))
			c.Header("Cache-Control", "no-store")
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code": http.StatusTooManyRequests,
				"msg":  "Too many login attempts; try again later",
				"data": nil,
			})
			return
		}
		c.Next()
	}
}
