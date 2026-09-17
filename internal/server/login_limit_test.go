package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLoginAttemptPolicyWindowAndPeers(t *testing.T) {
	l := newLoginAttemptLimiter()
	now := time.Unix(1000, 0)
	for i := 0; i < loginAttemptLimit; i++ {
		if wait := l.allow("192.0.2.1", now); wait != 0 {
			t.Fatalf("attempt %d wait=%v", i, wait)
		}
	}
	if wait := l.allow("192.0.2.1", now.Add(time.Second)); wait != loginAttemptWindow-time.Second {
		t.Fatalf("wait=%v", wait)
	}
	if wait := l.allow("192.0.2.2", now); wait != 0 {
		t.Fatalf("independent peer wait=%v", wait)
	}
	if wait := l.allow("192.0.2.1", now.Add(loginAttemptWindow)); wait != 0 {
		t.Fatalf("expired window wait=%v", wait)
	}
}

func TestLoginAttemptPolicyCapacityAndExpiry(t *testing.T) {
	l := newLoginAttemptLimiter()
	now := time.Unix(1000, 0)
	// Seed policy state directly; no load or network traffic is generated.
	for i := 0; i < loginPeerLimit; i++ {
		l.entries[fmt.Sprint(i)] = loginAttemptEntry{attempts: 1, expires: now.Add(loginAttemptWindow)}
	}
	if wait := l.allow("new-peer", now); wait != loginAttemptWindow {
		t.Fatalf("capacity wait=%v", wait)
	}
	if len(l.entries) != loginPeerLimit {
		t.Fatalf("entry cap not preserved: %d", len(l.entries))
	}
	if wait := l.allow("new-peer", now.Add(loginAttemptWindow)); wait != 0 || len(l.entries) != 1 {
		t.Fatalf("expiry wait=%v entries=%d", wait, len(l.entries))
	}
}

func TestLoginPeerNormalization(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"192.0.2.1:1234", "192.0.2.1"},
		{"[2001:db8::1]:1234", "2001:db8::1"},
		{"[::ffff:192.0.2.1]:1234", "192.0.2.1"},
		{"192.0.2.1", "192.0.2.1"},
		{"@", "unknown-peer"},
		{"", "unknown-peer"},
	} {
		if got := loginPeer(tc.addr); got != tc.want {
			t.Errorf("loginPeer(%q)=%q want %q", tc.addr, got, tc.want)
		}
	}
}

func TestLoginAttemptMiddlewareContract(t *testing.T) {
	gin.SetMode(gin.TestMode)
	l := newLoginAttemptLimiter()
	r := gin.New()
	called := 0
	r.POST("/enc-api/login", l.middleware(), func(c *gin.Context) {
		called++
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": "synthetic login response"})
	})
	req := httptest.NewRequest(http.MethodPost, "/enc-api/login", nil)
	req.RemoteAddr = "192.0.2.1:1234"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || called != 1 || rr.Header().Get("Retry-After") != "" {
		t.Fatalf("normal login status=%d called=%d", rr.Code, called)
	}
	// Set the known peer's policy budget directly to exercise the denied state.
	l.entries["192.0.2.1"] = loginAttemptEntry{attempts: loginAttemptLimit, expires: time.Now().Add(30 * time.Second)}
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests || called != 1 {
		t.Fatalf("limited status=%d called=%d", rr.Code, called)
	}
	retry, err := strconv.Atoi(rr.Header().Get("Retry-After"))
	if err != nil || retry < 1 || retry > 30 {
		t.Fatalf("Retry-After=%q", rr.Header().Get("Retry-After"))
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != float64(429) || body["msg"] != "Too many login attempts; try again later" {
		t.Fatalf("response=%v", body)
	}
	if _, ok := body["data"]; !ok || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing schema/cache contract: %v", body)
	}
}
