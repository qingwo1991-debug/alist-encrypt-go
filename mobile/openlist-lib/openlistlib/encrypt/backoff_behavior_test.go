package encrypt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestUpstreamIsLocalLoopback(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"::1", true},
		{"192.168.1.10", false},
		{"panservice.mail.wo.cn", false},
		{"", false},
	}
	for _, c := range cases {
		p := &ProxyServer{config: &ProxyConfig{AlistHost: c.host}}
		if got := p.upstreamIsLocalLoopback(); got != c.want {
			t.Errorf("host=%q got=%v want=%v", c.host, got, c.want)
		}
	}
}

func TestMarkUpstreamFailureSkipsLocalLoopback(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "127.0.0.1", AlistPort: 5244}}
	// 本地上游：连续失败也不应激活 backoff。
	for i := 0; i < upstreamFailureThreshold+2; i++ {
		p.markUpstreamFailure(errors.New("dial tcp 127.0.0.1:5244: connect: connection refused"))
	}
	if active, _, _ := p.upstreamBackoffState(); active {
		t.Fatal("local loopback upstream must not activate backoff")
	}
}

func TestMarkUpstreamFailureSkipsDeadlineExceeded(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "panservice.mail.wo.cn", AlistPort: 443}}
	for i := 0; i < upstreamFailureThreshold+2; i++ {
		p.markUpstreamFailure(context.DeadlineExceeded)
	}
	if active, _, _ := p.upstreamBackoffState(); active {
		t.Fatal("context deadline exceeded must not activate backoff")
	}
}

func TestMarkUpstreamFailureActivatesForRemote(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "panservice.mail.wo.cn", AlistPort: 443}}
	for i := 0; i < upstreamFailureThreshold; i++ {
		p.markUpstreamFailure(errors.New("connection refused"))
	}
	active, remain, reason := p.upstreamBackoffState()
	if !active {
		t.Fatal("remote upstream should activate backoff after threshold failures")
	}
	if remain <= 0 {
		t.Fatalf("expected positive backoff remain, got %v", remain)
	}
	if !strings.Contains(reason, "connection refused") {
		t.Fatalf("expected reason to be recorded, got %q", reason)
	}
	// 成功一次后清除。
	p.markUpstreamSuccess()
	if active, _, _ := p.upstreamBackoffState(); active {
		t.Fatal("backoff should be cleared after success")
	}
}

func TestUpstreamBackoffClamp(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{AlistHost: "remote.example", UpstreamBackoffSeconds: 0}}
	if got := p.upstreamBackoff(); got != 20*time.Second {
		t.Fatalf("default backoff = %v, want 20s", got)
	}
}
