package net

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

type fakeResolver struct {
	ips []net.IPAddr
	err error
}

func (f fakeResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	return f.ips, f.err
}

type fakeConn struct {
	net.Conn
}

// fakeDial 记录拨号地址，并按地址族模拟失败/成功。
func fakeDial(failV6 bool) (func(ctx context.Context, network, addr string) (net.Conn, error), *[]string) {
	var mu sync.Mutex
	var addrs []string
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		addrs = append(addrs, addr)
		mu.Unlock()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.To4() == nil && failV6 {
			return nil, errors.New("operation not permitted")
		}
		return &fakeConn{}, nil
	}, &addrs
}

func TestPreferIPv4DialContextFallsBackFromIPv6EPERM(t *testing.T) {
	dial, addrs := fakeDial(true)
	prefer := preferIPv4DialContextWithResolver(dial, fakeResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("2408:8752:400:9:0:1:0:11")},
		{IP: net.ParseIP("116.162.104.224")},
	}})
	conn, err := prefer(context.Background(), "tcp", "hydownload.pan.wo.cn:443")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if conn == nil {
		t.Fatal("conn is nil")
	}
	// IPv4 优先：直接成功，不浪费 IPv6 尝试。
	if len(*addrs) != 1 || (*addrs)[0] != "116.162.104.224:443" {
		t.Fatalf("expected single IPv4 dial, got %v", *addrs)
	}
}

func TestPreferIPv4DialContextFallsBackToIPv6WhenIPv4Fails(t *testing.T) {
	inner := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if net.ParseIP(host).To4() != nil {
			return nil, errors.New("ipv4 refused")
		}
		return &fakeConn{}, nil
	}
	prefer := preferIPv4DialContextWithResolver(inner, fakeResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("2408:8752:400:9:0:1:0:11")},
		{IP: net.ParseIP("116.162.104.224")},
	}})
	conn, err := prefer(context.Background(), "tcp", "hydownload.pan.wo.cn:443")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if conn == nil {
		t.Fatal("conn is nil")
	}
}

func TestPreferIPv4DialContextUsesIPv6WhenIPv4Unavailable(t *testing.T) {
	dial, addrs := fakeDial(false)
	prefer := preferIPv4DialContextWithResolver(dial, fakeResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("2408:8752:400:9:0:1:0:11")},
	}})
	conn, err := prefer(context.Background(), "tcp", "ipv6-only.example:443")
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if conn == nil {
		t.Fatal("conn is nil")
	}
	if len(*addrs) != 1 || (*addrs)[0] != "[2408:8752:400:9:0:1:0:11]:443" {
		t.Fatalf("expected IPv6 dial, got %v", *addrs)
	}
}

func TestPreferIPv4DialContextPassesThroughIPAndNonTCP(t *testing.T) {
	dial, addrs := fakeDial(false)
	prefer := preferIPv4DialContextWithResolver(dial, fakeResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("1.2.3.4")},
	}})
	// 已是 IP：原样拨号，不解析。
	if _, err := prefer(context.Background(), "tcp", "116.162.104.224:443"); err != nil {
		t.Fatalf("ip dial failed: %v", err)
	}
	if len(*addrs) != 1 || (*addrs)[0] != "116.162.104.224:443" {
		t.Fatalf("expected passthrough IP dial, got %v", *addrs)
	}
	// 非 TCP：原样拨号。
	if _, err := prefer(context.Background(), "udp", "hydownload.pan.wo.cn:53"); err != nil {
		t.Fatalf("udp dial failed: %v", err)
	}
	if len(*addrs) != 2 || (*addrs)[1] != "hydownload.pan.wo.cn:53" {
		t.Fatalf("expected udp passthrough, got %v", *addrs)
	}
}

func TestPreferIPv4DialContextAllFailV4(t *testing.T) {
	inner := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("dial refused")
	}
	prefer := preferIPv4DialContextWithResolver(inner, fakeResolver{ips: []net.IPAddr{
		{IP: net.ParseIP("2408:8752:400:9:0:1:0:11")},
		{IP: net.ParseIP("116.162.104.224")},
	}})
	_, err := prefer(context.Background(), "tcp", "all-fail.example:443")
	if err == nil {
		t.Fatal("expected error when all dials fail")
	}
}

func TestPreferIPv4DialContextResolverErrorFallsBack(t *testing.T) {
	dial, addrs := fakeDial(false)
	prefer := preferIPv4DialContextWithResolver(dial, fakeResolver{err: errors.New("dns down")})
	if _, err := prefer(context.Background(), "tcp", "dns-down.example:443"); err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	if len(*addrs) != 1 || (*addrs)[0] != "dns-down.example:443" {
		t.Fatalf("expected original host dial, got %v", *addrs)
	}
}
