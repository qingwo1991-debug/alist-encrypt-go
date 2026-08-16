package encrypt

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ipResolver 抽象 DNS 解析，便于测试注入。
type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// preferIPv4DialContext 包装上游拨号函数：域名解析后优先使用 IPv4，
// IPv4 全部失败后才尝试 IPv6。
//
// 背景：Android/部分移动网络对 IPv6 出站会返回 "operation not permitted"
// （EPERM），而 Go 默认拨号在个别环境下不会自动回退 IPv4，导致上游 CDN
// （如联通云盘 hydownload.pan.wo.cn、panservice.mail.wo.cn）无法连接、
// 视频无法播放。该包装在传入 IP 或非 TCP 时保持原行为，IPv6-only
// 网络下仍可正常使用 IPv6。
func preferIPv4DialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return preferIPv4DialContextWithResolver(dial, net.DefaultResolver)
}

func preferIPv4DialContextWithResolver(dial func(ctx context.Context, network, addr string) (net.Conn, error), resolver ipResolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dial == nil {
		d := &net.Dialer{Timeout: defaultUpstreamDialTimeout}
		dial = d.DialContext
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return dial(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil {
			// 已是 IP 或无法拆分：交给原拨号器（保留 IPv6 能力）。
			return dial(ctx, network, addr)
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return dial(ctx, network, addr)
		}
		var v4, v6 []net.IP
		for _, ipa := range ips {
			if ipa.IP.To4() != nil {
				v4 = append(v4, ipa.IP)
			} else if ipa.IP.To16() != nil {
				v6 = append(v6, ipa.IP)
			}
		}
		var lastErr error
		for _, ip := range append(v4, v6...) {
			conn, derr := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("no usable address for %s", host)
		}
		return nil, lastErr
	}
}

const defaultUpstreamDialTimeout = 15 * time.Second
