package encrypt

import (
	"testing"
	"time"
)

func TestShouldRetryPropfind404(t *testing.T) {
	cases := []struct {
		name      string
		depth     string
		path      string
		expectRet bool
	}{
		{name: "depth0 file", depth: "0", path: "/dav/folder/a.mp4", expectRet: true},
		{name: "depth0 noext file", depth: "0", path: "/dav/folder/abc", expectRet: true},
		{name: "depth1 list", depth: "1", path: "/dav/folder/", expectRet: false},
		{name: "infinity list", depth: "infinity", path: "/dav/folder/", expectRet: false},
		{name: "empty depth ext path", depth: "", path: "/dav/folder/a.mkv", expectRet: true},
		{name: "empty depth dir path", depth: "", path: "/dav/folder/", expectRet: false},
		{name: "root", depth: "0", path: "/", expectRet: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRetryPropfind404(tc.depth, tc.path)
			if got != tc.expectRet {
				t.Fatalf("shouldRetryPropfind404(%q,%q)=%v expect %v", tc.depth, tc.path, got, tc.expectRet)
			}
		})
	}
}

func TestPropfindRetryTimeoutClamp(t *testing.T) {
	p := &ProxyServer{config: &ProxyConfig{ProbeTimeoutSeconds: 20}}
	if got := p.propfindRetryTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("expected 1500ms cap, got %v", got)
	}

	p = &ProxyServer{config: &ProxyConfig{ProbeTimeoutSeconds: 1}}
	if got := p.propfindRetryTimeout(); got != 1*time.Second {
		t.Fatalf("expected 1s passthrough, got %v", got)
	}

	p = &ProxyServer{config: &ProxyConfig{ProbeTimeoutSeconds: 0}}
	if got := p.propfindRetryTimeout(); got != 1500*time.Millisecond {
		t.Fatalf("expected default capped 1500ms, got %v", got)
	}
}
