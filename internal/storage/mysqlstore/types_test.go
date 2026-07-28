package mysqlstore

import "testing"

func TestSplitProviderKeyPreservesIPv6(t *testing.T) {
	tests := []struct {
		key      string
		wantHost string
		wantPath string
	}{
		{key: "media.example::/movie.mkv", wantHost: "media.example", wantPath: "/movie.mkv"},
		{key: "[2001:db8::1]:8443", wantHost: "[2001:db8::1]:8443"},
		{key: "[2001:db8::1]:8443::/movie.mkv", wantHost: "[2001:db8::1]:8443", wantPath: "/movie.mkv"},
		{key: "2001:db8::1", wantHost: "2001:db8::1"},
	}
	for _, tt := range tests {
		host, path := SplitProviderKey(tt.key)
		if host != tt.wantHost || path != tt.wantPath {
			t.Fatalf("SplitProviderKey(%q)=(%q,%q), want (%q,%q)", tt.key, host, path, tt.wantHost, tt.wantPath)
		}
	}
}
