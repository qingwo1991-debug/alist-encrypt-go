package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildAlistURLUsesSchemeSpecificDefaultPort(t *testing.T) {
	tests := []struct {
		name   string
		server AlistServer
		want   string
	}{
		{name: "http default", server: AlistServer{ServerHost: "example.com", ServerPort: 80}, want: "http://example.com"},
		{name: "http nondefault 443", server: AlistServer{ServerHost: "example.com", ServerPort: 443}, want: "http://example.com:443"},
		{name: "https default", server: AlistServer{ServerHost: "example.com", ServerPort: 443, HTTPS: true}, want: "https://example.com"},
		{name: "https nondefault 80", server: AlistServer{ServerHost: "example.com", ServerPort: 80, HTTPS: true}, want: "https://example.com:80"},
		{name: "ipv6 default", server: AlistServer{ServerHost: "2001:db8::1", ServerPort: 443, HTTPS: true}, want: "https://[2001:db8::1]"},
		{name: "ipv6 custom", server: AlistServer{ServerHost: "[2001:db8::1]", ServerPort: 5244}, want: "http://[2001:db8::1]:5244"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildAlistURL(tt.server); got != tt.want {
				t.Fatalf("BuildAlistURL()=%q, want %q", got, tt.want)
			}
		})
	}
}

func TestListenAddressesBracketIPv6(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scheme.Address = "::"
	cfg.Scheme.HTTPPort = 5344
	cfg.Scheme.HTTPSPort = 5443
	if got := cfg.GetHTTPAddr(); got != "[::]:5344" {
		t.Fatalf("GetHTTPAddr()=%q", got)
	}
	if got := cfg.GetHTTPSAddr(); got != "[::]:5443" {
		t.Fatalf("GetHTTPSAddr()=%q", got)
	}
}

func TestServerEndpointValidationRejectsURLAndInvalidPort(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
	}{
		{host: "https://example.com", port: 5244},
		{host: "user@example.com", port: 5244},
		{host: "example.com/path", port: 5244},
		{host: "example.com", port: 0},
		{host: "example.com", port: 65536},
		{host: "bad:ipv6", port: 5244},
	} {
		if err := validateServerEndpoint(tc.host, tc.port, "alist"); err == nil {
			t.Fatalf("validateServerEndpoint(%q, %d) unexpectedly succeeded", tc.host, tc.port)
		}
	}
}

func TestReplaceFromJSONRejectsEmptyJWTWithoutMutatingConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JWTSecret = "stable-secret"
	originalURL := cfg.GetAlistURL()
	payload, err := cfg.MarshalJSONSnapshot()
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	raw["jwt_secret"] = ""
	rawAlist := raw["alistServer"].(map[string]interface{})
	rawAlist["serverHost"] = "changed.example"
	invalid, _ := json.Marshal(raw)
	if err := cfg.ReplaceFromJSON(invalid); err == nil || !strings.Contains(err.Error(), "jwt_secret") {
		t.Fatalf("ReplaceFromJSON() error=%v, want jwt_secret rejection", err)
	}
	if got := cfg.GetAlistURL(); got != originalURL {
		t.Fatalf("config mutated after rejected replacement: %q", got)
	}
}

func TestSchemeValidationRejectsUnstartableSettings(t *testing.T) {
	for _, scheme := range []SchemeConfig{
		{HTTPPort: 0, HTTPSPort: -1},
		{HTTPPort: 5344, HTTPSPort: 0},
		{HTTPPort: 5344, HTTPSPort: 5443, CertFile: "cert.pem"},
		{HTTPPort: 5344, HTTPSPort: -1, ForceHTTPS: true},
		{HTTPPort: 5344, HTTPSPort: -1, UnixFilePerm: "999"},
	} {
		if err := validateSchemeConfig(scheme); err == nil {
			t.Fatalf("validateSchemeConfig(%+v) unexpectedly succeeded", scheme)
		}
	}
}

func TestUpdateSchemeRequestsRestartForAnyListenerChange(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	current := cfg.SchemeSnapshot()
	needRestart, err := cfg.UpdateScheme(current)
	if err != nil {
		t.Fatalf("save unchanged scheme: %v", err)
	}
	if needRestart {
		t.Fatal("unchanged scheme unexpectedly requested restart")
	}
	current.Address = "127.0.0.1"
	needRestart, err = cfg.UpdateScheme(current)
	if err != nil {
		t.Fatalf("save changed scheme: %v", err)
	}
	if !needRestart {
		t.Fatal("listener address change did not request restart")
	}
}
