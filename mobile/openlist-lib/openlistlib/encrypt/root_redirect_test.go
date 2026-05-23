package encrypt

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestShouldRedirectToAlistEntry(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{name: "root get", method: http.MethodGet, path: "/", want: true},
		{name: "index get", method: http.MethodGet, path: "/index", want: true},
		{name: "public index get", method: http.MethodGet, path: "/public/index.html", want: true},
		{name: "head root", method: http.MethodHead, path: "/", want: true},
		{name: "post root", method: http.MethodPost, path: "/", want: false},
		{name: "other path", method: http.MethodGet, path: "/api/fs/list", want: false},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(tt.method, "http://127.0.0.1:5344"+tt.path, nil)
		if got := shouldRedirectToAlistEntry(req); got != tt.want {
			t.Fatalf("%s: shouldRedirectToAlistEntry()=%v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestHandleRootRedirectsToAlistEntry(t *testing.T) {
	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost: "127.0.0.1",
			AlistPort: 5244,
		},
	}

	tests := []struct {
		path     string
		location string
	}{
		{path: "/", location: "http://127.0.0.1:5244/"},
		{path: "/index", location: "http://127.0.0.1:5244/"},
		{path: "/public/index.html", location: "http://127.0.0.1:5244/"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5344"+tt.path, nil)
		rr := httptest.NewRecorder()
		p.handleRoot(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("path=%s status=%d, want %d", tt.path, rr.Code, http.StatusFound)
		}
		if got := rr.Header().Get("Location"); got != tt.location {
			t.Fatalf("path=%s location=%q, want %q", tt.path, got, tt.location)
		}
	}
}
