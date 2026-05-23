package encrypt

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestHandleRootProxiesToAlistContent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Fatalf("backend path=%q, want %q", r.URL.Path, "/")
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("alist-root-content"))
	}))
	defer backend.Close()

	parsed, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost: parsed.Hostname(),
			AlistPort: port,
			AlistHttps: parsed.Scheme == "https",
		},
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:5344/", nil)
	rr := httptest.NewRecorder()
	p.handleRoot(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if body := rr.Body.String(); body != "alist-root-content" {
		t.Fatalf("body=%q, want %q", body, "alist-root-content")
	}
}

func TestHandleProxyPreservesRelativeRedirectLocation(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/#/login?redirect=/dashboard", http.StatusFound)
	}))
	defer backend.Close()

	parsed, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost:  parsed.Hostname(),
			AlistPort:  port,
			AlistHttps: parsed.Scheme == "https",
		},
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://192.168.1.7:5344/", nil)
	rr := httptest.NewRecorder()
	p.handleProxy(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusFound)
	}
	if got := rr.Header().Get("Location"); got != "/#/login?redirect=/dashboard" {
		t.Fatalf("location=%q, want %q", got, "/#/login?redirect=/dashboard")
	}
}

func TestHandleProxyRewritesAbsoluteRedirectLocation(t *testing.T) {
	var backendURL string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, backendURL+"/@login?redirect=%2Fdashboard", http.StatusFound)
	}))
	backendURL = backend.URL
	defer backend.Close()

	parsed, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend url: %v", err)
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}

	p := &ProxyServer{
		config: &ProxyConfig{
			AlistHost:  parsed.Hostname(),
			AlistPort:  port,
			AlistHttps: parsed.Scheme == "https",
		},
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "http://192.168.1.7:5344/", nil)
	rr := httptest.NewRecorder()
	p.handleProxy(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusFound)
	}
	want := "http://192.168.1.7:5344/@login?redirect=%2Fdashboard"
	if got := rr.Header().Get("Location"); got != want {
		t.Fatalf("location=%q, want %q", got, want)
	}
}
