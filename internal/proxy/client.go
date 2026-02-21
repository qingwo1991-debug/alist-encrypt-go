package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"

	"github.com/alist-encrypt-go/internal/config"
)

// Client wraps http.Client with connection pooling and HTTP/2 support
type Client struct {
	*http.Client
	h2cClient *http.Client // Separate client for h2c connections
	cfg       *config.Config
}

var internalDirectHosts = map[string]struct{}{
	"localhost":            {},
	"127.0.0.1":            {},
	"::1":                  {},
	"openalist":            {},
	"alist":                {},
	"mysql":                {},
	"host.docker.internal": {},
}

func cloneProxyRules(rules []config.ProxyRule) []config.ProxyRule {
	if len(rules) == 0 {
		return nil
	}
	cp := append([]config.ProxyRule(nil), rules...)
	sort.SliceStable(cp, func(i, j int) bool {
		if cp[i].Priority != cp[j].Priority {
			return cp[i].Priority < cp[j].Priority
		}
		return cp[i].Pattern < cp[j].Pattern
	})
	return cp
}

func baseTransport(cfg *config.Config) *http.Transport {
	if cfg == nil || cfg.Proxy == nil {
		cfg = config.DefaultConfig()
	}
	proxyCfg := cfg.Proxy
	dialTimeout := time.Duration(proxyCfg.DialTimeoutSeconds) * time.Second
	tlsTimeout := time.Duration(proxyCfg.TLSHandshakeSeconds) * time.Second
	respHeaderTimeout := time.Duration(proxyCfg.ResponseHeaderSecs) * time.Second
	if dialTimeout <= 0 {
		dialTimeout = 30 * time.Second
	}
	if tlsTimeout <= 0 {
		tlsTimeout = 10 * time.Second
	}
	if respHeaderTimeout <= 0 {
		respHeaderTimeout = 15 * time.Second
	}
	return &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     proxyCfg.EnableHTTP2,
		MaxIdleConns:          proxyCfg.MaxIdleConns,
		MaxIdleConnsPerHost:   proxyCfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       proxyCfg.MaxConnsPerHost,
		IdleConnTimeout:       time.Duration(proxyCfg.IdleConnTimeout) * time.Second,
		TLSHandshakeTimeout:   tlsTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: respHeaderTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: proxyCfg.InsecureSkipVerify},
	}
}

func parseHostOnly(hostport string) string {
	host := strings.ToLower(strings.TrimSpace(hostport))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			return strings.ToLower(strings.TrimSpace(parsedHost))
		}
	}
	return strings.Trim(host, "[]")
}

func isPrivateHost(host string) bool {
	if host == "" {
		return true
	}
	if _, ok := internalDirectHosts[host]; ok {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	if addr.Is6() && (addr.IsUnspecified() || addr.IsInterfaceLocalMulticast()) {
		return true
	}
	return false
}

func matchRuleHost(rule config.ProxyRule, host string) bool {
	switch rule.MatchType {
	case "domain":
		return host == rule.Pattern
	case "host":
		return host == rule.Pattern
	case "domain_suffix":
		if host == rule.Pattern {
			return true
		}
		return strings.HasSuffix(host, "."+rule.Pattern)
	case "cidr":
		prefix, err := netip.ParsePrefix(rule.Pattern)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	default:
		return false
	}
}

func matchesNoProxy(pattern string, host string) bool {
	item := strings.ToLower(strings.TrimSpace(pattern))
	if item == "" || host == "" {
		return false
	}
	if prefix, err := netip.ParsePrefix(item); err == nil {
		if addr, err := netip.ParseAddr(host); err == nil {
			return prefix.Contains(addr)
		}
		return false
	}
	item = strings.TrimPrefix(item, ".")
	if host == item {
		return true
	}
	return strings.HasSuffix(host, "."+item)
}

func proxyFunc(cfg *config.Config) func(*http.Request) (*url.URL, error) {
	if cfg == nil || cfg.Proxy == nil {
		cfg = config.DefaultConfig()
	}
	rules := cloneProxyRules(cfg.Proxy.Rules)
	noProxy := append([]string(nil), cfg.Proxy.NoProxy...)
	mode := strings.ToLower(strings.TrimSpace(cfg.Proxy.Mode))
	fixedURL := strings.TrimSpace(cfg.Proxy.URL)
	var fixedProxyURL *url.URL
	if fixedURL != "" {
		if parsed, err := url.Parse(fixedURL); err == nil {
			fixedProxyURL = parsed
		}
	}
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		host := parseHostOnly(req.URL.Host)
		if host == "" {
			host = parseHostOnly(req.Host)
		}
		// Always keep service discovery/private addresses direct.
		if isPrivateHost(host) {
			return nil, nil
		}
		if mode == "env" {
			return http.ProxyFromEnvironment(req)
		}
		if mode == "direct" {
			return nil, nil
		}
		if mode == "fixed" {
			for _, item := range noProxy {
				if matchesNoProxy(item, host) {
					return nil, nil
				}
			}
			return fixedProxyURL, nil
		}
		if mode == "rules" {
			for _, rule := range rules {
				if !rule.Enabled {
					continue
				}
				if matchRuleHost(rule, host) {
					if rule.Action == "proxy" {
						return fixedProxyURL, nil
					}
					return nil, nil
				}
			}
			for _, item := range noProxy {
				if matchesNoProxy(item, host) {
					return nil, nil
				}
			}
			// rules mode defaults to direct for unmatched hosts.
			return nil, nil
		}
		return nil, nil
	}
}

// NewHTTPClient builds a shared HTTP client with unified proxy routing.
func NewHTTPClient(cfg *config.Config, timeout time.Duration) *http.Client {
	transport := baseTransport(cfg)
	transport.Proxy = proxyFunc(cfg)
	if cfg.Proxy.EnableHTTP2 {
		http2.ConfigureTransport(transport)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// NewClient creates a new HTTP client with connection pooling
func NewClient(cfg *config.Config) *Client {
	proxyCfg := cfg.Proxy
	transport := baseTransport(cfg)
	transport.Proxy = proxyFunc(cfg)

	// Configure HTTP/2 if enabled
	if proxyCfg.EnableHTTP2 {
		http2.ConfigureTransport(transport)
	}

	client := &Client{
		Client: &http.Client{
			Transport: transport,
			Timeout:   0, // No timeout for streaming
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects automatically
			},
		},
		cfg: cfg,
	}

	// Create h2c client if enabled for backend connections
	if cfg.AlistServer.EnableH2C {
		h2cTransport := &http2.Transport{
			AllowHTTP: true, // Allow HTTP/2 over cleartext (h2c)
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				// For h2c, we dial without TLS
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}
		client.h2cClient = &http.Client{
			Transport: h2cTransport,
			Timeout:   0,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return client
}

// Do executes an HTTP request, using h2c if enabled and target is backend
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Use h2c client for backend connections if enabled
	if c.h2cClient != nil && c.isBackendRequest(req) {
		resp, err := c.h2cClient.Do(req)
		if err == nil && resp != nil {
			log.Debug().
				Str("proto", resp.Proto).
				Str("url", req.URL.String()).
				Msg("H2C connection used")
		}
		return resp, err
	}
	return c.Client.Do(req)
}

// isBackendRequest checks if the request is to the Alist backend
func (c *Client) isBackendRequest(req *http.Request) bool {
	backendHost := c.cfg.AlistServer.ServerHost
	// Check both with and without port
	reqHost := req.URL.Host
	if reqHost == "" {
		reqHost = req.Host
	}
	// Strip port for comparison
	if host, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = host
	}
	return reqHost == backendHost
}

// Get performs a GET request
func (c *Client) Get(url string) (*http.Response, error) {
	return c.Client.Get(url)
}
