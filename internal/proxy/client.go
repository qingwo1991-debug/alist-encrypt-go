package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"

	"github.com/alist-encrypt-go/internal/config"
)

// Client wraps http.Client with connection pooling and HTTP/2 support
type Client struct {
	*http.Client
	h2cClient *http.Client // Separate client for h2c connections
	cfg       *config.Config
}

// NewClient creates a new HTTP client with connection pooling
func NewClient(cfg *config.Config) *Client {
	proxyCfg := cfg.Proxy

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     proxyCfg.EnableHTTP2,
		MaxIdleConns:          proxyCfg.MaxIdleConns,
		MaxIdleConnsPerHost:   proxyCfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       proxyCfg.MaxConnsPerHost,
		IdleConnTimeout:       time.Duration(proxyCfg.IdleConnTimeout) * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: proxyCfg.InsecureSkipVerify,
		},
	}

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
		return c.h2cClient.Do(req)
	}
	return c.Client.Do(req)
}

// isBackendRequest checks if the request is to the Alist backend
func (c *Client) isBackendRequest(req *http.Request) bool {
	backendHost := c.cfg.AlistServer.ServerHost
	return req.URL.Host == backendHost || req.Host == backendHost
}

// Get performs a GET request
func (c *Client) Get(url string) (*http.Response, error) {
	return c.Client.Get(url)
}
