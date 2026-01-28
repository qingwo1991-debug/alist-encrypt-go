package proxy

import (
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
	cfg *config.Config
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

	return &Client{
		Client: &http.Client{
			Transport: transport,
			Timeout:   0, // No timeout for streaming
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects automatically
			},
		},
		cfg: cfg,
	}
}

// Do executes an HTTP request
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.Client.Do(req)
}

// Get performs a GET request
func (c *Client) Get(url string) (*http.Response, error) {
	return c.Client.Get(url)
}
