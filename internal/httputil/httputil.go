package httputil

import (
	"bytes"
	"context"
	"io"
	"net/http"
)

// RequestBuilder provides a fluent API for building HTTP requests
type RequestBuilder struct {
	ctx         context.Context
	method      string
	url         string
	body        io.Reader
	headers     http.Header
	skipHeaders map[string]bool
}

// NewRequest creates a new RequestBuilder
func NewRequest(method, url string) *RequestBuilder {
	return &RequestBuilder{
		method:      method,
		url:         url,
		headers:     make(http.Header),
		skipHeaders: make(map[string]bool),
	}
}

// WithContext sets the request context
func (b *RequestBuilder) WithContext(ctx context.Context) *RequestBuilder {
	b.ctx = ctx
	return b
}

// WithBody sets the request body from bytes
func (b *RequestBuilder) WithBody(body []byte) *RequestBuilder {
	b.body = bytes.NewReader(body)
	return b
}

// WithBodyReader sets the request body from a reader
func (b *RequestBuilder) WithBodyReader(body io.Reader) *RequestBuilder {
	b.body = body
	return b
}

// WithHeader adds a single header
func (b *RequestBuilder) WithHeader(key, value string) *RequestBuilder {
	b.headers.Set(key, value)
	return b
}

// CopyHeaders copies headers from source request
func (b *RequestBuilder) CopyHeaders(src *http.Request) *RequestBuilder {
	for key, values := range src.Header {
		if b.skipHeaders[key] {
			continue
		}
		for _, value := range values {
			b.headers.Add(key, value)
		}
	}
	return b
}

// CopyHeadersExcept copies headers from source request, excluding specified headers
func (b *RequestBuilder) CopyHeadersExcept(src *http.Request, skip ...string) *RequestBuilder {
	for _, h := range skip {
		b.skipHeaders[h] = true
	}
	return b.CopyHeaders(src)
}

// Build creates the http.Request
func (b *RequestBuilder) Build() (*http.Request, error) {
	var req *http.Request
	var err error

	if b.ctx != nil {
		req, err = http.NewRequestWithContext(b.ctx, b.method, b.url, b.body)
	} else {
		req, err = http.NewRequest(b.method, b.url, b.body)
	}
	if err != nil {
		return nil, err
	}

	// Copy headers
	for key, values := range b.headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	return req, nil
}

// CopyResponseHeaders copies response headers to the writer, optionally skipping some
func CopyResponseHeaders(w http.ResponseWriter, resp *http.Response, skip ...string) {
	skipMap := make(map[string]bool)
	for _, h := range skip {
		skipMap[h] = true
	}

	for key, values := range resp.Header {
		if skipMap[key] {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}

// CopyHeaders copies headers from source to destination
func CopyHeaders(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// WriteResponse writes the response status, headers, and body
func WriteResponse(w http.ResponseWriter, resp *http.Response, buf []byte) error {
	CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	if buf != nil {
		_, err := io.CopyBuffer(w, resp.Body, buf)
		return err
	}

	_, err := io.Copy(w, resp.Body)
	return err
}

// WriteResponseWithBody writes response headers and a custom body
func WriteResponseWithBody(w http.ResponseWriter, resp *http.Response, body []byte) {
	CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}
