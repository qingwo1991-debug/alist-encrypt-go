package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	stderrors "errors"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/rs/zerolog/log"
)

// Buffer pool for streaming - default 512KB buffers for high-bitrate video
var streamBufferSize = 512 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, streamBufferSize)
		return &buf
	},
}

func clampStreamBufferKB(kb int) int {
	if kb < 32 {
		return 32
	}
	if kb > 4096 {
		return 4096
	}
	return kb
}

func applyStreamBufferConfig(cfg *config.Config) {
	if cfg == nil || cfg.AlistServer.StreamBufferKb <= 0 {
		return
	}
	effectiveKB := clampStreamBufferKB(cfg.AlistServer.StreamBufferKb)
	streamBufferSize = effectiveKB * 1024
	bufferPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, streamBufferSize)
			return &buf
		},
	}
}

type rangeCompatCache struct {
	entries sync.Map // host -> time.Time (expiry)
}

func (c *rangeCompatCache) shouldSkip(host string, ttl time.Duration) bool {
	if host == "" || ttl <= 0 {
		return false
	}
	if val, ok := c.entries.Load(host); ok {
		if exp, ok2 := val.(time.Time); ok2 {
			if time.Now().Before(exp) {
				return true
			}
			c.entries.Delete(host)
		}
	}
	return false
}

func (c *rangeCompatCache) mark(host string, ttl time.Duration) {
	if host == "" || ttl <= 0 {
		return
	}
	c.entries.Store(host, time.Now().Add(ttl))
}

func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

func putBuffer(buf *[]byte) {
	bufferPool.Put(buf)
}

// GetBuffer exports buffer pool for other packages
func GetBuffer() *[]byte {
	return getBuffer()
}

// PutBuffer exports buffer pool for other packages
func PutBuffer(buf *[]byte) {
	putBuffer(buf)
}

// StreamProxy handles streaming proxy with encryption/decryption
type StreamProxy struct {
	client *Client
	cfg    *config.Config
	compat *rangeCompatCache
}

// StreamStrategy controls how range and streaming are handled.
type StreamStrategy string

const (
	StreamStrategyRange   StreamStrategy = "range"
	StreamStrategyChunked StreamStrategy = "chunked"
	StreamStrategyFull    StreamStrategy = "full"
)

// StreamOutcome describes the streaming result for strategy selection.
type StreamOutcome struct {
	Err             error
	Retryable       bool
	FailureReason   string
	BytesWritten    int64
	ExpectedBytes   int64
	ResponseStarted bool
}

// NewStreamProxy creates a new stream proxy
func NewStreamProxy(cfg *config.Config) *StreamProxy {
	applyStreamBufferConfig(cfg)
	return &StreamProxy{
		client: NewClient(cfg),
		cfg:    cfg,
		compat: &rangeCompatCache{},
	}
}

func (s *StreamProxy) rangeCompatTTL() time.Duration {
	if s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return 0
	}
	if s.cfg.AlistServer.RangeCompatTtlMinutes <= 0 {
		return 0
	}
	return time.Duration(s.cfg.AlistServer.RangeCompatTtlMinutes) * time.Minute
}

func (s *StreamProxy) rangeCompatHost(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func (s *StreamProxy) shouldSkipRange(targetURL string) bool {
	if s.compat == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return false
	}
	ttl := s.rangeCompatTTL()
	if ttl <= 0 {
		return false
	}
	return s.compat.shouldSkip(s.rangeCompatHost(targetURL), ttl)
}

func (s *StreamProxy) markRangeIncompatible(targetURL string) {
	if s.compat == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return
	}
	ttl := s.rangeCompatTTL()
	if ttl <= 0 {
		return
	}
	s.compat.mark(s.rangeCompatHost(targetURL), ttl)
}

// RangeCompatStats returns range compatibility cache stats
func (s *StreamProxy) RangeCompatStats() map[string]interface{} {
	count := 0
	if s.compat != nil {
		s.compat.entries.Range(func(_, _ interface{}) bool {
			count++
			return true
		})
	}

	return map[string]interface{}{
		"enabled": s.cfg != nil && s.cfg.AlistServer.EnableRangeCompatCache,
		"ttl_minutes": func() int {
			if s.cfg != nil {
				return s.cfg.AlistServer.RangeCompatTtlMinutes
			}
			return 0
		}(),
		"entries": count,
	}
}

// ProxyRequest forwards a request to the target and copies response
func (s *StreamProxy) ProxyRequest(w http.ResponseWriter, r *http.Request, targetURL string) error {
	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return errors.NewProxyErrorWithCause("failed to proxy request", err)
	}
	defer resp.Body.Close()

	// Copy response headers and write response
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Stream response body with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, resp.Body, *buf)
	return err
}

// ProxyDownloadDecrypt downloads and decrypts content
func (s *StreamProxy) ProxyDownloadDecrypt(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64) error {
	result := s.ProxyDownloadDecryptWithStrategy(w, r, targetURL, passwdInfo, fileSize, StreamStrategyRange)
	return result.Err
}

// ProxyDownloadDecryptWithStrategy downloads and decrypts content with strategy control.
func (s *StreamProxy) ProxyDownloadDecryptWithStrategy(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy) *StreamOutcome {
	// Handle empty files without decryption overhead
	if fileSize == 0 {
		w.Header().Set("Content-Length", "0")
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		return &StreamOutcome{ResponseStarted: true}
	}

	rangeHeader := r.Header.Get("Range")

	// Build request with client headers (including Range when present)
	req, err := httputil.NewRequest("GET", targetURL).
		WithContext(r.Context()).
		CopyHeaders(r).
		Build()
	if err != nil {
		return &StreamOutcome{Err: errors.NewInternalWithCause("failed to create request", err)}
	}
	applyStrategyHeaders(req, strategy)
	if rangeHeader != "" && s.shouldSkipRange(targetURL) {
		req.Header.Del("Range")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		reason, retryable := classifyStreamError(err)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	}

	// Handle redirects - Alist/WebDAV may return 302 to actual storage URL
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		resp.Body.Close()

		if location == "" {
			return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
		}

		log.Debug().Str("location", location).Msg("Following redirect for decryption")

		// Build new request to the redirect target
		redirectReq, err := httputil.NewRequest("GET", location).
			WithContext(r.Context()).
			CopyHeadersExcept(r, "Host").
			Build()
		if err != nil {
			return &StreamOutcome{Err: errors.NewInternalWithCause("failed to create redirect request", err)}
		}
		applyStrategyHeaders(redirectReq, strategy)
		if rangeHeader != "" && s.shouldSkipRange(location) {
			redirectReq.Header.Del("Range")
		}

		resp, err = s.client.Client.Do(redirectReq)
		if err != nil {
			reason, retryable := classifyStreamError(err)
			return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch from redirect", err), FailureReason: reason, Retryable: retryable}
		}
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, r, resp, targetURL, passwdInfo, fileSize, rangeHeader, strategy)
}

// ProxyUploadEncrypt uploads with encryption
func (s *StreamProxy) ProxyUploadEncrypt(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64) error {
	// Create encryption stream
	flowEnc, err := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
	if err != nil {
		return errors.NewEncryptionErrorWithCause("failed to create cipher", err)
	}

	encryptedBody := flowEnc.EncryptReader(r.Body)

	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(encryptedBody).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return errors.NewProxyErrorWithCause("failed to upload", err)
	}
	defer resp.Body.Close()

	// Copy response headers and write status
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	// Stream response with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, resp.Body, *buf)
	return err
}

// ProxyDownloadDecryptReq downloads and decrypts content using a pre-built request
func (s *StreamProxy) ProxyDownloadDecryptReq(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64) error {
	result := s.ProxyDownloadDecryptReqWithStrategy(w, req, targetURL, passwdInfo, fileSize, StreamStrategyRange)
	return result.Err
}

// ProxyDownloadDecryptReqWithStrategy downloads and decrypts using a pre-built request and strategy.
func (s *StreamProxy) ProxyDownloadDecryptReqWithStrategy(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy) *StreamOutcome {
	rangeHeader := req.Header.Get("Range")
	applyStrategyHeaders(req, strategy)
	if rangeHeader != "" && s.shouldSkipRange(targetURL) {
		req.Header.Del("Range")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		reason, retryable := classifyStreamError(err)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	}

	// Handle redirects - Alist/WebDAV may return 302 to actual storage URL
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		resp.Body.Close()

		if location == "" {
			return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
		}

		log.Debug().Str("location", location).Msg("Following redirect for decryption (req)")

		// Build new request to the redirect target
		redirectReq, err := httputil.NewRequest("GET", location).
			WithContext(req.Context()).
			CopyHeadersExcept(req, "Host").
			Build()
		if err != nil {
			return &StreamOutcome{Err: errors.NewInternalWithCause("failed to create redirect request", err)}
		}
		applyStrategyHeaders(redirectReq, strategy)
		if rangeHeader != "" && s.shouldSkipRange(location) {
			redirectReq.Header.Del("Range")
		}

		resp, err = s.client.Client.Do(redirectReq)
		if err != nil {
			reason, retryable := classifyStreamError(err)
			return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch from redirect", err), FailureReason: reason, Retryable: retryable}
		}
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, req, resp, targetURL, passwdInfo, fileSize, rangeHeader, strategy)
}

func applyStrategyHeaders(req *http.Request, strategy StreamStrategy) {
	if strategy == StreamStrategyFull {
		req.Header.Del("Range")
	}
}

func (s *StreamProxy) streamDecryptResponse(w http.ResponseWriter, req *http.Request, resp *http.Response, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, rangeHeader string, strategy StreamStrategy) *StreamOutcome {
	result := &StreamOutcome{}

	// Get file size from Content-Length if not provided
	fileSize = resolveFileSize(fileSize, resp)

	if strategy == StreamStrategyFull {
		rangeHeader = ""
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") && (rangeHeader != "" || fileSize > 0) {
		return &StreamOutcome{Retryable: true, FailureReason: "html_response"}
	}

	if rangeHeader != "" && (strategy == StreamStrategyRange || strategy == StreamStrategyChunked) {
		if resp.StatusCode != http.StatusPartialContent && resp.Header.Get("Content-Range") == "" {
			markURL := targetURL
			if resp.Request != nil && resp.Request.URL != nil {
				markURL = resp.Request.URL.String()
			}
			s.markRangeIncompatible(markURL)
			return &StreamOutcome{Retryable: true, FailureReason: "range_status"}
		}
	}

	if rangeHeader != "" && fileSize == 0 && strategy != StreamStrategyFull {
		return &StreamOutcome{Retryable: true, FailureReason: "size_unknown"}
	}

	// Create decryption stream
	flowEnc, err := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
	if err != nil {
		result.Err = errors.NewDecryptionErrorWithCause("failed to create cipher", err)
		return result
	}

	// Parse and validate Range header
	var requestedRange *httputil.Range
	var isRangeRequest bool

	if rangeHeader != "" {
		rangeReq, err := httputil.ParseRange(rangeHeader, fileSize)
		if err != nil {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			result.ResponseStarted = true
			return result
		}

		isRangeRequest = rangeReq != nil && len(rangeReq.Ranges) > 0
		if isRangeRequest {
			if len(rangeReq.Ranges) > 1 {
				isRangeRequest = false
			} else {
				requestedRange = &rangeReq.Ranges[0]
			}
		}
	}

	upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
	if rangeHeader != "" && !upstreamIsRange {
		markURL := targetURL
		if resp.Request != nil && resp.Request.URL != nil {
			markURL = resp.Request.URL.String()
		}
		s.markRangeIncompatible(markURL)
	}
	if isRangeRequest && upstreamIsRange {
		if err := flowEnc.SetPosition(requestedRange.Start); err != nil {
			result.Err = errors.NewDecryptionErrorWithCause("failed to set position", err)
			return result
		}
	}

	// Copy only safe headers (NOT Content-Length, NOT Content-Range, NOT ETag)
	httputil.CopySelectiveHeaders(w, resp, []string{
		"Content-Type",
		"Content-Disposition",
		"Cache-Control",
		"Last-Modified",
	})

	// Always advertise range support
	w.Header().Set("Accept-Ranges", "bytes")

	var readerToStream io.Reader
	decryptReader := flowEnc.DecryptReader(resp.Body)

	if isRangeRequest {
		if strategy == StreamStrategyRange {
			w.Header().Set("Content-Length", strconv.FormatInt(requestedRange.ContentLength(), 10))
		}
		w.Header().Set("Content-Range", requestedRange.ContentRangeHeader(fileSize))
		w.WriteHeader(http.StatusPartialContent)
		result.ResponseStarted = true
		result.ExpectedBytes = requestedRange.ContentLength()

		if !upstreamIsRange && requestedRange.Start > 0 {
			if _, err := io.CopyN(io.Discard, decryptReader, requestedRange.Start); err != nil {
				result.Err = errors.NewProxyErrorWithCause("failed to skip encrypted bytes", err)
				return result
			}
		}

		readerToStream = io.LimitReader(decryptReader, requestedRange.ContentLength())
	} else {
		if strategy != StreamStrategyChunked && fileSize > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
			result.ExpectedBytes = fileSize
		}
		w.WriteHeader(http.StatusOK)
		result.ResponseStarted = true
		readerToStream = decryptReader
	}

	buf := getBuffer()
	defer putBuffer(buf)
	written, err := io.CopyBuffer(w, readerToStream, *buf)
	result.BytesWritten = written
	if err != nil {
		log.Error().Err(err).Msg("Error streaming decrypted content")
		result.Err = err
		if result.ExpectedBytes > 0 && written < result.ExpectedBytes {
			result.FailureReason = "short_write"
			result.Retryable = false
			return result
		}
		reason, retryable := classifyStreamError(err)
		if result.FailureReason == "" {
			result.FailureReason = reason
		}
		result.Retryable = retryable
	}

	return result
}

func classifyStreamError(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	if stderrors.Is(err, context.DeadlineExceeded) {
		return "timeout", false
	}
	var netErr net.Error
	if stderrors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout", false
		}
		return "network_error", false
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer") {
		return "client_disconnect", false
	}
	if strings.Contains(msg, "timeout") {
		return "timeout", false
	}
	return "network_error", false
}

// resolveFileSize extracts file size from response headers if not provided
func resolveFileSize(cachedSize int64, resp *http.Response) int64 {
	// Priority 1: Use cached size from directory listing
	if cachedSize > 0 {
		return cachedSize
	}

	// Priority 2: Extract total from Content-Range (if upstream returned 206)
	if resp.StatusCode == http.StatusPartialContent {
		if cr := resp.Header.Get("Content-Range"); cr != "" {
			// Format: bytes start-end/total
			if idx := strings.LastIndex(cr, "/"); idx >= 0 {
				if total, err := strconv.ParseInt(cr[idx+1:], 10, 64); err == nil && total > 0 {
					return total
				}
			}
		}
	}

	// Priority 3: Use Content-Length (if full response)
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
			return size
		}
	}

	return 0
}
