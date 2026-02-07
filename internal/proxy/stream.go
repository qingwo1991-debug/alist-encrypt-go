package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/rs/zerolog/log"
)

// Buffer pool for streaming - 512KB buffers for high-bitrate video
const streamBufferSize = 512 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, streamBufferSize)
		return &buf
	},
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
}

// NewStreamProxy creates a new stream proxy
func NewStreamProxy(cfg *config.Config) *StreamProxy {
	return &StreamProxy{
		client: NewClient(cfg),
		cfg:    cfg,
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
	req, err := httputil.NewRequest("GET", targetURL).
		WithContext(r.Context()).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return errors.NewProxyErrorWithCause("failed to fetch", err)
	}
	defer resp.Body.Close()

	// Get file size from Content-Length if not provided
	fileSize = resolveFileSize(fileSize, resp)

	// Create decryption stream
	flowEnc, err := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
	if err != nil {
		return errors.NewDecryptionErrorWithCause("failed to create cipher", err)
	}

	// Parse and validate Range header
	rangeReq, err := httputil.ParseRange(r.Header.Get("Range"), fileSize)
	if err != nil {
		// Invalid range - return 416 Range Not Satisfiable
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return nil
	}

	var requestedRange *httputil.Range
	isRangeRequest := rangeReq != nil && len(rangeReq.Ranges) > 0

	if isRangeRequest {
		if len(rangeReq.Ranges) > 1 {
			// Multi-range not supported - serve full content with 200
			isRangeRequest = false
		} else {
			requestedRange = &rangeReq.Ranges[0]
		}
	}

	// Set decryption position for range requests
	if isRangeRequest {
		if err := flowEnc.SetPosition(requestedRange.Start); err != nil {
			return errors.NewDecryptionErrorWithCause("failed to set position", err)
		}
	}

	// Copy only safe headers (NOT Content-Length, NOT Content-Range)
	httputil.CopySelectiveHeaders(w, resp, []string{
		"Content-Type",
		"Content-Disposition",
		"Cache-Control",
		"ETag",
		"Last-Modified",
	})

	// Always advertise range support
	w.Header().Set("Accept-Ranges", "bytes")

	var readerToStream io.Reader
	if isRangeRequest {
		// Partial content response
		w.Header().Set("Content-Length", strconv.FormatInt(requestedRange.ContentLength(), 10))
		w.Header().Set("Content-Range", requestedRange.ContentRangeHeader(fileSize))
		w.WriteHeader(http.StatusPartialContent) // 206

		// Limit stream output to exact range
		readerToStream = io.LimitReader(flowEnc.DecryptReader(resp.Body), requestedRange.ContentLength())
	} else {
		// Full content response
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		w.WriteHeader(http.StatusOK) // 200

		readerToStream = flowEnc.DecryptReader(resp.Body)
	}

	// Stream decrypted content with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, readerToStream, *buf)
	if err != nil {
		log.Error().Err(err).Msg("Error streaming decrypted content")
	}
	return err
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
	resp, err := s.client.Do(req)
	if err != nil {
		return errors.NewProxyErrorWithCause("failed to fetch", err)
	}
	defer resp.Body.Close()

	// Get file size from Content-Length if not provided
	fileSize = resolveFileSize(fileSize, resp)

	// Create decryption stream
	flowEnc, err := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
	if err != nil {
		return errors.NewDecryptionErrorWithCause("failed to create cipher", err)
	}

	// Parse and validate Range header
	rangeReq, err := httputil.ParseRange(req.Header.Get("Range"), fileSize)
	if err != nil {
		// Invalid range - return 416 Range Not Satisfiable
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return nil
	}

	var requestedRange *httputil.Range
	isRangeRequest := rangeReq != nil && len(rangeReq.Ranges) > 0

	if isRangeRequest {
		if len(rangeReq.Ranges) > 1 {
			// Multi-range not supported - serve full content with 200
			isRangeRequest = false
		} else {
			requestedRange = &rangeReq.Ranges[0]
		}
	}

	// Set decryption position for range requests
	if isRangeRequest {
		if err := flowEnc.SetPosition(requestedRange.Start); err != nil {
			return errors.NewDecryptionErrorWithCause("failed to set position", err)
		}
	}

	// Copy only safe headers (NOT Content-Length, NOT Content-Range)
	httputil.CopySelectiveHeaders(w, resp, []string{
		"Content-Type",
		"Content-Disposition",
		"Cache-Control",
		"ETag",
		"Last-Modified",
	})

	// Always advertise range support
	w.Header().Set("Accept-Ranges", "bytes")

	var readerToStream io.Reader
	if isRangeRequest {
		// Partial content response
		w.Header().Set("Content-Length", strconv.FormatInt(requestedRange.ContentLength(), 10))
		w.Header().Set("Content-Range", requestedRange.ContentRangeHeader(fileSize))
		w.WriteHeader(http.StatusPartialContent) // 206

		// Limit stream output to exact range
		readerToStream = io.LimitReader(flowEnc.DecryptReader(resp.Body), requestedRange.ContentLength())
	} else {
		// Full content response
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		w.WriteHeader(http.StatusOK) // 200

		readerToStream = flowEnc.DecryptReader(resp.Body)
	}

	// Stream decrypted content with large buffer
	buf := getBuffer()
	defer putBuffer(buf)
	_, err = io.CopyBuffer(w, readerToStream, *buf)
	if err != nil {
		log.Error().Err(err).Msg("Error streaming decrypted content")
	}
	return err
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
