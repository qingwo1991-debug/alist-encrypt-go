package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/rs/zerolog/log"
)

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
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to proxy request: %w", err)
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream response body
	_, err = io.Copy(w, resp.Body)
	return err
}

// ProxyDownloadDecrypt downloads and decrypts content
func (s *StreamProxy) ProxyDownloadDecrypt(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64) error {
	req, err := http.NewRequestWithContext(r.Context(), "GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Parse Range header for position seeking
	var startPos int64
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		startPos = parseRangeStart(rangeHeader)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch: %w", err)
	}
	defer resp.Body.Close()

	// Get file size from Content-Length if not provided
	if fileSize == 0 {
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			fileSize, _ = strconv.ParseInt(cl, 10, 64)
		}
		// For partial content, try to get total from Content-Range
		if resp.StatusCode == http.StatusPartialContent {
			if cr := resp.Header.Get("Content-Range"); cr != "" {
				// Format: bytes start-end/total
				if idx := strings.LastIndex(cr, "/"); idx >= 0 {
					if total, err := strconv.ParseInt(cr[idx+1:], 10, 64); err == nil && total > 0 {
						fileSize = total
					}
				}
			}
		}
	}

	// Create decryption stream
	flowEnc, err := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Set position for Range requests
	if startPos > 0 {
		if err := flowEnc.SetPosition(startPos); err != nil {
			return fmt.Errorf("failed to set position: %w", err)
		}
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream decrypted content
	decryptedReader := flowEnc.DecryptReader(resp.Body)
	_, err = io.Copy(w, decryptedReader)
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
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	encryptedBody := flowEnc.EncryptReader(r.Body)

	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, encryptedBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload: %w", err)
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	return err
}

// parseRangeStart parses the start position from Range header
func parseRangeStart(rangeHeader string) int64 {
	// Format: bytes=start-end or bytes=start-
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0
	}
	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeSpec, "-")
	if len(parts) < 1 {
		return 0
	}
	start, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	return start
}
