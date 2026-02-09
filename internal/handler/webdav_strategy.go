package handler

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/trace"
)

// getFileSizeWithStrategy retrieves file size using learned strategy or multi-source resolver
func (h *WebDAVHandler) getFileSizeWithStrategy(davPath, realPath, targetURL string, r *http.Request) (int64, StrategyType) {
	ctx := r.Context()
	dirPath := path.Dir(davPath)
	fileName := path.Base(davPath)

	// Check if we have a learned strategy for this directory path
	if strategy, ok := h.strategyCache.GetStrategy(dirPath); ok {
		trace.Logf(ctx, "strategy", "Using learned strategy %s for path %s (success=%d)",
			strategy.Strategy, dirPath, strategy.SuccessCount)

		// Try the learned strategy directly (fast path)
		size, err := h.executeStrategy(strategy.Strategy, davPath, realPath, targetURL, r)
		if err == nil && size > 0 {
			h.strategyCache.RecordSuccess(dirPath, strategy.Strategy)
			return size, strategy.Strategy
		}

		// Strategy failed, record failure
		trace.Logf(ctx, "strategy", "Learned strategy %s failed for path %s, using multi-source resolver",
			strategy.Strategy, dirPath)
		h.strategyCache.RecordFailure(dirPath, strategy.Strategy)
	}

	// Use multi-source parallel resolver for robust file size retrieval
	file := FileItem{
		DisplayPath:   davPath,
		EncryptedPath: realPath,
		TargetURL:     targetURL,
		FileName:      fileName,
	}

	// Try to get PROPFIND size from cache first
	if fileInfo, ok := h.fileDAO.Get(davPath); ok {
		file.PropfindSize = fileInfo.Size
	}

	// Build auth headers
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}

	// Resolve with multi-source validation
	result := h.sizeResolver.ResolveSingle(ctx, file, authHeaders)

	if result.Error != nil {
		trace.Logf(ctx, "size-resolver", "All sources failed: %v", result.Error)
		return 0, ""
	}

	// Record successful source as strategy
	var usedStrategy StrategyType
	switch result.Source {
	case SourceCache:
		usedStrategy = StrategyFileInfoCache
	case SourcePropfind:
		usedStrategy = StrategyFileInfoCache
	case SourceHEAD:
		usedStrategy = StrategyHEADRequest
	case SourceRange:
		usedStrategy = StrategyRangeRequest
	}

	if result.Size > 0 {
		h.strategyCache.RecordSuccess(dirPath, usedStrategy)
		trace.Logf(ctx, "size-resolver", "Resolved size=%d from %s (confidence=%d)",
			result.Size, result.Source, result.Confidence)
	}

	return result.Size, usedStrategy
}

// executeStrategy executes a specific strategy to get file size (fast path for learned strategies)
func (h *WebDAVHandler) executeStrategy(strategy StrategyType, davPath, realPath, targetURL string, r *http.Request) (int64, error) {
	switch strategy {
	case StrategyFileInfoCache:
		// Try file info cache
		if fileInfo, ok := h.fileDAO.Get(davPath); ok && IsValidSize(fileInfo.Size) {
			return fileInfo.Size, nil
		}
		return 0, ErrStrategyFailed

	case StrategyFileSizeCache:
		// Try file size cache
		if size, ok := h.fileDAO.GetFileSize(realPath); ok && IsValidSize(size) {
			return size, nil
		}
		// Also try display path
		if size, ok := h.fileDAO.GetFileSize(davPath); ok && IsValidSize(size) {
			return size, nil
		}
		return 0, ErrStrategyFailed

	case StrategyHEADRequest:
		// Execute HEAD request
		return h.executeHEADRequest(targetURL, realPath, r)

	case StrategyRangeRequest:
		// Execute Range request
		return h.executeRangeRequest(targetURL, r)

	default:
		return 0, ErrStrategyFailed
	}
}

// executeHEADRequest sends a HEAD request to get file size
func (h *WebDAVHandler) executeHEADRequest(targetURL, realPath string, r *http.Request) (int64, error) {
	ctx := r.Context()

	hasAuth := r.Header.Get("Authorization") != ""
	hasCookie := r.Header.Get("Cookie") != ""
	trace.Logf(ctx, "head-request", "Building HEAD request (auth=%v, cookie=%v)", hasAuth, hasCookie)

	headReq, err := httputil.NewRequest("HEAD", targetURL).
		WithContext(ctx).
		CopyHeadersExcept(r, "Host", "Content-Length", "Content-Type", "Accept-Encoding").
		Build()
	if err != nil {
		trace.Logf(ctx, "head-request", "Failed to build HEAD request: %v", err)
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	headResp, err := client.Do(headReq)
	if err != nil {
		trace.Logf(ctx, "head-request", "HEAD request failed: %v", err)
		return 0, err
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		trace.Logf(ctx, "head-request", "HEAD request failed with status %d", headResp.StatusCode)
		return 0, fmt.Errorf("HEAD request failed with status %d", headResp.StatusCode)
	}

	// Reject HTML error pages
	contentType := headResp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		trace.Logf(ctx, "head-request", "Received HTML response (likely error page)")
		return 0, fmt.Errorf("received HTML response (likely error page)")
	}

	if contentLen := headResp.Header.Get("Content-Length"); contentLen != "" {
		size, err := strconv.ParseInt(contentLen, 10, 64)
		if err != nil {
			return 0, err
		}

		// Validate minimum size
		if !IsValidSize(size) {
			trace.Logf(ctx, "head-request", "File size %d too small (min %d)", size, MinValidFileSize)
			return 0, fmt.Errorf("file size %d too small", size)
		}

		trace.Logf(ctx, "head-request", "HEAD request succeeded, size=%d", size)
		return size, nil
	}

	return 0, ErrStrategyFailed
}

// executeRangeRequest sends a Range request to get file size from Content-Range
func (h *WebDAVHandler) executeRangeRequest(targetURL string, r *http.Request) (int64, error) {
	ctx := r.Context()

	rangeReq, err := httputil.NewRequest("GET", targetURL).
		WithContext(ctx).
		WithHeader("Range", "bytes=0-0").
		CopyHeadersExcept(r, "Host", "Content-Length", "Content-Type", "Accept-Encoding", "Range").
		Build()
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(rangeReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Range request failed with status %d", resp.StatusCode)
	}

	// Parse Content-Range: bytes 0-0/1234567
	contentRange := resp.Header.Get("Content-Range")
	if contentRange != "" {
		parts := strings.Split(contentRange, "/")
		if len(parts) == 2 && parts[1] != "*" {
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err == nil && IsValidSize(size) {
				trace.Logf(ctx, "range-request", "Range request succeeded, size=%d", size)
				return size, nil
			}
		}
	}

	// Fallback to Content-Length for servers that don't support Range
	if resp.StatusCode == http.StatusOK {
		if contentLen := resp.Header.Get("Content-Length"); contentLen != "" {
			size, err := strconv.ParseInt(contentLen, 10, 64)
			if err == nil && IsValidSize(size) {
				return size, nil
			}
		}
	}

	return 0, ErrStrategyFailed
}

// ErrStrategyFailed indicates the strategy execution failed
var ErrStrategyFailed = &StrategyError{Message: "strategy failed"}

type StrategyError struct {
	Message string
}

func (e *StrategyError) Error() string {
	return e.Message
}
