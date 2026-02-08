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

// MinFileSizeForCache is the minimum file size to cache (1KB)
// This prevents caching error responses which are typically very small
const MinFileSizeForCache = 1024

// getFileSizeWithStrategy retrieves file size using learned strategy or fallback chain
func (h *WebDAVHandler) getFileSizeWithStrategy(davPath, realPath, targetURL string, r *http.Request) (int64, StrategyType) {
	dirPath := path.Dir(davPath)

	// Check if we have a learned strategy for this directory path
	if strategy, ok := h.strategyCache.GetStrategy(dirPath); ok {
		trace.Logf(r.Context(), "strategy", "Using learned strategy %s for path %s (success=%d)",
			strategy.Strategy, dirPath, strategy.SuccessCount)

		// Try the learned strategy directly
		size, err := h.executeStrategy(strategy.Strategy, davPath, realPath, targetURL, r)
		if err == nil && size > 0 {
			// Success! Record it
			h.strategyCache.RecordSuccess(dirPath, strategy.Strategy)
			return size, strategy.Strategy
		}

		// Strategy failed, record failure and invalidate
		trace.Logf(r.Context(), "strategy", "Learned strategy %s failed for path %s, invalidating",
			strategy.Strategy, dirPath)
		h.strategyCache.RecordFailure(dirPath, strategy.Strategy)
	}

	// No learned strategy or it failed - execute full fallback chain
	size, usedStrategy := h.fallbackChain(davPath, realPath, targetURL, r)

	// Record successful strategy
	if size > 0 {
		h.strategyCache.RecordSuccess(dirPath, usedStrategy)
		trace.Logf(r.Context(), "strategy", "Recorded strategy %s for path %s", usedStrategy, dirPath)
	}

	return size, usedStrategy
}

// executeStrategy executes a specific strategy to get file size
func (h *WebDAVHandler) executeStrategy(strategy StrategyType, davPath, realPath, targetURL string, r *http.Request) (int64, error) {
	switch strategy {
	case StrategyFileInfoCache:
		// Try file info cache
		if fileInfo, ok := h.fileDAO.Get(davPath); ok {
			return fileInfo.Size, nil
		}
		return 0, ErrStrategyFailed

	case StrategyFileSizeCache:
		// Try file size cache
		if size, ok := h.fileDAO.GetFileSize(realPath); ok {
			return size, nil
		}
		return 0, ErrStrategyFailed

	case StrategyHEADRequest:
		// Execute HEAD request
		return h.executeHEADRequest(targetURL, realPath, r)

	default:
		return 0, ErrStrategyFailed
	}
}

// fallbackChain executes the complete fallback chain
func (h *WebDAVHandler) fallbackChain(davPath, realPath, targetURL string, r *http.Request) (int64, StrategyType) {
	ctx := r.Context()

	// Level 1: File info cache (fastest, ~1μs)
	if fileInfo, ok := h.fileDAO.Get(davPath); ok {
		trace.Logf(ctx, "fallback", "Hit file info cache")
		return fileInfo.Size, StrategyFileInfoCache
	}

	// Level 2: File size cache (fast, ~1μs)
	if size, ok := h.fileDAO.GetFileSize(realPath); ok {
		trace.Logf(ctx, "fallback", "Hit file size cache")
		return size, StrategyFileSizeCache
	}

	// Level 3: HEAD request (slow, 10-50ms)
	trace.Logf(ctx, "fallback", "Cache miss, trying HEAD request")
	size, err := h.executeHEADRequest(targetURL, realPath, r)
	if err == nil && size > 0 {
		// Cache for 24 hours
		h.fileDAO.SetFileSize(realPath, size, 24*time.Hour)
		trace.Logf(ctx, "fallback", "HEAD request succeeded, size=%d", size)
		return size, StrategyHEADRequest
	}

	// All strategies failed
	trace.Logf(ctx, "fallback", "All strategies failed")
	return 0, ""
}

// executeHEADRequest sends a HEAD request to get file size
func (h *WebDAVHandler) executeHEADRequest(targetURL, realPath string, r *http.Request) (int64, error) {
	ctx := r.Context()

	// Log if we're copying auth headers
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

	// Validate HTTP status code
	if headResp.StatusCode != http.StatusOK {
		trace.Logf(ctx, "head-request", "HEAD request failed with status %d", headResp.StatusCode)
		return 0, fmt.Errorf("HEAD request failed with status %d", headResp.StatusCode)
	}

	// Log successful authentication
	trace.Logf(ctx, "head-request", "HEAD request succeeded with status 200")

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

		// Validate minimum size to prevent caching error responses
		if size < MinFileSizeForCache {
			trace.Logf(ctx, "head-request", "File size %d too small (min %d), likely error response",
				size, MinFileSizeForCache)
			return 0, fmt.Errorf("file size %d too small (min %d), likely error response",
				size, MinFileSizeForCache)
		}

		trace.Logf(ctx, "head-request", "HEAD request succeeded, size=%d", size)
		return size, nil
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
