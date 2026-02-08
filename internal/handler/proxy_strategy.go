package handler

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/trace"
)

// getFileSizeWithStrategy retrieves file size using learned strategy or fallback chain (HTTP API version)
func (h *ProxyHandler) getFileSizeWithStrategy(displayPath, realPath, urlPrefix string, r *http.Request) (*dao.FileInfo, StrategyType) {
	dirPath := path.Dir(displayPath)

	// Check if we have a learned strategy for this directory path
	if strategy, ok := h.strategyCache.GetStrategy(dirPath); ok {
		trace.Logf(r.Context(), "strategy", "Using learned strategy %s for path %s (success=%d)",
			strategy.Strategy, dirPath, strategy.SuccessCount)

		// Try the learned strategy directly
		fileInfo, err := h.executeStrategyHTTP(strategy.Strategy, displayPath, realPath, urlPrefix, r)
		if err == nil && fileInfo.Size > 0 {
			// Success! Record it
			h.strategyCache.RecordSuccess(dirPath, strategy.Strategy)
			return fileInfo, strategy.Strategy
		}

		// Strategy failed, record failure and invalidate
		trace.Logf(r.Context(), "strategy", "Learned strategy %s failed for path %s, invalidating",
			strategy.Strategy, dirPath)
		h.strategyCache.RecordFailure(dirPath, strategy.Strategy)
	}

	// No learned strategy or it failed - execute full fallback chain
	fileInfo, usedStrategy := h.fallbackChainHTTP(displayPath, realPath, urlPrefix, r)

	// Record successful strategy
	if fileInfo.Size > 0 {
		h.strategyCache.RecordSuccess(dirPath, usedStrategy)
		trace.Logf(r.Context(), "strategy", "Recorded strategy %s for path %s", usedStrategy, dirPath)
	}

	return fileInfo, usedStrategy
}

// executeStrategyHTTP executes a specific strategy to get file size (HTTP API version)
func (h *ProxyHandler) executeStrategyHTTP(strategy StrategyType, displayPath, realPath, urlPrefix string, r *http.Request) (*dao.FileInfo, error) {
	switch strategy {
	case StrategyFileInfoCache:
		// Try file info cache
		if fileInfo, ok := h.fileDAO.Get(displayPath); ok {
			return fileInfo, nil
		}
		return nil, ErrStrategyFailed

	case StrategyFileSizeCache:
		// Try file size cache
		if size, ok := h.fileDAO.GetFileSize(realPath); ok {
			return &dao.FileInfo{Path: displayPath, Size: size}, nil
		}
		return nil, ErrStrategyFailed

	case StrategyHEADRequest:
		// Execute HEAD request
		headURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), urlPrefix+realPath, r)
		size, err := h.executeHEADRequestHTTP(headURL, realPath, r.Context())
		if err != nil {
			return nil, err
		}
		return &dao.FileInfo{Path: displayPath, Size: size}, nil

	default:
		return nil, ErrStrategyFailed
	}
}

// fallbackChainHTTP executes the complete fallback chain (HTTP API version)
func (h *ProxyHandler) fallbackChainHTTP(displayPath, realPath, urlPrefix string, r *http.Request) (*dao.FileInfo, StrategyType) {
	ctx := r.Context()

	// Level 1: File info cache (fastest, ~1μs)
	if fileInfo, ok := h.fileDAO.Get(displayPath); ok {
		trace.Logf(ctx, "fallback", "Hit file info cache")
		return fileInfo, StrategyFileInfoCache
	}

	// Level 2: File size cache (fast, ~1μs)
	if size, ok := h.fileDAO.GetFileSize(realPath); ok {
		trace.Logf(ctx, "fallback", "Hit file size cache")
		return &dao.FileInfo{Path: displayPath, Size: size}, StrategyFileSizeCache
	}

	// Level 3: HEAD request (slow, 10-50ms)
	trace.Logf(ctx, "fallback", "Cache miss, trying HEAD request")
	headURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), urlPrefix+realPath, r)
	size, err := h.executeHEADRequestHTTP(headURL, realPath, ctx)
	if err == nil && size > 0 {
		// Cache for 24 hours
		h.fileDAO.SetFileSize(realPath, size, 24*time.Hour)
		trace.Logf(ctx, "fallback", "HEAD request succeeded, size=%d", size)
		return &dao.FileInfo{Path: displayPath, Size: size}, StrategyHEADRequest
	}

	// All strategies failed
	trace.Logf(ctx, "fallback", "All strategies failed, using size 0")
	return &dao.FileInfo{Path: displayPath, Size: 0}, ""
}

// executeHEADRequestHTTP sends a HEAD request to get file size (HTTP API version)
func (h *ProxyHandler) executeHEADRequestHTTP(headURL, realPath string, ctx context.Context) (int64, error) {
	headReq, err := httputil.NewRequest("HEAD", headURL).
		WithContext(ctx).
		Build()
	if err != nil {
		return 0, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	headResp, err := client.Do(headReq)
	if err != nil {
		return 0, err
	}
	defer headResp.Body.Close()

	// Validate HTTP status code
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
