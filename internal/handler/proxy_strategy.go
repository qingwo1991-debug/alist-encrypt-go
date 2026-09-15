package handler

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
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
		headURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), urlPrefix+realPath)
		size, err := h.executeHEADRequestHTTP(headURL, realPath, r)
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

	// Level 2.5: MySQL/meta resolver + Level 3: HEAD request. Cold cache:
	// instead of running these serial (up to 2-3 upstream RTTs on the
	// first-frame path), run them CONCURRENTLY and take the first good result.
	// Both are read-only upstream probes that independently backfill caches, so
	// parallelizing is safe and the user sees whichever returns first. This
	// matches the probeCandidateCandidates design used by the ContentMeta path.
	if h.sizeResolver != nil {
		trace.Logf(ctx, "fallback", "Cold cache: parallel resolver + HEAD")
		type strategyHit struct {
			size  int64
			strat StrategyType
			ok    bool
		}
		results := make(chan strategyHit, 2)
		var wg sync.WaitGroup
		authHeaders := make(http.Header)
		if auth := r.Header.Get("Authorization"); auth != "" {
			authHeaders.Set("Authorization", auth)
		}
		if cookie := r.Header.Get("Cookie"); cookie != "" {
			authHeaders.Set("Cookie", cookie)
		}
		headURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), urlPrefix+realPath)
		file := FileItem{
			DisplayPath:   displayPath,
			EncryptedPath: realPath,
			TargetURL:     headURL,
			FileName:      path.Base(displayPath),
		}

		if h.sizeResolver != nil {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result := h.sizeResolver.ResolveSingle(ctx, file, authHeaders)
				if result.Error == nil && result.Size > 0 {
					h.fileDAO.SetFileSize(realPath, result.Size, 24*time.Hour)
					results <- strategyHit{size: result.Size, strat: strategyFromSizeSource(result.Source), ok: true}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			size, err := h.executeHEADRequestHTTP(headURL, realPath, r)
			if err == nil && size > 0 {
				h.fileDAO.SetFileSize(realPath, size, 24*time.Hour)
				results <- strategyHit{size: size, strat: StrategyHEADRequest, ok: true}
			}
		}()

		go func() {
			wg.Wait()
			close(results)
		}()
		for hit := range results {
			if hit.ok {
				trace.Logf(ctx, "fallback", "Parallel strategy won via %s, size=%d", hit.strat, hit.size)
				return &dao.FileInfo{Path: displayPath, Size: hit.size}, hit.strat
			}
		}
		return &dao.FileInfo{Path: displayPath, Size: 0}, ""
	}

	// Resolver disabled: run the HEAD request alone.
	trace.Logf(ctx, "fallback", "Cache miss, trying HEAD request")
	headURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), urlPrefix+realPath)
	size, err := h.executeHEADRequestHTTP(headURL, realPath, r)
	if err == nil && size > 0 {
		h.fileDAO.SetFileSize(realPath, size, 24*time.Hour)
		trace.Logf(ctx, "fallback", "HEAD request succeeded, size=%d", size)
		return &dao.FileInfo{Path: displayPath, Size: size}, StrategyHEADRequest
	}

	// All strategies failed
	trace.Logf(ctx, "fallback", "All strategies failed, using size 0")
	return &dao.FileInfo{Path: displayPath, Size: 0}, ""
}

// executeHEADRequestHTTP sends a HEAD request to get file size (HTTP API version)
func (h *ProxyHandler) executeHEADRequestHTTP(headURL, realPath string, r *http.Request) (int64, error) {
	ctx := r.Context()

	// Log if we're copying auth headers
	hasAuth := r.Header.Get("Authorization") != ""
	hasCookie := r.Header.Get("Cookie") != ""
	trace.Logf(ctx, "head-request", "Building HEAD request (auth=%v, cookie=%v)", hasAuth, hasCookie)

	headReq, err := httputil.NewRequest("HEAD", headURL).
		WithContext(ctx).
		CopyHeadersExcept(r, "Host", "Content-Length", "Content-Type", "Accept-Encoding").
		Build()
	if err != nil {
		trace.Logf(ctx, "head-request", "Failed to build HEAD request: %v", err)
		return 0, err
	}

	// The caller may reach /d/ without credentials (raw browser URL, some WebDAV
	// clients). Alist's /d/ requires a token, so a bare HEAD returns 401 and the
	// size is misreported as unknown, forcing a slower full resolution chain.
	// Fall back to the configured scan identity when the request carries none.
	if headReq.Header.Get("Authorization") == "" && headReq.Header.Get("Cookie") == "" {
		injectProbeAuthFallback(headReq, h.cfg)
	}

	headResp, err := h.shortClient.Do(headReq)
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
		if !IsValidSize(size) {
			trace.Logf(ctx, "head-request", "File size %d too small (min %d), likely error response",
				size, MinValidFileSize)
			return 0, fmt.Errorf("file size %d too small (min %d), likely error response",
				size, MinValidFileSize)
		}

		trace.Logf(ctx, "head-request", "HEAD request succeeded, size=%d", size)
		return size, nil
	}

	return 0, ErrStrategyFailed
}

func strategyFromSizeSource(source SizeSource) StrategyType {
	switch source {
	case SourceCache, SourcePropfind:
		return StrategyFileInfoCache
	case SourceHEAD:
		return StrategyHEADRequest
	case SourceRange:
		return StrategyRangeRequest
	default:
		return ""
	}
}
