package handler

import (
	"context"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/alist-encrypt-go/internal/dao"
	"github.com/rs/zerolog/log"
)

// FileSizeResolver provides robust file size resolution with multi-source validation
type FileSizeResolver struct {
	client      *http.Client
	fileDAO     *dao.FileDAO
	semaphore   chan struct{} // Limit concurrent HTTP requests
	maxWorkers  int

	// Stats
	totalRequests uint64
	cacheHits     uint64
	headHits      uint64
	rangeHits     uint64
	failures      uint64
}

// NewFileSizeResolver creates a new file size resolver
func NewFileSizeResolver(fileDAO *dao.FileDAO, maxWorkers int) *FileSizeResolver {
	if maxWorkers <= 0 {
		maxWorkers = 20 // Default: 20 concurrent HTTP requests
	}
	return &FileSizeResolver{
		client:     &http.Client{Timeout: 10 * time.Second},
		fileDAO:    fileDAO,
		semaphore:  make(chan struct{}, maxWorkers),
		maxWorkers: maxWorkers,
	}
}

// SizeSource represents a source of file size information
type SizeSource string

const (
	SourceCache    SizeSource = "cache"
	SourcePropfind SizeSource = "propfind"
	SourceHEAD     SizeSource = "head"
	SourceRange    SizeSource = "range"
)

// SizeResult holds the result from a size resolution attempt
type SizeResult struct {
	Path       string
	Size       int64
	Source     SizeSource
	Confidence int // 0-100, higher is more confident
	Error      error
}

// FileItem represents a file to resolve size for
type FileItem struct {
	DisplayPath   string
	EncryptedPath string
	TargetURL     string
	FileName      string
	PropfindSize  int64 // Size from PROPFIND (may be 0 or wrong)
}

// MinValidFileSize is the minimum size for a valid file (1KB)
const MinValidFileSize = 1024

// MinVideoFileSize is the minimum expected size for video files (100KB)
const MinVideoFileSize = 100 * 1024

// IsValidSize checks if a file size is reasonable
func IsValidSize(size int64) bool {
	return size >= MinValidFileSize
}

// IsLikelyVideoSize checks if size is reasonable for video content
func IsLikelyVideoSize(size int64) bool {
	return size >= MinVideoFileSize
}

// ResolveBatch resolves file sizes for multiple files in parallel
// Each file also uses multi-source parallel resolution internally
func (r *FileSizeResolver) ResolveBatch(ctx context.Context, items []FileItem, authHeaders http.Header) []SizeResult {
	if len(items) == 0 {
		return nil
	}

	results := make([]SizeResult, len(items))
	var wg sync.WaitGroup

	for i, item := range items {
		wg.Add(1)
		go func(idx int, file FileItem) {
			defer wg.Done()

			// Check context cancellation
			select {
			case <-ctx.Done():
				results[idx] = SizeResult{Path: file.DisplayPath, Error: ctx.Err()}
				return
			default:
			}

			// Resolve single file with multi-source
			result := r.ResolveSingle(ctx, file, authHeaders)
			results[idx] = result

			// Cache valid result
			if result.Size > 0 && result.Error == nil {
				r.cacheResult(file, result)
			}
		}(i, item)
	}

	wg.Wait()
	return results
}

// ResolveSingle resolves file size for a single file using multiple sources in parallel
func (r *FileSizeResolver) ResolveSingle(ctx context.Context, file FileItem, authHeaders http.Header) SizeResult {
	atomic.AddUint64(&r.totalRequests, 1)

	resultChan := make(chan SizeResult, 4)
	var wg sync.WaitGroup

	// Source 1: Cache lookup (instant, no semaphore needed)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.tryCache(file, resultChan)
	}()

	// Source 2: PROPFIND size (if provided and valid)
	if file.PropfindSize > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.tryPropfindSize(file, resultChan)
		}()
	}

	// Source 3: HEAD request (requires semaphore)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.tryHEAD(ctx, file, authHeaders, resultChan)
	}()

	// Source 4: Range request (requires semaphore, most reliable)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.tryRange(ctx, file, authHeaders, resultChan)
	}()

	// Close channel when all sources complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect and select best result
	return r.selectBest(ctx, file, resultChan)
}

// tryCache attempts to get size from cache
func (r *FileSizeResolver) tryCache(file FileItem, results chan<- SizeResult) {
	// Try display path first
	if size, ok := r.fileDAO.GetFileSize(file.DisplayPath); ok && IsValidSize(size) {
		results <- SizeResult{
			Path:       file.DisplayPath,
			Size:       size,
			Source:     SourceCache,
			Confidence: r.calculateConfidence(size, file.FileName, SourceCache),
		}
		return
	}

	// Try encrypted path
	if size, ok := r.fileDAO.GetFileSize(file.EncryptedPath); ok && IsValidSize(size) {
		results <- SizeResult{
			Path:       file.DisplayPath,
			Size:       size,
			Source:     SourceCache,
			Confidence: r.calculateConfidence(size, file.FileName, SourceCache),
		}
		return
	}

	// No cache hit
	results <- SizeResult{Path: file.DisplayPath, Source: SourceCache, Error: ErrCacheMiss}
}

// tryPropfindSize uses the size from PROPFIND response
func (r *FileSizeResolver) tryPropfindSize(file FileItem, results chan<- SizeResult) {
	if !IsValidSize(file.PropfindSize) {
		results <- SizeResult{Path: file.DisplayPath, Source: SourcePropfind, Error: ErrInvalidSize}
		return
	}

	results <- SizeResult{
		Path:       file.DisplayPath,
		Size:       file.PropfindSize,
		Source:     SourcePropfind,
		Confidence: r.calculateConfidence(file.PropfindSize, file.FileName, SourcePropfind),
	}
}

// tryHEAD attempts HEAD request with semaphore
func (r *FileSizeResolver) tryHEAD(ctx context.Context, file FileItem, authHeaders http.Header, results chan<- SizeResult) {
	// Acquire semaphore
	select {
	case r.semaphore <- struct{}{}:
		defer func() { <-r.semaphore }()
	case <-ctx.Done():
		results <- SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: ctx.Err()}
		return
	}

	size, err := r.headRequest(ctx, file.TargetURL, authHeaders)
	if err != nil {
		results <- SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: err}
		return
	}

	if !IsValidSize(size) {
		results <- SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: ErrInvalidSize}
		return
	}

	atomic.AddUint64(&r.headHits, 1)
	results <- SizeResult{
		Path:       file.DisplayPath,
		Size:       size,
		Source:     SourceHEAD,
		Confidence: r.calculateConfidence(size, file.FileName, SourceHEAD),
	}
}

// tryRange attempts Range request with semaphore
func (r *FileSizeResolver) tryRange(ctx context.Context, file FileItem, authHeaders http.Header, results chan<- SizeResult) {
	// Acquire semaphore
	select {
	case r.semaphore <- struct{}{}:
		defer func() { <-r.semaphore }()
	case <-ctx.Done():
		results <- SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: ctx.Err()}
		return
	}

	size, err := r.rangeRequest(ctx, file.TargetURL, authHeaders)
	if err != nil {
		results <- SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: err}
		return
	}

	if !IsValidSize(size) {
		results <- SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: ErrInvalidSize}
		return
	}

	atomic.AddUint64(&r.rangeHits, 1)
	results <- SizeResult{
		Path:       file.DisplayPath,
		Size:       size,
		Source:     SourceRange,
		Confidence: r.calculateConfidence(size, file.FileName, SourceRange),
	}
}

// calculateConfidence returns confidence score based on size, file type, and source
func (r *FileSizeResolver) calculateConfidence(size int64, fileName string, source SizeSource) int {
	base := 0
	switch source {
	case SourceCache:
		base = 50
	case SourcePropfind:
		base = 55
	case SourceHEAD:
		base = 65
	case SourceRange:
		base = 75 // Range is most reliable
	}

	// Bonus for reasonable video size
	if isVideoFile(fileName) && IsLikelyVideoSize(size) {
		base += 15
	} else if IsValidSize(size) {
		base += 5
	}

	if base > 100 {
		base = 100
	}
	return base
}

// selectBest chooses the best result from multiple sources
func (r *FileSizeResolver) selectBest(ctx context.Context, file FileItem, results <-chan SizeResult) SizeResult {
	var validResults []SizeResult
	var maxSize int64

	// Collect all results
	for result := range results {
		if result.Error != nil {
			continue
		}
		if result.Size > 0 {
			validResults = append(validResults, result)
			if result.Size > maxSize {
				maxSize = result.Size
			}
		}
	}

	if len(validResults) == 0 {
		atomic.AddUint64(&r.failures, 1)
		return SizeResult{
			Path:  file.DisplayPath,
			Error: ErrNoValidSize,
		}
	}

	// Strategy 1: If only one valid result, use it
	if len(validResults) == 1 {
		r.recordHit(validResults[0].Source)
		return validResults[0]
	}

	// Strategy 2: Cross-validation - if results differ significantly, prefer larger
	// Error responses (HTML pages, JSON errors) are typically small
	var best SizeResult
	for _, result := range validResults {
		// Score = size * confidence
		// This favors larger sizes with higher confidence
		score := float64(result.Size) * float64(result.Confidence)
		bestScore := float64(best.Size) * float64(best.Confidence)

		if score > bestScore {
			best = result
		}
	}

	// Strategy 3: If best is suspiciously smaller than max, use max
	if best.Size < maxSize/2 && IsLikelyVideoSize(maxSize) {
		for _, result := range validResults {
			if result.Size == maxSize {
				log.Debug().
					Str("path", file.DisplayPath).
					Int64("selected", maxSize).
					Int64("rejected", best.Size).
					Msg("Cross-validation: selected larger size")
				r.recordHit(result.Source)
				return result
			}
		}
	}

	r.recordHit(best.Source)
	return best
}

// recordHit updates hit statistics
func (r *FileSizeResolver) recordHit(source SizeSource) {
	switch source {
	case SourceCache:
		atomic.AddUint64(&r.cacheHits, 1)
	case SourceHEAD:
		atomic.AddUint64(&r.headHits, 1)
	case SourceRange:
		atomic.AddUint64(&r.rangeHits, 1)
	}
}

// cacheResult stores the resolved size in cache
func (r *FileSizeResolver) cacheResult(file FileItem, result SizeResult) {
	// Cache with both display and encrypted paths
	r.fileDAO.SetFileSize(file.DisplayPath, result.Size, 24*time.Hour)
	if file.EncryptedPath != "" && file.EncryptedPath != file.DisplayPath {
		r.fileDAO.SetFileSize(file.EncryptedPath, result.Size, 24*time.Hour)
	}
}

// headRequest performs a HEAD request to get Content-Length
func (r *FileSizeResolver) headRequest(ctx context.Context, url string, authHeaders http.Header) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return 0, err
	}

	// Copy auth headers
	copyAuthHeaders(req, authHeaders)

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, &SizeResolverError{Message: "HEAD failed", StatusCode: resp.StatusCode}
	}

	// Reject HTML responses (likely error pages)
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		return 0, &SizeResolverError{Message: "received HTML response"}
	}

	contentLen := resp.Header.Get("Content-Length")
	if contentLen == "" {
		return 0, &SizeResolverError{Message: "no Content-Length header"}
	}

	return strconv.ParseInt(contentLen, 10, 64)
}

// rangeRequest performs a Range request to get file size from Content-Range header
func (r *FileSizeResolver) rangeRequest(ctx context.Context, url string, authHeaders http.Header) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}

	// Request just the first byte
	req.Header.Set("Range", "bytes=0-0")
	copyAuthHeaders(req, authHeaders)

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// 206 Partial Content is expected for Range requests
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, &SizeResolverError{Message: "Range request failed", StatusCode: resp.StatusCode}
	}

	// Parse Content-Range header: "bytes 0-0/1234567"
	contentRange := resp.Header.Get("Content-Range")
	if contentRange != "" {
		parts := strings.Split(contentRange, "/")
		if len(parts) == 2 && parts[1] != "*" {
			return strconv.ParseInt(parts[1], 10, 64)
		}
	}

	// Fallback to Content-Length if full response (no Range support)
	if resp.StatusCode == http.StatusOK {
		contentLen := resp.Header.Get("Content-Length")
		if contentLen != "" {
			return strconv.ParseInt(contentLen, 10, 64)
		}
	}

	return 0, &SizeResolverError{Message: "no size info in response"}
}

// copyAuthHeaders copies authentication headers to the request
func copyAuthHeaders(req *http.Request, authHeaders http.Header) {
	for _, key := range []string{"Authorization", "Cookie"} {
		if values := authHeaders[key]; len(values) > 0 {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
	}
}

// Stats returns resolver statistics
func (r *FileSizeResolver) Stats() map[string]interface{} {
	total := atomic.LoadUint64(&r.totalRequests)
	cacheHits := atomic.LoadUint64(&r.cacheHits)
	headHits := atomic.LoadUint64(&r.headHits)
	rangeHits := atomic.LoadUint64(&r.rangeHits)
	failures := atomic.LoadUint64(&r.failures)

	return map[string]interface{}{
		"total_requests": total,
		"cache_hits":     cacheHits,
		"head_hits":      headHits,
		"range_hits":     rangeHits,
		"failures":       failures,
		"max_workers":    r.maxWorkers,
	}
}

// Error types
type SizeResolverError struct {
	Message    string
	StatusCode int
}

func (e *SizeResolverError) Error() string {
	if e.StatusCode > 0 {
		return e.Message + " (status " + strconv.Itoa(e.StatusCode) + ")"
	}
	return e.Message
}

var (
	ErrNoValidSize = &SizeResolverError{Message: "no valid file size from any source"}
	ErrCacheMiss   = &SizeResolverError{Message: "cache miss"}
	ErrInvalidSize = &SizeResolverError{Message: "invalid size"}
)

// isVideoFile checks if the filename suggests video content
func isVideoFile(fileName string) bool {
	ext := strings.ToLower(path.Ext(fileName))
	videoExts := map[string]bool{
		".mp4": true, ".mkv": true, ".avi": true, ".mov": true,
		".wmv": true, ".flv": true, ".webm": true, ".m4v": true,
		".ts": true, ".m2ts": true, ".mpg": true, ".mpeg": true,
		".rmvb": true, ".rm": true, ".3gp": true,
	}
	return videoExts[ext]
}
