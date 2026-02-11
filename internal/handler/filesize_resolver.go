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
	fileDAO          *dao.FileDAO
	metaStore        FileMetaStore
	semaphore        chan struct{} // Limit concurrent HTTP requests
	maxWorkers       int
	minMetaSizeBytes int64

	providerMeta sync.Map // provider host -> *providerMetaState

	// Connection pool - reuse connections
	client *http.Client

	// Circuit breaker state per host
	circuitBreakers sync.Map // host -> *CircuitBreaker

	// Stats
	totalRequests uint64
	cacheHits     uint64
	propfindHits  uint64
	headHits      uint64
	rangeHits     uint64
	failures      uint64
	earlyReturns  uint64
	circuitBreaks uint64
}

type providerMetaState struct {
	mu        sync.Mutex
	conflicts int
	disabled  bool
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	failures    int32
	lastFailure int64 // Unix nano
	state       int32 // 0=closed, 1=open, 2=half-open
}

const (
	cbClosed   = 0
	cbOpen     = 1
	cbHalfOpen = 2

	cbFailureThreshold = 5                // Open after 5 consecutive failures
	cbResetTimeout     = 30 * time.Second // Try again after 30 seconds
)

// NewFileSizeResolver creates a new file size resolver
func NewFileSizeResolver(fileDAO *dao.FileDAO, metaStore FileMetaStore, maxWorkers int, minMetaSizeBytes int64) *FileSizeResolver {
	if maxWorkers <= 0 {
		maxWorkers = 20
	}

	// Connection pool with keep-alive
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}

	return &FileSizeResolver{
		fileDAO:          fileDAO,
		metaStore:        metaStore,
		semaphore:        make(chan struct{}, maxWorkers),
		maxWorkers:       maxWorkers,
		minMetaSizeBytes: minMetaSizeBytes,
		client: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
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
	Path        string
	Size        int64
	Source      SizeSource
	Confidence  int // 0-100, higher is more confident
	ContentType string
	StatusCode  int
	ETag        string
	Error       error
}

// FileItem represents a file to resolve size for
type FileItem struct {
	DisplayPath   string
	EncryptedPath string
	TargetURL     string
	FileName      string
	PropfindSize  int64
}

// MinValidFileSize is the minimum size for a valid file (1KB)
const MinValidFileSize = 1024

// MinVideoFileSize is the minimum expected size for video files (100KB)
const MinVideoFileSize = 100 * 1024

// HighConfidenceThreshold - if confidence >= this, return early
const HighConfidenceThreshold = 80

// IsValidSize checks if a file size is reasonable
func IsValidSize(size int64) bool {
	return size >= MinValidFileSize
}

// IsLikelyVideoSize checks if size is reasonable for video content
func IsLikelyVideoSize(size int64) bool {
	return size >= MinVideoFileSize
}

// ResolveBatch resolves file sizes for multiple files in parallel
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

			select {
			case <-ctx.Done():
				results[idx] = SizeResult{Path: file.DisplayPath, Error: ctx.Err()}
				return
			default:
			}

			result := r.ResolveSingle(ctx, file, authHeaders)
			results[idx] = result

			if result.Size > 0 && result.Error == nil {
				r.cacheResult(ctx, file, result)
			}
		}(i, item)
	}

	wg.Wait()
	return results
}

// ResolveSingle resolves file size with early termination on high confidence
func (r *FileSizeResolver) ResolveSingle(ctx context.Context, file FileItem, authHeaders http.Header) SizeResult {
	atomic.AddUint64(&r.totalRequests, 1)

	// Fast path: Check cache first (synchronous, ~64ns)
	if result, ok := r.tryFastPath(ctx, file); ok {
		return result
	}

	// Slow path: parallel resolution with early termination
	return r.resolveWithEarlyTermination(ctx, file, authHeaders)
}

// ResolveSingleFresh resolves file size without using cached/meta sources
func (r *FileSizeResolver) ResolveSingleFresh(ctx context.Context, file FileItem, authHeaders http.Header) SizeResult {
	atomic.AddUint64(&r.totalRequests, 1)
	file.PropfindSize = 0
	result := r.resolveWithEarlyTermination(ctx, file, authHeaders)
	if result.Size > 0 && result.Error == nil {
		r.cacheResult(ctx, file, result)
	}
	return result
}

// tryFastPath attempts cache lookup before launching goroutines
func (r *FileSizeResolver) tryFastPath(ctx context.Context, file FileItem) (SizeResult, bool) {
	// Try MySQL meta store first
	if r.metaStore != nil {
		providerKey := ProviderKey(file.TargetURL, file.DisplayPath)
		if r.shouldUseMeta(providerKey) {
			if meta, ok, _ := r.metaStore.Get(ctx, providerKey, file.DisplayPath); ok && IsValidSize(meta.Size) && r.isMetaSizeValid(meta.Size) {
				confidence := r.calculateConfidence(meta.Size, file.FileName, SourceCache)
				atomic.AddUint64(&r.cacheHits, 1)
				return SizeResult{
					Path:        file.DisplayPath,
					Size:        meta.Size,
					Source:      SourceCache,
					Confidence:  confidence,
					ContentType: meta.ContentType,
					StatusCode:  meta.StatusCode,
				}, true
			}
		}
	}
	// Try display path
	if size, ok := r.fileDAO.GetFileSize(file.DisplayPath); ok && IsValidSize(size) {
		confidence := r.calculateConfidence(size, file.FileName, SourceCache)
		atomic.AddUint64(&r.cacheHits, 1)
		return SizeResult{
			Path:       file.DisplayPath,
			Size:       size,
			Source:     SourceCache,
			Confidence: confidence,
		}, true
	}

	// Try encrypted path
	if file.EncryptedPath != "" && file.EncryptedPath != file.DisplayPath {
		if size, ok := r.fileDAO.GetFileSize(file.EncryptedPath); ok && IsValidSize(size) {
			confidence := r.calculateConfidence(size, file.FileName, SourceCache)
			atomic.AddUint64(&r.cacheHits, 1)
			return SizeResult{
				Path:       file.DisplayPath,
				Size:       size,
				Source:     SourceCache,
				Confidence: confidence,
			}, true
		}
	}

	// Try PROPFIND size if valid
	if IsValidSize(file.PropfindSize) {
		confidence := r.calculateConfidence(file.PropfindSize, file.FileName, SourcePropfind)
		if confidence >= HighConfidenceThreshold {
			atomic.AddUint64(&r.propfindHits, 1)
			atomic.AddUint64(&r.earlyReturns, 1)
			return SizeResult{
				Path:       file.DisplayPath,
				Size:       file.PropfindSize,
				Source:     SourcePropfind,
				Confidence: confidence,
			}, true
		}
	}

	return SizeResult{}, false
}

// resolveWithEarlyTermination runs parallel resolution with early return
func (r *FileSizeResolver) resolveWithEarlyTermination(ctx context.Context, file FileItem, authHeaders http.Header) SizeResult {
	// Create cancellable context for early termination
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultChan := make(chan SizeResult, 4)
	var wg sync.WaitGroup
	var returned int32

	// Helper to send result and potentially trigger early return
	sendResult := func(result SizeResult) {
		select {
		case resultChan <- result:
			// If high confidence and valid, trigger early return
			if result.Error == nil && IsValidSize(result.Size) && result.Confidence >= HighConfidenceThreshold {
				if atomic.CompareAndSwapInt32(&returned, 0, 1) {
					atomic.AddUint64(&r.earlyReturns, 1)
					cancel() // Cancel other pending requests
				}
			}
		case <-ctx.Done():
		}
	}

	// Source 1: PROPFIND size (if not already checked in fast path)
	if file.PropfindSize > 0 && IsValidSize(file.PropfindSize) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendResult(SizeResult{
				Path:       file.DisplayPath,
				Size:       file.PropfindSize,
				Source:     SourcePropfind,
				Confidence: r.calculateConfidence(file.PropfindSize, file.FileName, SourcePropfind),
			})
		}()
	}

	// Source 2: HEAD request
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.tryHEADWithRetry(ctx, file, authHeaders, sendResult)
	}()

	// Source 3: Range request (most reliable, but slower)
	wg.Add(1)
	go func() {
		defer wg.Done()
		r.tryRangeWithRetry(ctx, file, authHeaders, sendResult)
	}()

	// Close channel when all sources complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results with early termination
	return r.collectResults(ctx, file, resultChan)
}

// collectResults gathers results and returns best one, supporting early termination
func (r *FileSizeResolver) collectResults(ctx context.Context, file FileItem, results <-chan SizeResult) SizeResult {
	var validResults []SizeResult
	var maxSize int64
	var highConfidenceResult *SizeResult

	timeout := time.After(12 * time.Second) // Overall timeout

	for {
		select {
		case result, ok := <-results:
			if !ok {
				// Channel closed, select best from collected results
				return r.selectBest(file, validResults, maxSize)
			}

			if result.Error != nil {
				continue
			}

			if IsValidSize(result.Size) {
				validResults = append(validResults, result)
				if result.Size > maxSize {
					maxSize = result.Size
				}

				// Early return on high confidence
				if result.Confidence >= HighConfidenceThreshold && highConfidenceResult == nil {
					highConfidenceResult = &result
					// Don't return immediately, collect a bit more for cross-validation
					// But set a short timeout
					go func() {
						time.Sleep(100 * time.Millisecond)
					}()
				}
			}

		case <-timeout:
			if len(validResults) > 0 {
				return r.selectBest(file, validResults, maxSize)
			}
			atomic.AddUint64(&r.failures, 1)
			return SizeResult{Path: file.DisplayPath, Error: ErrTimeout}

		case <-ctx.Done():
			if len(validResults) > 0 {
				return r.selectBest(file, validResults, maxSize)
			}
			return SizeResult{Path: file.DisplayPath, Error: ctx.Err()}
		}
	}
}

// tryHEADWithRetry attempts HEAD request with retry
func (r *FileSizeResolver) tryHEADWithRetry(ctx context.Context, file FileItem, authHeaders http.Header, sendResult func(SizeResult)) {
	host := extractHost(file.TargetURL)

	// Check circuit breaker
	if r.isCircuitOpen(host) {
		atomic.AddUint64(&r.circuitBreaks, 1)
		sendResult(SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: ErrCircuitOpen})
		return
	}

	// Acquire semaphore with timeout
	select {
	case r.semaphore <- struct{}{}:
		defer func() { <-r.semaphore }()
	case <-ctx.Done():
		sendResult(SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: ctx.Err()})
		return
	case <-time.After(5 * time.Second):
		sendResult(SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: ErrSemaphoreTimeout})
		return
	}

	// Retry loop
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(500 * time.Millisecond): // Backoff
			case <-ctx.Done():
				sendResult(SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: ctx.Err()})
				return
			}
		}

		size, contentType, etag, status, err := r.headRequest(ctx, file.TargetURL, authHeaders, 8*time.Second)
		if err == nil && IsValidSize(size) {
			r.recordSuccess(host)
			atomic.AddUint64(&r.headHits, 1)
			sendResult(SizeResult{
				Path:        file.DisplayPath,
				Size:        size,
				Source:      SourceHEAD,
				Confidence:  r.calculateConfidence(size, file.FileName, SourceHEAD),
				ContentType: contentType,
				StatusCode:  status,
				ETag:        etag,
			})
			return
		}
		lastErr = err
	}

	r.recordFailure(host)
	sendResult(SizeResult{Path: file.DisplayPath, Source: SourceHEAD, Error: lastErr})
}

// tryRangeWithRetry attempts Range request with retry
func (r *FileSizeResolver) tryRangeWithRetry(ctx context.Context, file FileItem, authHeaders http.Header, sendResult func(SizeResult)) {
	host := extractHost(file.TargetURL)

	if r.isCircuitOpen(host) {
		atomic.AddUint64(&r.circuitBreaks, 1)
		sendResult(SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: ErrCircuitOpen})
		return
	}

	select {
	case r.semaphore <- struct{}{}:
		defer func() { <-r.semaphore }()
	case <-ctx.Done():
		sendResult(SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: ctx.Err()})
		return
	case <-time.After(5 * time.Second):
		sendResult(SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: ErrSemaphoreTimeout})
		return
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-ctx.Done():
				sendResult(SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: ctx.Err()})
				return
			}
		}

		size, contentType, etag, status, err := r.rangeRequest(ctx, file.TargetURL, authHeaders, 8*time.Second)
		if err == nil && IsValidSize(size) {
			r.recordSuccess(host)
			atomic.AddUint64(&r.rangeHits, 1)
			sendResult(SizeResult{
				Path:        file.DisplayPath,
				Size:        size,
				Source:      SourceRange,
				Confidence:  r.calculateConfidence(size, file.FileName, SourceRange),
				ContentType: contentType,
				StatusCode:  status,
				ETag:        etag,
			})
			return
		}
		lastErr = err
	}

	r.recordFailure(host)
	sendResult(SizeResult{Path: file.DisplayPath, Source: SourceRange, Error: lastErr})
}

// selectBest chooses the best result from collected results
func (r *FileSizeResolver) selectBest(file FileItem, validResults []SizeResult, maxSize int64) SizeResult {
	if len(validResults) == 0 {
		atomic.AddUint64(&r.failures, 1)
		return SizeResult{Path: file.DisplayPath, Error: ErrNoValidSize}
	}

	if len(validResults) == 1 {
		r.recordSourceHit(validResults[0].Source)
		return validResults[0]
	}

	// Find best by score
	var best SizeResult
	for _, result := range validResults {
		score := float64(result.Size) * float64(result.Confidence)
		bestScore := float64(best.Size) * float64(best.Confidence)
		if score > bestScore {
			best = result
		}
	}

	// Cross-validation: if best is much smaller than max, prefer max
	if best.Size < maxSize/2 && IsLikelyVideoSize(maxSize) {
		for _, result := range validResults {
			if result.Size == maxSize {
				log.Debug().
					Str("path", file.DisplayPath).
					Int64("selected", maxSize).
					Int64("rejected", best.Size).
					Msg("Cross-validation: selected larger size")
				r.recordSourceHit(result.Source)
				return result
			}
		}
	}

	r.recordSourceHit(best.Source)
	return best
}

// calculateConfidence returns confidence score
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
		base = 75
	}

	if isVideoFile(fileName) && IsLikelyVideoSize(size) {
		base += 20 // Higher bonus for video
	} else if IsValidSize(size) {
		base += 5
	}

	if base > 100 {
		base = 100
	}
	return base
}

// Circuit breaker methods
func (r *FileSizeResolver) getCircuitBreaker(host string) *CircuitBreaker {
	cb, _ := r.circuitBreakers.LoadOrStore(host, &CircuitBreaker{})
	return cb.(*CircuitBreaker)
}

func (r *FileSizeResolver) isCircuitOpen(host string) bool {
	cb := r.getCircuitBreaker(host)
	state := atomic.LoadInt32(&cb.state)

	if state == cbClosed {
		return false
	}

	if state == cbOpen {
		lastFailure := atomic.LoadInt64(&cb.lastFailure)
		if time.Since(time.Unix(0, lastFailure)) > cbResetTimeout {
			atomic.CompareAndSwapInt32(&cb.state, cbOpen, cbHalfOpen)
			return false
		}
		return true
	}

	return false // half-open allows one request
}

func (r *FileSizeResolver) recordSuccess(host string) {
	cb := r.getCircuitBreaker(host)
	atomic.StoreInt32(&cb.failures, 0)
	atomic.StoreInt32(&cb.state, cbClosed)
}

func (r *FileSizeResolver) recordFailure(host string) {
	cb := r.getCircuitBreaker(host)
	failures := atomic.AddInt32(&cb.failures, 1)
	atomic.StoreInt64(&cb.lastFailure, time.Now().UnixNano())

	if failures >= cbFailureThreshold {
		atomic.StoreInt32(&cb.state, cbOpen)
	}
}

func (r *FileSizeResolver) recordSourceHit(source SizeSource) {
	switch source {
	case SourceCache:
		atomic.AddUint64(&r.cacheHits, 1)
	case SourcePropfind:
		atomic.AddUint64(&r.propfindHits, 1)
	case SourceHEAD:
		atomic.AddUint64(&r.headHits, 1)
	case SourceRange:
		atomic.AddUint64(&r.rangeHits, 1)
	}
}

// cacheResult stores the resolved size

func (r *FileSizeResolver) cacheResult(ctx context.Context, file FileItem, result SizeResult) {
	r.fileDAO.SetFileSize(file.DisplayPath, result.Size, 24*time.Hour)
	if file.EncryptedPath != "" && file.EncryptedPath != file.DisplayPath {
		r.fileDAO.SetFileSize(file.EncryptedPath, result.Size, 24*time.Hour)
	}

	if r.metaStore == nil {
		return
	}

	if result.StatusCode != http.StatusOK && result.StatusCode != http.StatusPartialContent {
		return
	}
	if result.ContentType != "" {
		contentType := strings.ToLower(result.ContentType)
		if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
			return
		}
	}
	if !IsValidSize(result.Size) || !r.isMetaSizeValid(result.Size) {
		return
	}

	providerKey := ProviderKey(file.TargetURL, file.DisplayPath)
	_ = r.metaStore.Upsert(ctx, FileMeta{
		ProviderKey:  providerKey,
		OriginalPath: file.DisplayPath,
		Size:         result.Size,
		ETag:         result.ETag,
		ContentType:  result.ContentType,
		StatusCode:   result.StatusCode,
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
	})
}

func (r *FileSizeResolver) RecordPlaybackSuccess(ctx context.Context, file FileItem, size int64, statusCode int, contentType, etag string) {
	providerKey := ProviderKey(file.TargetURL, file.DisplayPath)
	r.resetProviderMeta(providerKey)

	if r.metaStore == nil {
		return
	}
	if statusCode != http.StatusOK && statusCode != http.StatusPartialContent && statusCode != 0 {
		return
	}
	if !IsValidSize(size) || !r.isMetaSizeValid(size) {
		return
	}
	if contentType != "" {
		ct := strings.ToLower(contentType)
		if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") {
			return
		}
	}

	_ = r.metaStore.Upsert(ctx, FileMeta{
		ProviderKey:  providerKey,
		OriginalPath: file.DisplayPath,
		Size:         size,
		ETag:         etag,
		ContentType:  contentType,
		StatusCode:   statusCode,
		UpdatedAt:    time.Now(),
		LastAccessed: time.Now(),
	})
}

func (r *FileSizeResolver) RecordMetaConflict(providerKey string) {
	provider := providerHostFromKey(providerKey)
	state := r.getProviderMetaState(provider)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.conflicts++
	if state.conflicts >= 3 {
		state.conflicts = 0
		state.disabled = true
		log.Warn().Str("provider", provider).Msg("Meta conflicts reached threshold, disabling meta cache for provider")
	}
}

func (r *FileSizeResolver) shouldUseMeta(providerKey string) bool {
	provider := providerHostFromKey(providerKey)
	state, ok := r.providerMeta.Load(provider)
	if !ok {
		return true
	}
	metaState := state.(*providerMetaState)
	metaState.mu.Lock()
	defer metaState.mu.Unlock()
	return !metaState.disabled
}

func (r *FileSizeResolver) resetProviderMeta(providerKey string) {
	provider := providerHostFromKey(providerKey)
	state := r.getProviderMetaState(provider)
	state.mu.Lock()
	defer state.mu.Unlock()
	state.conflicts = 0
	state.disabled = false
}

func (r *FileSizeResolver) getProviderMetaState(provider string) *providerMetaState {
	if provider == "" {
		provider = "default"
	}
	state, _ := r.providerMeta.LoadOrStore(provider, &providerMetaState{})
	return state.(*providerMetaState)
}

func (r *FileSizeResolver) isMetaSizeValid(size int64) bool {
	if r.minMetaSizeBytes <= 0 {
		return true
	}
	return size >= r.minMetaSizeBytes
}

// headRequest performs HEAD request with specific timeout
func (r *FileSizeResolver) headRequest(ctx context.Context, url string, authHeaders http.Header, timeout time.Duration) (int64, string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return 0, "", "", 0, err
	}

	copyAuthHeaders(req, authHeaders)

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, "", "", resp.StatusCode, &SizeResolverError{Message: "HEAD failed", StatusCode: resp.StatusCode}
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		return 0, contentType, resp.Header.Get("ETag"), resp.StatusCode, &SizeResolverError{Message: "received non-media response"}
	}

	contentLen := resp.Header.Get("Content-Length")
	if contentLen == "" {
		return 0, contentType, resp.Header.Get("ETag"), resp.StatusCode, &SizeResolverError{Message: "no Content-Length"}
	}

	size, err := strconv.ParseInt(contentLen, 10, 64)
	return size, contentType, resp.Header.Get("ETag"), resp.StatusCode, err
}

// rangeRequest performs Range request with specific timeout
func (r *FileSizeResolver) rangeRequest(ctx context.Context, url string, authHeaders http.Header, timeout time.Duration) (int64, string, string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, "", "", 0, err
	}

	req.Header.Set("Range", "bytes=0-0")
	copyAuthHeaders(req, authHeaders)

	resp, err := r.client.Do(req)
	if err != nil {
		return 0, "", "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, "", "", resp.StatusCode, &SizeResolverError{Message: "Range failed", StatusCode: resp.StatusCode}
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json") {
		return 0, contentType, resp.Header.Get("ETag"), resp.StatusCode, &SizeResolverError{Message: "received non-media response"}
	}

	// Parse Content-Range: bytes 0-0/1234567
	contentRange := resp.Header.Get("Content-Range")
	if contentRange != "" {
		parts := strings.Split(contentRange, "/")
		if len(parts) == 2 && parts[1] != "*" {
			size, err := strconv.ParseInt(parts[1], 10, 64)
			return size, contentType, resp.Header.Get("ETag"), resp.StatusCode, err
		}
	}

	if resp.StatusCode == http.StatusOK {
		if contentLen := resp.Header.Get("Content-Length"); contentLen != "" {
			size, err := strconv.ParseInt(contentLen, 10, 64)
			return size, contentType, resp.Header.Get("ETag"), resp.StatusCode, err
		}
	}

	return 0, contentType, resp.Header.Get("ETag"), resp.StatusCode, &SizeResolverError{Message: "no size info"}
}

// Stats returns resolver statistics
func (r *FileSizeResolver) Stats() map[string]interface{} {
	total := atomic.LoadUint64(&r.totalRequests)
	cacheHits := atomic.LoadUint64(&r.cacheHits)
	propfindHits := atomic.LoadUint64(&r.propfindHits)
	headHits := atomic.LoadUint64(&r.headHits)
	rangeHits := atomic.LoadUint64(&r.rangeHits)
	failures := atomic.LoadUint64(&r.failures)
	earlyReturns := atomic.LoadUint64(&r.earlyReturns)
	circuitBreaks := atomic.LoadUint64(&r.circuitBreaks)

	hitRate := float64(0)
	if total > 0 {
		hitRate = float64(cacheHits+propfindHits+headHits+rangeHits) / float64(total) * 100
	}

	return map[string]interface{}{
		"total_requests": total,
		"cache_hits":     cacheHits,
		"propfind_hits":  propfindHits,
		"head_hits":      headHits,
		"range_hits":     rangeHits,
		"failures":       failures,
		"early_returns":  earlyReturns,
		"circuit_breaks": circuitBreaks,
		"hit_rate":       hitRate,
		"max_workers":    r.maxWorkers,
	}
}

// Helper functions
func copyAuthHeaders(req *http.Request, authHeaders http.Header) {
	for _, key := range []string{"Authorization", "Cookie"} {
		if values := authHeaders[key]; len(values) > 0 {
			for _, v := range values {
				req.Header.Add(key, v)
			}
		}
	}
}

func extractHost(url string) string {
	// Simple extraction: http://host:port/path -> host:port
	start := strings.Index(url, "://")
	if start == -1 {
		return url
	}
	rest := url[start+3:]
	end := strings.Index(rest, "/")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

func providerHostFromKey(providerKey string) string {
	if providerKey == "" {
		return ""
	}
	if idx := strings.Index(providerKey, "::"); idx >= 0 {
		return providerKey[:idx]
	}
	return providerKey
}

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
	ErrNoValidSize      = &SizeResolverError{Message: "no valid size from any source"}
	ErrCacheMiss        = &SizeResolverError{Message: "cache miss"}
	ErrInvalidSize      = &SizeResolverError{Message: "invalid size"}
	ErrCircuitOpen      = &SizeResolverError{Message: "circuit breaker open"}
	ErrSemaphoreTimeout = &SizeResolverError{Message: "semaphore timeout"}
	ErrTimeout          = &SizeResolverError{Message: "overall timeout"}
)
