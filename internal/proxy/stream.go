package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	stderrors "errors"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/rs/zerolog/log"
)

// Pre-compiled regex for Content-Disposition rewriting (avoids per-request compilation)
var contentDispositionRe = regexp.MustCompile(`(?i)filename\*?=[^;]*;?`)

// Buffer pool for streaming - default 512KB buffers for high-bitrate video
var streamBufferSize int64 = 512 * 1024

var bufferPool = sync.Pool{
	New: func() interface{} {
		size := atomic.LoadInt64(&streamBufferSize)
		buf := make([]byte, size)
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
	newSize := int64(effectiveKB * 1024)
	atomic.StoreInt64(&streamBufferSize, newSize)
	// No need to replace bufferPool — the pool's New func already reads
	// atomic.LoadInt64(&streamBufferSize), so new allocations automatically
	// pick up the updated size. Old buffers remain valid until recycled.
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
	client           *Client
	cfg              *config.Config
	compatStore      RangeCompatStore
	redirectRewriter RedirectRewriter
	rangeStats       *rangeLearningStats
	playbackHintsMu  sync.RWMutex
	playbackHints    map[string]recentPlaybackHint
	playbackHintHits uint64
	chunkedHintHits  uint64
	rangeHintHits    uint64
	fullHintHits     uint64
	cbGate           *backoff.Gate    // circuit breaker for upstream failures
	retrier          *backoff.Retrier // retry with jitter for transient network errors
	uploadMetaMu     sync.Mutex
	uploadMeta       map[string]uploadMetaEntry
}

type contentMetaContextKey struct{}

type uploadMetaEntry struct {
	Meta      encryption.ContentMeta
	ExpiresAt time.Time
}

const uploadMetaTTL = 30 * time.Minute

// RedirectRewriter can rewrite upstream redirect locations for decrypt streams.
// Return the new location and true if rewritten.
type RedirectRewriter func(req *http.Request, location string, fileSize int64, passwdInfo *config.PasswdInfo) (string, bool)

// StreamStrategy controls how range and streaming are handled.
type StreamStrategy string

const (
	StreamStrategyRange   StreamStrategy = "range"
	StreamStrategyChunked StreamStrategy = "chunked"
	StreamStrategyFull    StreamStrategy = "full"
)

type recentPlaybackHint struct {
	Strategy  StreamStrategy
	UpdatedAt time.Time
}

const firstFrameWindowBytes int64 = 2 * 1024 * 1024
const recentPlaybackHintTTL = 2 * time.Minute

// SelectOptimalStrategy picks the single best strategy based on cached range
// compatibility, playback hints, and the request shape (first-frame seek etc).
func (s *StreamProxy) SelectOptimalStrategy(targetURL, storageKey, method, rangeHeader string) StreamStrategy {
	profile := classifyRequestRange(method, rangeHeader)

	// Check recent playback hint first (fastest path)
	if hinted, ok := s.recentPlaybackStrategy(targetURL, storageKey, profile); ok {
		return hinted
	}

	if !profile.HasRange {
		if s.shouldSkipRange(targetURL, storageKey) {
			return StreamStrategyFull
		}
		return StreamStrategyRange
	}

	if s.shouldSkipRange(targetURL, storageKey) {
		if profile.IsFirstFrameHint {
			return StreamStrategyChunked
		}
		maxDiscard := s.chunkedSeekMaxDiscardBytes()
		if maxDiscard <= 0 || profile.Start <= maxDiscard {
			return StreamStrategyChunked
		}
		return StreamStrategyFull
	}

	return StreamStrategyRange
}

// IsFirstFrameRangeHint reports whether the request looks like a first-frame
// read, such as bytes=0- or a small bounded window starting at 0.
func IsFirstFrameRangeHint(method, rangeHeader string) bool {
	return classifyRequestRange(method, rangeHeader).IsFirstFrameHint
}

// RecordPlaybackHint records a successful playback strategy for quick reuse.
func (s *StreamProxy) RecordPlaybackHint(targetURL, storageKey string, strategy StreamStrategy) {
	key := s.hintKeyFor(targetURL, storageKey)
	s.playbackHintsMu.Lock()
	defer s.playbackHintsMu.Unlock()
	if s.playbackHints == nil {
		s.playbackHints = make(map[string]recentPlaybackHint)
	}
	s.playbackHints[key] = recentPlaybackHint{Strategy: strategy, UpdatedAt: time.Now()}
	atomic.AddUint64(&s.playbackHintHits, 1)
	switch strategy {
	case StreamStrategyRange:
		atomic.AddUint64(&s.rangeHintHits, 1)
	case StreamStrategyChunked:
		atomic.AddUint64(&s.chunkedHintHits, 1)
	case StreamStrategyFull:
		atomic.AddUint64(&s.fullHintHits, 1)
	}
}

func (s *StreamProxy) hintKeyFor(targetURL, storageKey string) string {
	return targetURL + "|" + storageKey
}

func (s *StreamProxy) recentPlaybackStrategy(targetURL, storageKey string, profile requestRangeProfile) (StreamStrategy, bool) {
	s.playbackHintsMu.RLock()
	if s.playbackHints == nil {
		s.playbackHintsMu.RUnlock()
		return "", false
	}
	key := s.hintKeyFor(targetURL, storageKey)
	hint, ok := s.playbackHints[key]
	if !ok {
		s.playbackHintsMu.RUnlock()
		return "", false
	}
	if time.Since(hint.UpdatedAt) > recentPlaybackHintTTL {
		s.playbackHintsMu.RUnlock()
		s.playbackHintsMu.Lock()
		delete(s.playbackHints, key)
		s.playbackHintsMu.Unlock()
		return "", false
	}
	strategy := hint.Strategy
	s.playbackHintsMu.RUnlock()
	return strategy, true
}

// requestRangeProfile classifies a Range request.
type requestRangeProfile struct {
	HasRange         bool
	Start            int64
	End              int64
	HasExplicitEnd   bool
	EstimatedLength  int64
	IsFirstFrameHint bool
}

// StreamOutcome describes the streaming result for strategy selection.
type StreamOutcome struct {
	Err             error
	Retryable       bool
	FailureReason   string
	NoLearning      bool
	BytesWritten    int64
	ExpectedBytes   int64
	ResponseStarted bool
	StatusCode      int
	ContentType     string
	ETag            string
}

const defaultRangeCompatReprobe = 30 * time.Minute

// NewStreamProxy creates a new stream proxy
func NewStreamProxy(cfg *config.Config) *StreamProxy {
	applyStreamBufferConfig(cfg)
	cbThreshold := 5
	cbCooldown := 30 * time.Second
	retrier := backoff.DefaultRetrier()
	if cfg != nil {
		if cfg.AlistServer.CircuitBreakerThreshold > 0 {
			cbThreshold = cfg.AlistServer.CircuitBreakerThreshold
		}
		if cfg.AlistServer.CircuitBreakerCooldownSecs > 0 {
			cbCooldown = time.Duration(cfg.AlistServer.CircuitBreakerCooldownSecs) * time.Second
		}
		if cfg.AlistServer.RetryMaxAttempts >= 0 {
			retrier.MaxRetries = cfg.AlistServer.RetryMaxAttempts
		}
	}
	return &StreamProxy{
		client:        NewClient(cfg),
		cfg:           cfg,
		compatStore:   NewMemoryRangeCompatStore(),
		rangeStats:    newRangeLearningStats(),
		playbackHints: make(map[string]recentPlaybackHint),
		cbGate:        backoff.NewGate(cbThreshold, cbCooldown),
		retrier:       retrier,
		uploadMeta:    make(map[string]uploadMetaEntry),
	}
}

// SetRedirectRewriter registers a redirect rewriter for decrypt streams.
func (s *StreamProxy) SetRedirectRewriter(rewriter RedirectRewriter) {
	s.redirectRewriter = rewriter
}

// SetRangeCompatStore sets a persistent range compatibility store.
func (s *StreamProxy) SetRangeCompatStore(store RangeCompatStore) {
	if s == nil {
		return
	}
	if store == nil {
		s.compatStore = NewMemoryRangeCompatStore()
		return
	}
	s.compatStore = store
}

func (s *StreamProxy) rangeCompatReprobeInterval() time.Duration {
	if s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return 0
	}
	if s.cfg.AlistServer.RangeReprobeMinutes > 0 {
		return time.Duration(s.cfg.AlistServer.RangeReprobeMinutes) * time.Minute
	}
	return defaultRangeCompatReprobe
}

func (s *StreamProxy) rangeFailToDowngrade() int {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.RangeFailToDowngrade <= 0 {
		return 2
	}
	return s.cfg.AlistServer.RangeFailToDowngrade
}

func (s *StreamProxy) rangeSuccessToRecover() int {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.RangeSuccessToRecover <= 0 {
		return 3
	}
	return s.cfg.AlistServer.RangeSuccessToRecover
}

func (s *StreamProxy) rangeProbeTimeout() time.Duration {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.RangeProbeTimeoutSeconds <= 0 {
		return 8 * time.Second
	}
	return time.Duration(s.cfg.AlistServer.RangeProbeTimeoutSeconds) * time.Second
}

func (s *StreamProxy) chunkedSeekMaxDiscardBytes() int64 {
	if s == nil || s.cfg == nil || s.cfg.AlistServer.ChunkedSeekMaxDiscardBytes <= 0 {
		return 8 * 1024 * 1024
	}
	return s.cfg.AlistServer.ChunkedSeekMaxDiscardBytes
}

func (s *StreamProxy) rangeCompatHost(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	return parsed.Host
}

func normalizeCompatStorageKey(storageKey string) string {
	storageKey = strings.TrimSpace(storageKey)
	if storageKey == "" {
		return "/"
	}
	if !strings.HasPrefix(storageKey, "/") {
		storageKey = "/" + storageKey
	}
	out := strings.TrimRight(storageKey, "/")
	if out == "" {
		return "/"
	}
	return out
}

func (s *StreamProxy) rangeCompatKey(targetURL, storageKey string) string {
	host := s.rangeCompatHost(targetURL)
	if host == "" {
		return ""
	}
	return host + "::" + normalizeCompatStorageKey(storageKey)
}

func (s *StreamProxy) shouldSkipRange(targetURL, storageKey string) bool {
	if s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return false
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return false
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil || !ok {
		return false
	}
	if !state.Incompatible {
		return false
	}
	if state.NextProbeAt.IsZero() {
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.skipCount, 1)
		}
		return true
	}
	shouldSkip := time.Now().Before(state.NextProbeAt)
	if shouldSkip && s.rangeStats != nil {
		atomic.AddUint64(&s.rangeStats.skipCount, 1)
	}
	return shouldSkip
}

func (s *StreamProxy) recordRangeFailure(targetURL, storageKey, reason string) {
	if s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil {
		return
	}
	if !ok {
		state = RangeCompatState{}
	}
	now := time.Now()
	state.LastReason = reason
	state.LastCheckedAt = now
	state.LastAccessed = now
	state.UpdatedAt = now
	if reason != "range_unsatisfiable" {
		state.ConsecutiveFailures++
		state.ConsecutiveSuccesses = 0
		if state.ConsecutiveFailures >= s.rangeFailToDowngrade() {
			wasIncompatible := state.Incompatible
			state.Incompatible = true
			reprobe := s.rangeCompatReprobeInterval()
			if reprobe <= 0 {
				reprobe = defaultRangeCompatReprobe
			}
			state.NextProbeAt = now.Add(reprobe)
			if !wasIncompatible && s.rangeStats != nil {
				atomic.AddUint64(&s.rangeStats.downgradeCount, 1)
			}
		}
	} else {
		state.ConsecutiveFailures = 0
		state.ConsecutiveSuccesses = 0
	}
	if s.rangeStats != nil {
		if reason == "range_unsupported" {
			atomic.AddUint64(&s.rangeStats.reasonUnsupported, 1)
		}
		if reason == "range_unsatisfiable" {
			atomic.AddUint64(&s.rangeStats.reasonUnsatisfiable, 1)
		}
	}
	_ = s.compatStore.Upsert(key, state)
}

func (s *StreamProxy) recordRangeSuccess(targetURL, storageKey string) {
	if s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil {
		return
	}
	if !ok {
		state = RangeCompatState{}
	}
	now := time.Now()
	state.ConsecutiveSuccesses++
	state.ConsecutiveFailures = 0
	state.LastReason = ""
	state.LastCheckedAt = now
	state.LastAccessed = now
	state.UpdatedAt = now
	if state.Incompatible && state.ConsecutiveSuccesses >= s.rangeSuccessToRecover() {
		state.Incompatible = false
		state.NextProbeAt = time.Time{}
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.recoverCount, 1)
		}
	}
	_ = s.compatStore.Upsert(key, state)
}

// ShouldBackgroundProbeRange returns whether range capability should be probed in background.
func (s *StreamProxy) ShouldBackgroundProbeRange(targetURL, storageKey string) bool {
	if s == nil || s.compatStore == nil || s.cfg == nil || !s.cfg.AlistServer.EnableRangeCompatCache {
		return false
	}
	key := s.rangeCompatKey(targetURL, storageKey)
	if key == "" {
		return false
	}
	state, ok, err := s.compatStore.Get(key)
	if err != nil || !ok {
		return true // cold start
	}
	if state.Incompatible {
		return state.NextProbeAt.IsZero() || !time.Now().Before(state.NextProbeAt)
	}
	return false
}

// ProbeRangeCompatibility sends a lightweight range probe and updates learning state.
func (s *StreamProxy) ProbeRangeCompatibility(ctx context.Context, targetURL string, authHeaders http.Header, storageKey string) {
	if !s.ShouldBackgroundProbeRange(targetURL, storageKey) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.rangeStats != nil {
		atomic.AddUint64(&s.rangeStats.probeTotal, 1)
	}
	probeCtx, cancel := context.WithTimeout(ctx, s.rangeProbeTimeout())
	defer cancel()

	req, err := httputil.NewRequest(http.MethodGet, targetURL).
		WithContext(probeCtx).
		Build()
	if err != nil {
		return
	}
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("Accept-Encoding", "identity")
	copyProbeAuthHeaders(req, authHeaders)

	resp, err := s.client.Do(req)
	if err != nil {
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return
	}
	if resp.StatusCode == http.StatusPartialContent && resp.Header.Get("Content-Range") != "" {
		s.recordRangeSuccess(targetURL, storageKey)
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeSuccess, 1)
		}
		return
	}
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") == "" {
		s.recordRangeFailure(targetURL, storageKey, "range_unsupported")
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	if resp.StatusCode == http.StatusPartialContent && resp.Header.Get("Content-Range") == "" {
		s.recordRangeFailure(targetURL, storageKey, "range_unsupported")
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.pseudoRangeCount, 1)
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		s.recordRangeFailure(targetURL, storageKey, "range_unsatisfiable")
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
		return
	}
	if resp.StatusCode >= http.StatusBadRequest {
		if s.rangeStats != nil {
			atomic.AddUint64(&s.rangeStats.probeFailure, 1)
		}
	}
}

func copyProbeAuthHeaders(req *http.Request, src http.Header) {
	if req == nil || src == nil {
		return
	}
	if auth := src.Get("Authorization"); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if cookie := src.Get("Cookie"); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if ua := src.Get("User-Agent"); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
}

func (s *StreamProxy) inspectEncryptedContent(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) encryption.ContentMeta {
	encType := encryption.EncType(passwdInfo.EncType)
	meta := encryption.LegacyContentMeta(encType, ciphertextSize)
	if s == nil || passwdInfo == nil || !passwdInfo.Enable || strings.TrimSpace(targetURL) == "" {
		return meta
	}
	if ctx == nil {
		ctx = context.Background()
	}
	currentURL := strings.TrimSpace(targetURL)
	currentAuth := authHeaders
	maxHops := 2
	if s.cfg != nil && s.cfg.AlistServer.RedirectMaxHops > 0 {
		maxHops = s.cfg.AlistServer.RedirectMaxHops
	}
	for hop := 0; hop <= maxHops; hop++ {
		req, err := httputil.NewRequest(http.MethodGet, currentURL).
			WithContext(ctx).
			Build()
		if err != nil {
			return meta
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", encryption.ContentHeaderSize()-1))
		req.Header.Set("Accept-Encoding", "identity")
		copyProbeAuthHeaders(req, currentAuth)

		resp, err := s.client.Do(req)
		if err != nil {
			return meta
		}
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			resp.Body.Close()
			if location == "" {
				return meta
			}
			nextURL, err := resolveRedirectTarget(currentURL, location)
			if err != nil {
				return meta
			}
			currentURL = nextURL
			currentAuth = make(http.Header)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= http.StatusBadRequest {
			return meta
		}
		prefix, err := io.ReadAll(io.LimitReader(resp.Body, encryption.ContentHeaderSize()))
		if err != nil {
			return meta
		}
		if total := parseContentRangeTotal(resp.Header.Get("Content-Range")); total > 0 {
			meta.CiphertextSize = total
			meta.PlainSize = total
		} else if cl := resp.Header.Get("Content-Length"); cl != "" {
			if total, err := strconv.ParseInt(cl, 10, 64); err == nil && total > 0 && resp.StatusCode == http.StatusOK {
				meta.CiphertextSize = total
				meta.PlainSize = total
			}
		}
		if parsed, ok, err := encryption.ParseContentHeader(encType, prefix, meta.CiphertextSize); err == nil && ok {
			return parsed
		}
		return meta
	}
	return meta
}

func (s *StreamProxy) InspectEncryptedContent(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) encryption.ContentMeta {
	return s.inspectEncryptedContent(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize)
}

func resolveRedirectTarget(baseURL, location string) (string, error) {
	ref, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	if ref.IsAbs() {
		return ref.String(), nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

func buildUpstreamRangeHeader(rangeHeader string, meta encryption.ContentMeta) string {
	if !meta.IsV2() {
		return rangeHeader
	}
	rangeHeader = strings.TrimSpace(rangeHeader)
	if rangeHeader == "" || !strings.HasPrefix(rangeHeader, "bytes=") {
		return rangeHeader
	}
	parts := strings.SplitN(strings.TrimPrefix(rangeHeader, "bytes="), ",", 2)
	if len(parts) == 0 {
		return rangeHeader
	}
	spec := strings.TrimSpace(parts[0])
	bounds := strings.SplitN(spec, "-", 2)
	if len(bounds) != 2 {
		return rangeHeader
	}
	startText := strings.TrimSpace(bounds[0])
	endText := strings.TrimSpace(bounds[1])
	if startText == "" {
		return rangeHeader
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 {
		return rangeHeader
	}
	start += meta.HeaderLen
	if endText == "" {
		return fmt.Sprintf("bytes=%d-", start)
	}
	end, err := strconv.ParseInt(endText, 10, 64)
	if err != nil || end < start-meta.HeaderLen {
		return rangeHeader
	}
	end += meta.HeaderLen
	return fmt.Sprintf("bytes=%d-%d", start, end)
}

func WithContentMeta(ctx context.Context, meta encryption.ContentMeta) context.Context {
	return context.WithValue(ctx, contentMetaContextKey{}, meta)
}

func contentMetaFromContext(ctx context.Context, passwdInfo *config.PasswdInfo, fallbackSize int64) encryption.ContentMeta {
	encType := encryption.EncType("")
	if passwdInfo != nil {
		encType = encryption.EncType(passwdInfo.EncType)
	}
	meta := encryption.LegacyContentMeta(encType, fallbackSize)
	if ctx == nil {
		return meta
	}
	if v := ctx.Value(contentMetaContextKey{}); v != nil {
		if stored, ok := v.(encryption.ContentMeta); ok {
			if stored.PlainSize <= 0 {
				stored.PlainSize = fallbackSize
			}
			if stored.CiphertextSize <= 0 && stored.IsV2() && stored.PlainSize > 0 {
				stored.CiphertextSize = stored.PlainSize + stored.HeaderLen
			}
			if stored.EncType == "" {
				stored.EncType = encType
			}
			return stored
		}
	}
	return meta
}

func uploadMetaKey(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func (s *StreamProxy) getUploadMeta(targetURL string) (encryption.ContentMeta, bool) {
	if s == nil {
		return encryption.ContentMeta{}, false
	}
	key := uploadMetaKey(targetURL)
	s.uploadMetaMu.Lock()
	defer s.uploadMetaMu.Unlock()
	entry, ok := s.uploadMeta[key]
	if !ok {
		return encryption.ContentMeta{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(s.uploadMeta, key)
		return encryption.ContentMeta{}, false
	}
	return entry.Meta, true
}

func (s *StreamProxy) putUploadMeta(targetURL string, meta encryption.ContentMeta) {
	if s == nil || !meta.IsV2() {
		return
	}
	key := uploadMetaKey(targetURL)
	s.uploadMetaMu.Lock()
	defer s.uploadMetaMu.Unlock()
	s.uploadMeta[key] = uploadMetaEntry{
		Meta:      meta,
		ExpiresAt: time.Now().Add(uploadMetaTTL),
	}
}

// classifyRequestRange parses Range header into a profile for strategy selection.
func classifyRequestRange(method, rangeHeader string) requestRangeProfile {
	if method == http.MethodHead {
		return requestRangeProfile{}
	}
	rangeHeader = strings.TrimSpace(rangeHeader)
	if rangeHeader == "" {
		return requestRangeProfile{}
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return requestRangeProfile{}
	}
	rangeVal := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.SplitN(rangeVal, ",", 2)
	if len(parts) == 0 {
		return requestRangeProfile{}
	}
	rangeSpec := strings.TrimSpace(parts[0])
	kv := strings.SplitN(rangeSpec, "-", 2)
	if len(kv) != 2 {
		return requestRangeProfile{}
	}

	start, err := strconv.ParseInt(strings.TrimSpace(kv[0]), 10, 64)
	if err != nil || start < 0 {
		return requestRangeProfile{}
	}

	profile := requestRangeProfile{
		HasRange: true,
		Start:    start,
		End:      -1,
	}

	if endStr := strings.TrimSpace(kv[1]); endStr != "" {
		end, err := strconv.ParseInt(endStr, 10, 64)
		if err == nil && end >= start {
			profile.End = end
			profile.HasExplicitEnd = true
			profile.EstimatedLength = end - start + 1
		}
	}

	if start == 0 {
		if !profile.HasExplicitEnd {
			profile.IsFirstFrameHint = true
		} else if profile.EstimatedLength > 0 && profile.EstimatedLength <= firstFrameWindowBytes {
			profile.IsFirstFrameHint = true
		}
	}

	return profile
}

// RangeCompatStats returns range compatibility cache stats
func (s *StreamProxy) RangeCompatStats() map[string]interface{} {
	configStats := map[string]interface{}{
		"enabled": s.cfg != nil && s.cfg.AlistServer.EnableRangeCompatCache,
		"reprobe_minutes": func() int {
			if s.cfg != nil && s.cfg.AlistServer.RangeReprobeMinutes > 0 {
				return s.cfg.AlistServer.RangeReprobeMinutes
			}
			return int(defaultRangeCompatReprobe / time.Minute)
		}(),
		"fail_to_downgrade":  s.rangeFailToDowngrade(),
		"success_to_recover": s.rangeSuccessToRecover(),
		"probe_timeout_seconds": func() int {
			if s != nil && s.cfg != nil && s.cfg.AlistServer.RangeProbeTimeoutSeconds > 0 {
				return s.cfg.AlistServer.RangeProbeTimeoutSeconds
			}
			return 8
		}(),
	}
	runtimeStats := map[string]interface{}{}
	if s.rangeStats != nil {
		for k, v := range s.rangeStats.snapshot() {
			runtimeStats[k] = v
		}
	}
	storeStats := map[string]interface{}{"mode": "unknown"}
	if provider, ok := s.compatStore.(interface{ Stats() map[string]interface{} }); ok && provider != nil {
		for k, v := range provider.Stats() {
			storeStats[k] = v
		}
	}
	flat := map[string]interface{}{
		"config":  configStats,
		"runtime": runtimeStats,
		"store":   storeStats,
	}
	for k, v := range configStats {
		flat[k] = v
	}
	for k, v := range runtimeStats {
		flat[k] = v
	}
	for k, v := range storeStats {
		flat[k] = v
	}
	return flat
}

// ProxyRequest forwards a request to the target and copies response
func (s *StreamProxy) ProxyRequest(w http.ResponseWriter, r *http.Request, targetURL string) error {
	if !s.cbGate.Allow() {
		return errors.NewProxyError("upstream temporarily unavailable (circuit open)")
	}

	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}

	// Retry transient network errors with jittered exponential backoff
	var resp *http.Response
	var doErr error
	_ = s.retrier.Do(r.Context(), func() error {
		resp, doErr = s.client.Do(req)
		if doErr != nil {
			if backoff.IsTransient(doErr) {
				return doErr
			}
			return nil
		}
		if backoff.IsTransientStatus(resp.StatusCode) {
			resp.Body.Close()
			doErr = fmt.Errorf("upstream status %d", resp.StatusCode)
			return doErr
		}
		return nil
	})
	if doErr != nil {
		s.cbGate.RecordFailure()
		return errors.NewProxyErrorWithCause("failed to proxy request", doErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		s.cbGate.RecordFailure()
	} else {
		s.cbGate.RecordSuccess()
	}

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
	return s.ProxyDownloadDecryptWithStrategyForStorage(w, r, targetURL, passwdInfo, fileSize, strategy, "")
}

// ProxyDownloadDecryptWithStrategyForStorage downloads and decrypts content with storage-scoped range learning.
func (s *StreamProxy) ProxyDownloadDecryptWithStrategyForStorage(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy, compatStorageKey string) *StreamOutcome {
	if !s.cbGate.Allow() {
		return &StreamOutcome{
			Err:           errors.NewProxyError("upstream temporarily unavailable (circuit open)"),
			Retryable:     true,
			FailureReason: "circuit_open",
		}
	}

	rangeHeader := r.Header.Get("Range")
	meta := contentMetaFromContext(r.Context(), passwdInfo, fileSize)
	if meta.PlainSize > 0 {
		fileSize = meta.PlainSize
	}
	rangeSkipped := strategy == StreamStrategyRange && rangeHeader != "" && s.shouldSkipRange(targetURL, compatStorageKey)

	if rangeSkipped {
		return &StreamOutcome{
			Err:           errors.NewProxyError("range unsupported"),
			Retryable:     true,
			FailureReason: "range_unsupported",
		}
	}

	// Build request with client headers (including Range when present)
	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		CopyHeaders(r).
		Build()
	if err != nil {
		return &StreamOutcome{Err: errors.NewInternalWithCause("failed to create request", err)}
	}
	applyStrategyHeaders(req, strategy)
	if strategy == StreamStrategyRange {
		req.Header.Set("Range", buildUpstreamRangeHeader(rangeHeader, meta))
	}

	// Retry transient network errors with jittered exponential backoff
	var resp *http.Response
	var doErr error
	_ = s.retrier.Do(r.Context(), func() error {
		resp, doErr = s.client.Do(req)
		if doErr != nil {
			if backoff.IsTransient(doErr) {
				return doErr
			}
			return nil
		}
		if backoff.IsTransientStatus(resp.StatusCode) {
			resp.Body.Close()
			doErr = fmt.Errorf("upstream status %d", resp.StatusCode)
			return doErr
		}
		return nil
	})
	if doErr != nil {
		reason, retryable := classifyStreamError(doErr)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", doErr), FailureReason: reason, Retryable: retryable}
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		defer resp.Body.Close()
		return s.handleRedirect(w, r, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, r, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
}

// ProxyUploadEncrypt uploads with encryption.
// startOffset should be the absolute file offset for chunked/resume uploads.
func (s *StreamProxy) ProxyUploadEncrypt(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, startOffset int64) error {
	var (
		encryptedBody io.Reader
		contentMeta   encryption.ContentMeta
		err           error
	)
	if startOffset > 0 {
		meta, ok := s.getUploadMeta(targetURL)
		if !ok {
			meta = encryption.LegacyContentMeta(encryption.EncType(passwdInfo.EncType), fileSize)
		}
		if !meta.IsV2() && (strings.Contains(targetURL, "/dav/") || strings.HasSuffix(targetURL, "/dav")) {
			meta = s.inspectEncryptedContent(r.Context(), targetURL, r.Header, passwdInfo, fileSize)
		}
		if meta.IsV2() {
			cipherImpl, cipherErr := encryption.NewCipherV2(encryption.EncType(passwdInfo.EncType), passwdInfo.Password, meta.PlainSize, meta.NonceField)
			if cipherErr != nil {
				return errors.NewEncryptionErrorWithCause("failed to create v2 cipher", cipherErr)
			}
			if err := cipherImpl.SetPosition(startOffset); err != nil {
				return errors.NewEncryptionErrorWithCause("failed to set upload offset", err)
			}
			encryptedBody = cipherImpl.EncryptReader(r.Body)
			contentMeta = meta
		} else {
			flowEnc, cipherErr := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
			if cipherErr != nil {
				return errors.NewEncryptionErrorWithCause("failed to create cipher", cipherErr)
			}
			if err := flowEnc.SetPosition(startOffset); err != nil {
				return errors.NewEncryptionErrorWithCause("failed to set upload offset", err)
			}
			encryptedBody = flowEnc.EncryptReader(r.Body)
			contentMeta = meta
		}
	} else {
		contentEnc, cipherErr := encryption.NewLatestContentEncryptor(passwdInfo.Password, passwdInfo.EncType, fileSize)
		if cipherErr != nil {
			return errors.NewEncryptionErrorWithCause("failed to create cipher", cipherErr)
		}
		encryptedBody, err = contentEnc.EncryptReader(r.Body, startOffset)
		if err != nil {
			return errors.NewEncryptionErrorWithCause("failed to create encrypt reader", err)
		}
		contentMeta = contentEnc.Meta
		s.putUploadMeta(targetURL, contentMeta)
	}

	req, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(encryptedBody).
		CopyHeaders(r).
		Build()
	if err != nil {
		return errors.NewInternalWithCause("failed to create request", err)
	}
	rewriteUploadHeadersForV2(req, contentMeta, startOffset, r.Header.Get("Content-Range"))

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
	return s.ProxyDownloadDecryptReqWithStrategyForStorage(w, req, targetURL, passwdInfo, fileSize, strategy, "")
}

// ProxyDownloadDecryptReqWithStrategyForStorage downloads and decrypts using storage-scoped range learning.
func (s *StreamProxy) ProxyDownloadDecryptReqWithStrategyForStorage(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy, compatStorageKey string) *StreamOutcome {
	rangeHeader := req.Header.Get("Range")
	meta := contentMetaFromContext(req.Context(), passwdInfo, fileSize)
	if meta.PlainSize > 0 {
		fileSize = meta.PlainSize
	}
	if strategy == StreamStrategyRange && rangeHeader != "" && s.shouldSkipRange(targetURL, compatStorageKey) {
		return &StreamOutcome{
			Err:           errors.NewProxyError("range unsupported"),
			Retryable:     true,
			FailureReason: "range_unsupported",
		}
	}
	applyStrategyHeaders(req, strategy)
	if strategy == StreamStrategyRange {
		req.Header.Set("Range", buildUpstreamRangeHeader(rangeHeader, meta))
	}
	// Strip WebDAV-specific headers for CDN requests (raw_url targets).
	// WebDAV players send Depth, Translate etc. that confuse cloud CDNs.
	s.StripForeignHeaders(req)
	resp, err := s.client.Do(req)
	if err != nil {
		reason, retryable := classifyStreamError(err)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		defer resp.Body.Close()
		return s.handleRedirect(w, req, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, req, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
}

func applyStrategyHeaders(req *http.Request, strategy StreamStrategy) {
	req.Header.Set("Accept-Encoding", "identity")
	if strategy == StreamStrategyFull || strategy == StreamStrategyChunked {
		req.Header.Del("Range")
	}
}

func (s *StreamProxy) streamDecryptResponse(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	result := &StreamOutcome{}
	if resp.StatusCode >= http.StatusInternalServerError {
		s.cbGate.RecordFailure()
		return &StreamOutcome{
			Err:           errors.NewProxyError(fmt.Sprintf("upstream status %d", resp.StatusCode)),
			Retryable:     true,
			FailureReason: "upstream_5xx",
			NoLearning:    true,
			StatusCode:    resp.StatusCode,
		}
	}
	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError && resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		if !isPassthroughStatus(resp.StatusCode) {
			return &StreamOutcome{
				Err:           errors.NewProxyError(fmt.Sprintf("upstream status %d", resp.StatusCode)),
				Retryable:     true,
				FailureReason: "upstream_4xx",
				NoLearning:    true,
				StatusCode:    resp.StatusCode,
			}
		}
	}
	if isPassthroughStatus(resp.StatusCode) {
		httputil.CopyResponseHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		result.ResponseStarted = true
		result.StatusCode = resp.StatusCode
		result.FailureReason = "upstream_4xx"
		result.NoLearning = true
		if req.Method == http.MethodHead {
			return result
		}
		buf := getBuffer()
		defer putBuffer(buf)
		written, err := io.CopyBuffer(w, resp.Body, *buf)
		result.BytesWritten = written
		if err != nil {
			result.Err = err
		}
		return result
	}

	// Upstream responded successfully (< 500), reset circuit breaker
	s.cbGate.RecordSuccess()

	// Get file size from Content-Length if not provided
	fileSize = resolveFileSize(fileSize, resp)
	originalSize := fileSize
	fileSize = normalizePlainFileSize(fileSize, &meta, resp.Header.Get("Content-Range"))
	if meta.IsV2() {
		log.Info().
			Str("target_url", targetURL).
			Str("client_range", rangeHeader).
			Str("upstream_content_range", resp.Header.Get("Content-Range")).
			Int64("file_size_before", originalSize).
			Int64("file_size_after", fileSize).
			Int64("ciphertext_size", meta.CiphertextSize).
			Int64("plaintext_size", meta.PlainSize).
			Int64("header_len", meta.HeaderLen).
			Msg("Normalized V2 playback sizes")
	}
	if fileSize == 0 {
		result.Err = errors.NewDecryptionError("file size required for decrypt stream")
		return result
	}

	// Create decryption stream
	var flowEnc encryption.Cipher
	var err error
	if meta.IsV2() {
		flowEnc, err = encryption.NewCipherV2(encryption.EncType(passwdInfo.EncType), passwdInfo.Password, fileSize, meta.NonceField)
	} else {
		flowEnc, err = encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
	}
	if err != nil {
		result.Err = errors.NewDecryptionErrorWithCause("failed to create cipher", err)
		return result
	}

	var activeRange *httputil.Range
	if rangeHeader != "" && req.Method == http.MethodGet {
		parsed, err := httputil.ParseRange(rangeHeader, fileSize)
		if err != nil {
			writeRangeNotSatisfiable(w, fileSize)
			result.Err = err
			result.FailureReason = "range_invalid"
			result.ResponseStarted = true
			result.StatusCode = http.StatusRequestedRangeNotSatisfiable
			return result
		}
		if parsed != nil {
			if len(parsed.Ranges) != 1 {
				writeRangeNotSatisfiable(w, fileSize)
				result.Err = errors.NewProxyError("multiple ranges not supported")
				result.FailureReason = "range_invalid"
				result.ResponseStarted = true
				result.StatusCode = http.StatusRequestedRangeNotSatisfiable
				return result
			}
			activeRange = &parsed.Ranges[0]
		}
	}

	// Preserve range start for Full strategy fallback: when Range is unsupported,
	// we download the full file but seek in the cipher + discard upstream bytes.
	fullRangeStart := int64(0)
	if strategy == StreamStrategyFull && activeRange != nil {
		fullRangeStart = activeRange.Start
		activeRange = nil
	}

	if activeRange != nil && strategy == StreamStrategyRange {
		if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") == "" {
			if s.rangeStats != nil {
				atomic.AddUint64(&s.rangeStats.pseudoRangeCount, 1)
			}
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsupported")
			return &StreamOutcome{Err: errors.NewProxyError("range unsupported"), Retryable: true, FailureReason: "range_unsupported"}
		}
		if resp.StatusCode == http.StatusPartialContent && resp.Header.Get("Content-Range") == "" {
			if s.rangeStats != nil {
				atomic.AddUint64(&s.rangeStats.pseudoRangeCount, 1)
			}
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsupported")
			return &StreamOutcome{Err: errors.NewProxyError("range unsupported"), Retryable: true, FailureReason: "range_unsupported"}
		}
		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			if total := parseContentRangeTotal(resp.Header.Get("Content-Range")); total > 0 {
				fileSize = total
			}
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsatisfiable")
			return &StreamOutcome{Err: errors.NewProxyError("range unsatisfiable"), Retryable: true, FailureReason: "range_unsatisfiable"}
		}
	}

	if activeRange != nil {
		if err := flowEnc.SetPosition(activeRange.Start); err != nil {
			result.Err = errors.NewDecryptionErrorWithCause("failed to set position", err)
			return result
		}
	}

	// For Full strategy with seek: build a synthetic range for correct 206 headers.
	fullSeekRange := activeRange
	if strategy == StreamStrategyFull && fullRangeStart > 0 {
		fullSeekRange = &httputil.Range{Start: fullRangeStart, End: fileSize - 1}
	}

	upstreamShiftedRange := meta.IsV2() && strategy == StreamStrategyRange && buildUpstreamRangeHeader(rangeHeader, meta) != rangeHeader

	statusCode := http.StatusOK
	if fullSeekRange != nil {
		statusCode = http.StatusPartialContent
	}

	// Copy upstream headers but override range-related headers
	httputil.CopyResponseHeaders(w, resp, "Content-Length", "Content-Range", "Accept-Ranges")
	w.Header().Set("Accept-Ranges", "bytes")

	if fullSeekRange != nil {
		w.Header().Set("Content-Range", fullSeekRange.ContentRangeHeader(fileSize))
		w.Header().Set("Content-Length", strconv.FormatInt(fullSeekRange.ContentLength(), 10))
		result.ExpectedBytes = fullSeekRange.ContentLength()
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		result.ExpectedBytes = fileSize
	}

	result.StatusCode = statusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ETag = resp.Header.Get("ETag")

	if req.Method == http.MethodGet && statusCode == http.StatusOK && passwdInfo != nil && passwdInfo.Enable && passwdInfo.EncName {
		showName := displayNameFromContext(req.Context())
		if showName == "" {
			allowLoose := s.cfg != nil && s.cfg.AlistServer.AllowLooseDecode
			showName = decodeNameFromRequest(passwdInfo, req.URL.Path, allowLoose)
		}
		if showName != "" {
			rewriteContentDisposition(w, showName)
		}
	}

	if req.Method == http.MethodHead {
		w.WriteHeader(statusCode)
		result.ResponseStarted = true
		if strategy == StreamStrategyRange && activeRange != nil && result.Err == nil {
			s.recordRangeSuccess(targetURL, compatStorageKey)
		}
		return result
	}

	bodyReader := io.Reader(resp.Body)
	if meta.IsV2() && !(upstreamShiftedRange && (resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != "")) {
		if err := discardBytes(bodyReader, meta.HeaderLen); err != nil {
			result.Err = errors.NewProxyErrorWithCause("failed to discard v2 header", err)
			return result
		}
	}

	// For Full strategy with a seek: position cipher and discard upstream bytes
	// BEFORE creating the decrypt reader, to sync stream positions.
	if strategy == StreamStrategyFull && fullRangeStart > 0 {
		if err := flowEnc.SetPosition(fullRangeStart); err != nil {
			result.Err = errors.NewDecryptionErrorWithCause("failed to set position for full seek", err)
			return result
		}
		if err := discardBytes(bodyReader, fullRangeStart); err != nil {
			result.Err = errors.NewProxyErrorWithCause("failed to discard bytes for full seek", err)
			return result
		}
	}

	sniffOffset := int64(0)
	if activeRange != nil {
		sniffOffset = activeRange.Start
	}
	if activeRange != nil {
		if strategy == StreamStrategyChunked {
			maxDiscard := s.chunkedSeekMaxDiscardBytes()
			if maxDiscard > 0 && activeRange.Start > maxDiscard {
				return &StreamOutcome{
					Err:           errors.NewProxyError("chunked seek offset too large"),
					Retryable:     true,
					FailureReason: "chunked_seek_too_large",
				}
			}
			if err := discardBytes(bodyReader, activeRange.Start); err != nil {
				result.Err = errors.NewProxyErrorWithCause("failed to discard range bytes", err)
				return result
			}
		}
	}
	if strategy == StreamStrategyFull && fullRangeStart > 0 {
		sniffOffset = fullRangeStart
	}

	readerToStream := flowEnc.DecryptReader(bodyReader)
	if activeRange != nil {
		readerToStream = io.LimitReader(readerToStream, activeRange.ContentLength())
	}

	// Sniff first bytes of decrypted output to detect wrong password/fileSize.
	// Can be disabled via config (enableSniff: false) for performance.
	if shouldSniffDecryptedContent(req.Method, resp.Header.Get("Content-Type"), sniffOffset) &&
		(s.cfg == nil || s.cfg.AlistServer.EnableSniff) {
		if sniffBytes, ok := sniffDecrypted(readerToStream); !ok {
			resp.Body.Close()
			return &StreamOutcome{
				Err:           errors.NewDecryptionError("decryption validation failed: output appears encrypted (wrong password or file size?)"),
				Retryable:     false,
				FailureReason: "decrypt_validation_failed",
				NoLearning:    true,
			}
		} else {
			readerToStream = sniffBytes
		}
	}
	w.WriteHeader(statusCode)
	result.ResponseStarted = true

	buf := getBuffer()
	defer putBuffer(buf)
	written, err := io.CopyBuffer(w, readerToStream, *buf)
	result.BytesWritten = written
	if err != nil {
		log.Error().Err(err).Msg("Error streaming decrypted content")
		result.Err = err
		reason, retryable := classifyStreamError(err)
		if result.FailureReason == "" {
			result.FailureReason = reason
		}
		result.Retryable = retryable
	}
	if strategy == StreamStrategyRange && activeRange != nil && result.Err == nil {
		s.recordRangeSuccess(targetURL, compatStorageKey)
	}

	return result
}

func (s *StreamProxy) handleRedirect(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	location := resp.Header.Get("Location")
	if location == "" {
		return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
	}

	if s.shouldFollowRedirect(passwdInfo) {
		return s.followRedirectDecrypt(w, req, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
	}

	newLocation := location
	if s.redirectRewriter != nil && passwdInfo != nil && passwdInfo.Enable {
		if rewritten, ok := s.redirectRewriter(req, location, fileSize, passwdInfo); ok && rewritten != "" {
			newLocation = rewritten
		}
	}

	httputil.CopyResponseHeaders(w, resp)
	w.Header().Set("Location", newLocation)
	w.WriteHeader(resp.StatusCode)
	return &StreamOutcome{ResponseStarted: true}
}

func (s *StreamProxy) shouldFollowRedirect(passwdInfo *config.PasswdInfo) bool {
	if s == nil || s.cfg == nil {
		return false
	}
	if !s.cfg.AlistServer.FollowRedirectForDecrypt {
		return false
	}
	return passwdInfo != nil && passwdInfo.Enable
}

func (s *StreamProxy) followRedirectDecrypt(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	baseURL := resp.Request.URL
	currentURL := resolveRedirectURL(baseURL, resp.Header.Get("Location"))
	if currentURL == "" {
		return &StreamOutcome{Err: errors.NewProxyError("invalid redirect location")}
	}

	maxHops := 2
	if s.cfg != nil && s.cfg.AlistServer.RedirectMaxHops > 0 {
		maxHops = s.cfg.AlistServer.RedirectMaxHops
	}

	for hop := 0; hop < maxHops; hop++ {
		newReq, err := httputil.NewRequest(req.Method, currentURL).
			WithContext(req.Context()).
			CopyHeaders(req).
			Build()
		if err != nil {
			return &StreamOutcome{Err: errors.NewInternalWithCause("failed to create redirect request", err)}
		}

		sanitizeRedirectHeaders(newReq, req.URL, currentURL)
		applyStrategyHeaders(newReq, strategy)
		if strategy == StreamStrategyRange {
			newReq.Header.Set("Range", buildUpstreamRangeHeader(rangeHeader, meta))
		}
		if rangeHeader != "" && s.shouldSkipRange(currentURL, compatStorageKey) {
			newReq.Header.Del("Range")
		}

		nextResp, err := s.client.Do(newReq)
		if err != nil {
			reason, retryable := classifyStreamError(err)
			return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to follow redirect", err), FailureReason: reason, Retryable: retryable}
		}

		if isRedirectStatus(nextResp.StatusCode) {
			location := nextResp.Header.Get("Location")
			nextResp.Body.Close()
			if location == "" {
				return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
			}
			baseURL, _ = url.Parse(currentURL)
			currentURL = resolveRedirectURL(baseURL, location)
			if currentURL == "" {
				return &StreamOutcome{Err: errors.NewProxyError("invalid redirect location")}
			}
			continue
		}

		return s.streamDecryptResponse(w, newReq, nextResp, passwdInfo, fileSize, meta, rangeHeader, strategy, currentURL, compatStorageKey)
	}

	return &StreamOutcome{Err: errors.NewProxyError("redirect hop limit exceeded")}
}

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func resolveRedirectURL(base *url.URL, location string) string {
	if location == "" {
		return ""
	}
	loc, err := url.Parse(location)
	if err != nil {
		return ""
	}
	if loc.IsAbs() {
		return loc.String()
	}
	if base == nil {
		return ""
	}
	return base.ResolveReference(loc).String()
}

func sanitizeRedirectHeaders(req *http.Request, originalURL *url.URL, targetURL string) {
	if req == nil {
		return
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	originalHost := ""
	if originalURL != nil {
		originalHost = originalURL.Host
	}
	if target.Host != "" && originalHost != "" && !strings.EqualFold(target.Host, originalHost) {
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
	}
	// Always strip WebDAV-specific and other foreign headers on redirect.
	// CDNs reject requests with unusual headers from WebDAV players.
	StripWebDAVHeaders(req)
	req.Header.Del("Referer")
	req.Host = ""
}

func parseRangeStart(rangeHeader string) (int64, bool) {
	if rangeHeader == "" {
		return 0, false
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, false
	}
	raw := strings.TrimPrefix(rangeHeader, "bytes=")
	if idx := strings.Index(raw, ","); idx >= 0 {
		raw = raw[:idx]
	}
	parts := strings.SplitN(raw, "-", 2)
	if len(parts) == 0 || parts[0] == "" {
		return 0, false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return 0, false
	}
	return start, true
}

func writeRangeNotSatisfiable(w http.ResponseWriter, fileSize int64) {
	w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", fileSize))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
}

func rewriteUploadHeadersForV2(req *http.Request, meta encryption.ContentMeta, startOffset int64, originalContentRange string) {
	if req == nil || !meta.IsV2() {
		return
	}
	ciphertextSize := meta.TotalCiphertextSize()
	if rewritten, ok := rewritePlainContentRangeToCiphertext(originalContentRange, meta.HeaderLen); ok {
		req.Header.Set("Content-Range", rewritten)
	}
	if req.ContentLength > 0 {
		if startOffset == 0 {
			req.ContentLength += meta.HeaderLen
		}
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	if ciphertextSize > 0 {
		sizeStr := strconv.FormatInt(ciphertextSize, 10)
		req.Header.Set("X-File-Size", sizeStr)
		req.Header.Set("File-Size", sizeStr)
		req.Header.Set("X-Upload-Content-Length", sizeStr)
		req.Header.Set("X-Expected-Entity-Length", sizeStr)
	}
}

func rewritePlainContentRangeToCiphertext(contentRange string, headerLen int64) (string, bool) {
	contentRange = strings.TrimSpace(contentRange)
	if contentRange == "" || headerLen <= 0 {
		return "", false
	}
	if !strings.HasPrefix(strings.ToLower(contentRange), "bytes ") {
		return "", false
	}
	spec := strings.TrimSpace(contentRange[len("bytes "):])
	slash := strings.Index(spec, "/")
	if slash <= 0 {
		return "", false
	}
	rangePart := strings.TrimSpace(spec[:slash])
	totalPart := strings.TrimSpace(spec[slash+1:])
	parts := strings.SplitN(rangePart, "-", 2)
	if len(parts) != 2 {
		return "", false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return "", false
	}
	end, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if err != nil || end < start {
		return "", false
	}
	total, err := strconv.ParseInt(totalPart, 10, 64)
	if err != nil || total <= 0 {
		return "", false
	}
	return fmt.Sprintf("bytes %d-%d/%d", start+headerLen, end+headerLen, total+headerLen), true
}

func parseContentRangeTotal(contentRange string) int64 {
	if contentRange == "" {
		return 0
	}
	if idx := strings.LastIndex(contentRange, "/"); idx >= 0 && idx+1 < len(contentRange) {
		totalStr := contentRange[idx+1:]
		if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil {
			return total
		}
	}
	return 0
}

func discardBytes(r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	if n > 4096 {
		buf := getBuffer()
		defer putBuffer(buf)
		_, err := io.CopyBuffer(io.Discard, io.LimitReader(r, n), *buf)
		return err
	}
	_, err := io.CopyN(io.Discard, r, n)
	return err
}

func normalizePlainFileSize(fileSize int64, meta *encryption.ContentMeta, contentRange string) int64 {
	if meta == nil {
		return fileSize
	}
	if total := parseContentRangeTotal(contentRange); total > 0 {
		if meta.IsV2() {
			meta.CiphertextSize = total
			if total > meta.HeaderLen {
				meta.PlainSize = total - meta.HeaderLen
				return meta.PlainSize
			}
		}
		if fileSize == 0 || total != fileSize {
			fileSize = total
		}
	}
	if meta.IsV2() {
		if meta.CiphertextSize == 0 && fileSize > 0 {
			meta.CiphertextSize = fileSize
		}
		if meta.PlainSize <= 0 && meta.CiphertextSize > meta.HeaderLen {
			meta.PlainSize = meta.CiphertextSize - meta.HeaderLen
		}
		if meta.PlainSize > 0 {
			return meta.PlainSize
		}
		return fileSize
	}
	if meta.PlainSize == 0 {
		meta.PlainSize = fileSize
	}
	return fileSize
}

func decodeNameFromRequest(passwdInfo *config.PasswdInfo, urlPath string, allowLoose bool) string {
	if passwdInfo == nil {
		return ""
	}
	name := path.Base(urlPath)
	decoded, err := url.PathUnescape(name)
	if err == nil {
		name = decoded
	}
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	decodedName := encryption.DecodeName(passwdInfo.Password, passwdInfo.EncType, base)
	if decodedName == "" && allowLoose {
		return encryption.DecodeNameLoose(passwdInfo.Password, passwdInfo.EncType, base)
	}
	return decodedName
}

func rewriteContentDisposition(w http.ResponseWriter, showName string) {
	cd := w.Header().Get("Content-Disposition")
	if cd != "" {
		cd = contentDispositionRe.ReplaceAllString(cd, "")
		cd = strings.TrimSpace(cd)
		if cd != "" && !strings.HasSuffix(cd, ";") {
			cd += ";"
		}
	}
	w.Header().Set("Content-Disposition", cd+"filename*=UTF-8''"+url.PathEscape(showName)+";")
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

func isPassthroughStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
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

// sniffDecrypted reads the first N bytes of decrypted output and checks
// if it looks like valid plaintext (not random encrypted garbage).
// Returns a reader that prepends the consumed bytes on success.
func sniffDecrypted(r io.Reader) (io.Reader, bool) {
	const sniffLen = 512
	buf := make([]byte, sniffLen)
	n, err := io.ReadFull(r, buf)
	if err != nil && n == 0 {
		// Empty response, let it through
		return io.MultiReader(bytes.NewReader(buf[:n]), r), true
	}
	sample := buf[:n]

	// Count unique byte values and zero bytes.
	// Encrypted data: ~200+ unique bytes in 512 samples, few zeros.
	// Valid plaintext: 30-120 unique bytes, many zero bytes (headers, structures).
	// Use fixed array instead of map for zero-GC stack allocation.
	var seen [256]bool
	zeros := 0
	unique := 0
	for _, b := range sample {
		if !seen[b] {
			seen[b] = true
			unique++
		}
		if b == 0 {
			zeros++
		}
	}

	// Heuristic: encrypted data has high entropy (high unique ratio, few zeros).
	// Valid decrypted data has lower entropy (fewer unique bytes, more zeros).
	uniqueRatio := 0.0
	if n > 0 {
		uniqueRatio = float64(unique) / float64(n)
	}
	if (n >= 128 && uniqueRatio >= 0.72 && zeros < 10) || (unique > 200 && zeros < 10) {
		log.Warn().Int("unique_bytes", unique).Int("zeros", zeros).
			Int("sample_len", n).
			Float64("unique_ratio", uniqueRatio).
			Msg("Decrypted data looks encrypted — wrong password or file size?")
		return nil, false
	}

	// Prepend the consumed bytes
	return io.MultiReader(bytes.NewReader(sample), r), true
}

func shouldSniffDecryptedContent(method, contentType string, startOffset int64) bool {
	if method != http.MethodGet {
		return false
	}
	if startOffset > 0 {
		return false
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.HasPrefix(mediaType, "video/") || strings.HasPrefix(mediaType, "audio/") {
		return false
	}
	return true
}

// StripForeignHeaders removes WebDAV-specific headers that confuse CDN targets.
func (s *StreamProxy) StripForeignHeaders(req *http.Request) {
	if req == nil || req.URL == nil {
		return
	}
	// Strip regardless of scheme — alist ignores these headers, CDNs reject them.
	StripWebDAVHeaders(req)
}

// StripWebDAVHeaders removes WebDAV-specific request headers that confuse CDNs.
func StripWebDAVHeaders(r *http.Request) {
	webdavHeaders := []string{
		"Depth", "Translate", "Destination", "If", "If-Match",
		"If-None-Match", "If-Modified-Since", "If-Unmodified-Since",
		"Lock-Token", "Overwrite", "Timeout",
	}
	for _, h := range webdavHeaders {
		r.Header.Del(h)
	}
	// Old encrypt proxy also stripped these for CDN compatibility:
	// - Authorization: CDNs don't understand alist/WebDAV auth tokens
	// - Referer: Aliyun CDN returns 403 with certain referrers
	// - Host: prevent host header mismatch with CDN
	r.Header.Del("Authorization")
	r.Header.Del("Referer")
	r.Header.Del("Host")
}
