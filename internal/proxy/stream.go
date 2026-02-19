package proxy

import (
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
}

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
	return &StreamProxy{
		client:      NewClient(cfg),
		cfg:         cfg,
		compatStore: NewMemoryRangeCompatStore(),
		rangeStats:  newRangeLearningStats(),
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
	return s.ProxyDownloadDecryptWithStrategyForStorage(w, r, targetURL, passwdInfo, fileSize, strategy, "")
}

// ProxyDownloadDecryptWithStrategyForStorage downloads and decrypts content with storage-scoped range learning.
func (s *StreamProxy) ProxyDownloadDecryptWithStrategyForStorage(w http.ResponseWriter, r *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy, compatStorageKey string) *StreamOutcome {
	rangeHeader := r.Header.Get("Range")
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

	resp, err := s.client.Do(req)
	if err != nil {
		reason, retryable := classifyStreamError(err)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		defer resp.Body.Close()
		return s.handleRedirect(w, r, resp, passwdInfo, fileSize, rangeHeader, strategy, targetURL, compatStorageKey)
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, r, resp, passwdInfo, fileSize, rangeHeader, strategy, targetURL, compatStorageKey)
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
	return s.ProxyDownloadDecryptReqWithStrategyForStorage(w, req, targetURL, passwdInfo, fileSize, strategy, "")
}

// ProxyDownloadDecryptReqWithStrategyForStorage downloads and decrypts using storage-scoped range learning.
func (s *StreamProxy) ProxyDownloadDecryptReqWithStrategyForStorage(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy, compatStorageKey string) *StreamOutcome {
	rangeHeader := req.Header.Get("Range")
	if strategy == StreamStrategyRange && rangeHeader != "" && s.shouldSkipRange(targetURL, compatStorageKey) {
		return &StreamOutcome{
			Err:           errors.NewProxyError("range unsupported"),
			Retryable:     true,
			FailureReason: "range_unsupported",
		}
	}
	applyStrategyHeaders(req, strategy)
	resp, err := s.client.Do(req)
	if err != nil {
		reason, retryable := classifyStreamError(err)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		defer resp.Body.Close()
		return s.handleRedirect(w, req, resp, passwdInfo, fileSize, rangeHeader, strategy, targetURL, compatStorageKey)
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, req, resp, passwdInfo, fileSize, rangeHeader, strategy, targetURL, compatStorageKey)
}

func applyStrategyHeaders(req *http.Request, strategy StreamStrategy) {
	if strategy == StreamStrategyFull || strategy == StreamStrategyChunked {
		req.Header.Del("Range")
	}
}

func (s *StreamProxy) streamDecryptResponse(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	result := &StreamOutcome{}
	if resp.StatusCode >= http.StatusInternalServerError {
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

	// Get file size from Content-Length if not provided
	fileSize = resolveFileSize(fileSize, resp)
	if total := parseContentRangeTotal(resp.Header.Get("Content-Range")); total > 0 && total != fileSize {
		fileSize = total
	}
	if fileSize == 0 {
		result.Err = errors.NewDecryptionError("file size required for decrypt stream")
		return result
	}

	// Create decryption stream
	flowEnc, err := encryption.NewFlowEnc(passwdInfo.Password, passwdInfo.EncType, fileSize)
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

	if strategy == StreamStrategyFull {
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

	statusCode := http.StatusOK
	if activeRange != nil {
		statusCode = http.StatusPartialContent
	}

	// Copy upstream headers but override range-related headers
	httputil.CopyResponseHeaders(w, resp, "Content-Length", "Content-Range", "Accept-Ranges")
	w.Header().Set("Accept-Ranges", "bytes")

	if activeRange != nil {
		w.Header().Set("Content-Range", activeRange.ContentRangeHeader(fileSize))
		w.Header().Set("Content-Length", strconv.FormatInt(activeRange.ContentLength(), 10))
		result.ExpectedBytes = activeRange.ContentLength()
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		result.ExpectedBytes = fileSize
	}

	result.StatusCode = statusCode
	result.ContentType = resp.Header.Get("Content-Type")
	result.ETag = resp.Header.Get("ETag")

	if req.Method == http.MethodGet && statusCode == http.StatusOK && passwdInfo != nil && passwdInfo.Enable && passwdInfo.EncName {
		allowLoose := s.cfg != nil && s.cfg.AlistServer.AllowLooseDecode
		if showName := decodeNameFromRequest(passwdInfo, req.URL.Path, allowLoose); showName != "" {
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

	readerToStream := flowEnc.DecryptReader(resp.Body)
	if activeRange != nil {
		if strategy == StreamStrategyChunked {
			if err := discardBytes(resp.Body, activeRange.Start); err != nil {
				result.Err = errors.NewProxyErrorWithCause("failed to discard range bytes", err)
				return result
			}
		}
		readerToStream = io.LimitReader(flowEnc.DecryptReader(resp.Body), activeRange.ContentLength())
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

func (s *StreamProxy) handleRedirect(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
	location := resp.Header.Get("Location")
	if location == "" {
		return &StreamOutcome{Err: errors.NewProxyError("redirect without Location header")}
	}

	if s.shouldFollowRedirect(passwdInfo) {
		return s.followRedirectDecrypt(w, req, resp, passwdInfo, fileSize, rangeHeader, strategy, targetURL, compatStorageKey)
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

func (s *StreamProxy) followRedirectDecrypt(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, rangeHeader string, strategy StreamStrategy, targetURL, compatStorageKey string) *StreamOutcome {
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

		return s.streamDecryptResponse(w, newReq, nextResp, passwdInfo, fileSize, rangeHeader, strategy, currentURL, compatStorageKey)
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
	req.Header.Del("Host")
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
	_, err := io.CopyN(io.Discard, r, n)
	return err
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
		re := regexp.MustCompile(`(?i)filename\*?=[^;]*;?`)
		cd = re.ReplaceAllString(cd, "")
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
