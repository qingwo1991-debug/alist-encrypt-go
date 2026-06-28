package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/alist-encrypt-go/internal/backoff"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/rs/zerolog/log"
)

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
	if outcome, ok := s.tryServeDecryptedCache(w, r, targetURL, passwdInfo, fileSize, meta, rangeHeader, compatStorageKey); ok {
		return outcome
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
		upstreamRange := buildUpstreamRangeHeader(rangeHeader, meta)
		req.Header.Set("Range", upstreamRange)
		log.Info().
			Str("category", "playback").
			Str("target_url", targetURL).
			Str("strategy", string(strategy)).
			Str("client_range", rangeHeader).
			Str("upstream_range", upstreamRange).
			Int("meta_version", meta.Version).
			Int64("plain_size", meta.PlainSize).
			Int64("ciphertext_size", meta.CiphertextSize).
			Int64("header_len", meta.HeaderLen).
			Msg("Prepared upstream decrypt request")
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
	if isRedirectStatus(resp.StatusCode) {
		defer resp.Body.Close()
		return s.handleRedirect(w, r, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
	}
	defer resp.Body.Close()

	return s.streamDecryptResponse(w, r, resp, passwdInfo, fileSize, meta, rangeHeader, strategy, targetURL, compatStorageKey)
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
	if outcome, ok := s.tryServeDecryptedCache(w, req, targetURL, passwdInfo, fileSize, meta, rangeHeader, compatStorageKey); ok {
		return outcome
	}
	applyStrategyHeaders(req, strategy)
	if strategy == StreamStrategyRange {
		upstreamRange := buildUpstreamRangeHeader(rangeHeader, meta)
		req.Header.Set("Range", upstreamRange)
		log.Info().
			Str("category", "playback").
			Str("target_url", targetURL).
			Str("strategy", string(strategy)).
			Str("client_range", rangeHeader).
			Str("upstream_range", upstreamRange).
			Int("meta_version", meta.Version).
			Int64("plain_size", meta.PlainSize).
			Int64("ciphertext_size", meta.CiphertextSize).
			Int64("header_len", meta.HeaderLen).
			Msg("Prepared upstream decrypt request")
	}
	// Strip WebDAV-specific headers for CDN requests (raw_url targets).
	// WebDAV players send Depth, Translate etc. that confuse cloud CDNs.
	s.StripForeignHeaders(req)
	resp, err := s.client.Do(req)
	if err != nil {
		reason, retryable := classifyStreamError(err)
		return &StreamOutcome{Err: errors.NewProxyErrorWithCause("failed to fetch", err), FailureReason: reason, Retryable: retryable}
	}
	if isRedirectStatus(resp.StatusCode) {
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

func (s *StreamProxy) tryServeDecryptedCache(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader, compatStorageKey string) (*StreamOutcome, bool) {
	if s == nil || s.blockCache == nil || req == nil || req.Method != http.MethodGet || rangeHeader == "" || fileSize <= 0 {
		return nil, false
	}
	if meta.PlainSize > 0 {
		fileSize = meta.PlainSize
	}
	parsed, err := httputil.ParseRange(rangeHeader, fileSize)
	if err != nil || parsed == nil || len(parsed.Ranges) != 1 {
		return nil, false
	}
	activeRange := parsed.Ranges[0]
	baseKey := s.decryptedCacheBaseKey(targetURL, passwdInfo, fileSize, meta, compatStorageKey)
	if baseKey == "" {
		return nil, false
	}
	data, ok := s.blockCache.getRange(baseKey, activeRange.Start, activeRange.ContentLength())
	if !ok {
		return nil, false
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", activeRange.ContentRangeHeader(fileSize))
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(data)), 10))
	w.WriteHeader(http.StatusPartialContent)
	n, writeErr := w.Write(data)
	outcome := &StreamOutcome{
		BytesWritten:    int64(n),
		ExpectedBytes:   activeRange.ContentLength(),
		ResponseStarted: true,
		StatusCode:      http.StatusPartialContent,
	}
	if writeErr != nil {
		outcome.Err = writeErr
		outcome.FailureReason = "cache_write_error"
	}
	return outcome, true
}

func (s *StreamProxy) decryptedCacheBaseKey(targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, compatStorageKey string) string {
	if passwdInfo == nil || !passwdInfo.Enable || fileSize <= 0 {
		return ""
	}
	stableID := strings.TrimSpace(compatStorageKey)
	if stableID == "" {
		stableID = strings.TrimSpace(targetURL)
	}
	if stableID == "" {
		return ""
	}
	passHash := sha256.Sum256([]byte(passwdInfo.Password))
	targetHash := sha256.Sum256([]byte(targetURL))
	nonce := ""
	if len(meta.NonceField) > 0 {
		nonce = hex.EncodeToString(meta.NonceField)
	}
	return fmt.Sprintf("%s|%x|%s|%x|%d|%d|%d|%d|%s",
		stableID,
		targetHash[:8],
		passwdInfo.EncType,
		passHash[:8],
		fileSize,
		meta.Version,
		meta.HeaderLen,
		meta.CiphertextSize,
		nonce,
	)
}

// DecryptedBlockCacheStats returns decrypted block cache runtime stats.
func (s *StreamProxy) DecryptedBlockCacheStats() map[string]interface{} {
	if s == nil || s.blockCache == nil {
		return map[string]interface{}{"enabled": false}
	}
	return s.blockCache.stats()
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

	log.Info().
		Str("category", "playback").
		Str("target_url", targetURL).
		Str("strategy", string(strategy)).
		Str("client_range", rangeHeader).
		Str("upstream_content_range", resp.Header.Get("Content-Range")).
		Int("upstream_status", resp.StatusCode).
		Int("response_status", statusCode).
		Str("response_content_range", w.Header().Get("Content-Range")).
		Str("response_content_length", w.Header().Get("Content-Length")).
		Int64("file_size", fileSize).
		Int64("expected_bytes", result.ExpectedBytes).
		Int("meta_version", meta.Version).
		Int64("plain_size", meta.PlainSize).
		Int64("ciphertext_size", meta.CiphertextSize).
		Int64("header_len", meta.HeaderLen).
		Bool("upstream_shifted_range", upstreamShiftedRange).
		Msg("Prepared decrypt response headers")

	if req.Method == http.MethodGet && passwdInfo != nil && passwdInfo.Enable && passwdInfo.EncName {
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
	if req.Method == http.MethodGet && rangeHeader != "" && s.blockCache != nil {
		baseKey := s.decryptedCacheBaseKey(targetURL, passwdInfo, fileSize, meta, compatStorageKey)
		readerToStream = newDecryptedCacheReader(readerToStream, s.blockCache, baseKey, sniffOffset)
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
