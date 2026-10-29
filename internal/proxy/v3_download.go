package proxy

import (
	"bytes"
	"context"
	stdErrors "errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/shared/encryptcore"
	"github.com/rs/zerolog/log"
)

// writeV3ResourceFailure commits an empty terminal response after clearing any
// uncommitted success headers left by an earlier strategy on the same writer.
func writeV3ResourceFailure(w http.ResponseWriter, err error, reason errors.FailureReason) *StreamOutcome {
	for _, name := range []string{"Content-Range", "Content-Type", "ETag", "Accept-Ranges", "Last-Modified", "Content-Disposition", "Content-Encoding", "Transfer-Encoding", "Expires", "Content-MD5", "Digest"} {
		w.Header().Del(name)
	}
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Retry-After", "2")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	return &StreamOutcome{Err: err, FailureReason: reason, NoLearning: true, StatusCode: http.StatusServiceUnavailable, ResponseStarted: true}
}

// v3KDFPlaybackFailure keeps service admission/cancellation terminal and out of
// provider learning. A canceled client gets no new HTTP response; busy admission
// clears uncommitted success headers and returns an empty retry-after 503.
func v3KDFPlaybackFailure(w http.ResponseWriter, req *http.Request, err error) *StreamOutcome {
	if canceled := req.Context().Err(); canceled != nil {
		return &StreamOutcome{Err: canceled, FailureReason: errors.ReasonClientDisconnect, NoLearning: true}
	}
	if stdErrors.Is(err, context.Canceled) || stdErrors.Is(err, context.DeadlineExceeded) {
		return &StreamOutcome{Err: err, FailureReason: errors.ReasonClientDisconnect, NoLearning: true}
	}
	if stdErrors.Is(err, encryption.ErrV3KDFBusy) {
		return writeV3ResourceFailure(w, err, "v3_kdf_busy")
	}
	return writeV3ResourceFailure(w, err, "v3_kdf_failed")
}

// v3FallbackCipherDiscard counts header bytes and complete authenticated records
// before the requested chunk. The intra-chunk prefix still requires that chunk's
// authentication, but is not a discarded record. Geometry is codec metadata, not
// proof that the password or any plaintext has been authenticated.
func v3FallbackCipherDiscard(meta encryption.ContentMeta, plainStart int64) (int64, error) {
	chunkSize := int64(meta.ChunkSize)
	if chunkSize <= 0 || chunkSize > 1<<30 || meta.HeaderLen != encryption.V3HeaderSize || plainStart < 0 {
		return 0, errors.NewDecryptionError("v3: invalid fallback geometry")
	}
	recordBytes := chunkSize + 16
	records := plainStart / chunkSize
	if records > (math.MaxInt64-meta.HeaderLen)/recordBytes {
		return 0, errors.NewDecryptionError("v3: fallback geometry overflows")
	}
	return meta.HeaderLen + records*recordBytes, nil
}

const v3SeekBudgetExceeded errors.FailureReason = "v3_seek_budget_exceeded"

// checkV3FallbackBudget is used both before fetch (when metadata is resolved)
// and defensively after upstream headers. It never applies to an exact Range
// window, HEAD, or an empty container, none of which discard complete records.
func (s *StreamProxy) checkV3FallbackBudget(w http.ResponseWriter, req *http.Request, meta encryption.ContentMeta, fileSize int64, rangeHeader string, strategy StreamStrategy) *StreamOutcome {
	if !meta.IsV3() || req.Method != http.MethodGet || fileSize <= 0 || (strategy != StreamStrategyFull && strategy != StreamStrategyChunked) {
		return nil
	}
	start := int64(0)
	if rangeHeader != "" {
		parsed, err := httputil.ParseRange(rangeHeader, fileSize)
		if err != nil || parsed == nil || len(parsed.Ranges) != 1 {
			return nil // Preserve the dispatcher's invalid/multiple-range response.
		}
		start = parsed.Ranges[0].Start
	}
	discard, err := v3FallbackCipherDiscard(meta, start)
	if err != nil {
		return writeV3ResourceFailure(w, err, "bad_v3_metadata")
	}
	if discard > s.chunkedSeekMaxDiscardBytes() {
		return writeV3ResourceFailure(w, errors.NewProxyError("v3 fallback ciphertext discard exceeds playback budget"), v3SeekBudgetExceeded)
	}
	return nil
}

// streamV3Response performs the decrypt-and-stream phase for a V3 container.
//
// The upstream Range built by buildUpstreamRangeHeader covers the contiguous
// sequence of chunk records that contain the client's plaintext interval
// (records are fixed width, so the ciphertext window is contiguous even when
// the interval spans several chunks). V3StreamReader then emits only the
// requested plaintext sub-slice of that window.
func (s *StreamProxy) streamV3Response(w http.ResponseWriter, req *http.Request, resp *http.Response, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader string, strategy StreamStrategy, activeRange *httputil.Range, fullRequestedRange *httputil.Range, targetURL, compatStorageKey string) *StreamOutcome {
	result := &StreamOutcome{}
	streamStart := time.Now()

	allowLoose := false
	if s != nil && s.cfg != nil {
		allowLoose = s.cfg.AlistServerSnapshot().AllowLooseDecode
	}

	chunkSize := int64(meta.ChunkSize)
	if _, err := v3FallbackCipherDiscard(meta, 0); err != nil {
		return writeV3ResourceFailure(w, err, "bad_v3_metadata")
	}
	nonce := meta.NonceField
	if int64(len(nonce)) != encryption.V3NonceFieldLen() {
		return &StreamOutcome{
			Err:           errors.NewDecryptionError(fmt.Sprintf("v3: expected %d-byte nonce in metadata, got %d", encryption.V3NonceFieldLen(), len(nonce))),
			Retryable:     false,
			FailureReason: "bad_v3_metadata",
			NoLearning:    true,
		}
	}
	// A Range-strategy request must come back as the exact chunk window we
	// asked for; any other interval would decrypt at the wrong position.
	if strategy == StreamStrategyRange && activeRange != nil {
		windowStart := activeRange.Start
		if p := v3Plan(req); p != nil {
			windowStart = p.tailStart
		}
		cipherStart, cipherEnd := encryption.V3ChunkWindow(windowStart, activeRange.End, chunkSize)
		contentRangeHeader := resp.Header.Get("Content-Range")
		if resp.StatusCode == http.StatusOK && contentRangeHeader == "" {
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsupported")
			return &StreamOutcome{Err: errors.NewProxyError("range unsupported"), Retryable: true, FailureReason: "range_unsupported"}
		}
		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsatisfiable")
			return &StreamOutcome{Err: errors.NewProxyError("range unsatisfiable"), Retryable: true, FailureReason: "range_unsatisfiable"}
		}
		actual, valid := parseContentRange(contentRangeHeader)
		if resp.StatusCode != http.StatusPartialContent || !valid || actual.Start != cipherStart || actual.End < cipherEnd {
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsupported")
			return &StreamOutcome{
				Err:           errors.NewProxyError(fmt.Sprintf("upstream Content-Range %q does not cover v3 chunk window %d-%d", contentRangeHeader, cipherStart, cipherEnd)),
				Retryable:     true,
				FailureReason: "range_unsupported",
				StatusCode:    resp.StatusCode,
			}
		}
	}

	if outcome := s.checkV3FallbackBudget(w, req, meta, fileSize, rangeHeader, strategy); outcome != nil {
		return outcome
	}
	if err := req.Context().Err(); err != nil {
		return &StreamOutcome{Err: err, FailureReason: errors.ReasonClientDisconnect, NoLearning: true}
	}

	responseRange := activeRange
	if fullRequestedRange != nil {
		responseRange = fullRequestedRange
	}
	statusCode := http.StatusOK
	if responseRange != nil {
		statusCode = http.StatusPartialContent
	}

	httputil.CopyResponseHeaders(w, resp, "Content-Length", "Content-Range", "Accept-Ranges")
	w.Header().Set("Accept-Ranges", "bytes")

	if responseRange != nil {
		w.Header().Set("Content-Range", responseRange.ContentRangeHeader(fileSize))
		w.Header().Set("Content-Length", strconv.FormatInt(responseRange.ContentLength(), 10))
		result.ExpectedBytes = responseRange.ContentLength()
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
		Int("response_status", statusCode).
		Str("response_content_range", w.Header().Get("Content-Range")).
		Str("response_content_length", w.Header().Get("Content-Length")).
		Int64("chunk_size", chunkSize).
		Uint32("kdf_iterations", meta.KDFIterations).
		Int64("plain_size", meta.PlainSize).
		Int64("ciphertext_size", meta.CiphertextSize).
		Msg("Prepared V3 decrypt response headers")

	if req.Method == http.MethodGet && passwdInfo != nil && passwdInfo.Enable && passwdInfo.EncName {
		showName := displayNameFromContext(req.Context())
		if showName == "" {
			showName = decodeNameFromRequest(passwdInfo, req.URL.Path, allowLoose)
		}
		if showName != "" {
			rewriteContentDisposition(w, showName)
		}
	}

	if req.Method == http.MethodHead {
		result.HeaderLatency = time.Since(streamStart)
		w.WriteHeader(statusCode)
		result.ResponseStarted = true
		if strategy == StreamStrategyRange && activeRange != nil && result.Err == nil {
			s.recordRangeSuccess(targetURL, compatStorageKey)
		}
		return result
	}

	// HEAD has returned using resolved codec geometry only; it neither needs
	// record memory nor claims to authenticate plaintext. Reject GET resources
	// before deriving a key or touching the upstream body.
	recordBytes := chunkSize + 16
	if recordBytes > v3RecordBudgetBytes {
		return writeV3ResourceFailure(w, errors.NewDecryptionError("v3 chunk exceeds playback memory budget"), "bad_v3_metadata")
	}
	// A queued KDF waiter owns no record lease or body buffer. Geometry and
	// fallback admission remain above this point, before CPU/transport work.
	key, err := encryption.DeriveV3KeyContext(req.Context(), passwdInfo.Password, nonce, meta.KDFIterations, encryption.V3KDFForeground)
	if err != nil {
		return v3KDFPlaybackFailure(w, req, err)
	}
	if err := req.Context().Err(); err != nil {
		return v3KDFPlaybackFailure(w, req, err)
	}
	release, ok := s.acquireV3Memory(recordBytes)
	if !ok {
		return writeV3ResourceFailure(w, errors.NewProxyError("v3 playback memory budget exhausted"), "resource_exhausted")
	}
	defer release()
	v3Cipher, err := encryption.NewV3ChunkCipher(key, nonce)
	if err != nil {
		result.Err = errors.NewDecryptionErrorWithCause("v3: create chunk cipher", err)
		return result
	}

	// Where the plaintext begins inside the upstream body:
	// - Range strategy: body starts at the window's first chunk record, so only
	//   the intra-chunk skip remains.
	// - Full/Chunked strategy (Range denied upstream): body is the whole
	//   container, so discard the header and skip from the very first chunk.
	// - Plain GET: body is the whole container, start at chunk 0.
	firstChunk := int64(0)
	skip := int64(0)
	limit := fileSize
	switch {
	case fullRequestedRange != nil:
		if err := discardBytes(resp.Body, meta.HeaderLen); err != nil {
			result.Err = errors.NewProxyErrorWithCause("failed to discard v3 header", err)
			return result
		}
		firstChunk = 0
		skip = fullRequestedRange.Start
		limit = fullRequestedRange.ContentLength()
	case activeRange != nil && strategy == StreamStrategyChunked:
		// applyStrategyHeaders removed upstream Range. The body still includes
		// front matter and starts at record zero, not at the requested window.
		if err := discardBytes(resp.Body, meta.HeaderLen); err != nil {
			result.Err = errors.NewProxyErrorWithCause("failed to discard v3 header", err)
			return result
		}
		skip = activeRange.Start
		limit = activeRange.ContentLength()
	case activeRange != nil:
		start := activeRange.Start
		if p := v3Plan(req); p != nil {
			start = p.tailStart
		}
		firstChunk = start / chunkSize
		skip = start % chunkSize
		limit = activeRange.End - start + 1
	default:
		if err := discardBytes(resp.Body, meta.HeaderLen); err != nil {
			result.Err = errors.NewProxyErrorWithCause("failed to discard v3 header", err)
			return result
		}
		if meta.PlainSize > 0 {
			limit = meta.PlainSize
		}
		firstChunk = 0
		skip = 0
	}
	var bodyReader io.Reader
	var reader *encryption.V3StreamReader
	cacheKey, cacheEnabled := v3CacheIdentity(req, targetURL, passwdInfo, meta, compatStorageKey)
	if p := v3Plan(req); p != nil {
		cacheKey, cacheEnabled = p.key, true
	}
	if cacheEnabled {
		reader, err = encryption.NewV3RecordReader(req.Context(), v3Cipher, chunkSize, firstChunk, skip, limit, meta.PlainSize, rootV3RecordCache, cacheKey, sequentialV3Loader(resp.Body, firstChunk, chunkSize))
	} else {
		reader, err = encryption.NewV3StreamReader(resp.Body, v3Cipher, chunkSize, firstChunk, skip, limit)
	}
	if err != nil {
		result.Err = errors.NewDecryptionErrorWithCause("failed to create v3 stream reader", err)
		return result
	}
	defer reader.Close()
	// Read one byte before committing: this authenticates the complete first
	// tail record even at nonzero offsets with sniff disabled. Never emit a
	// successful cached prefix followed by a first-tail authentication failure.
	var first [1]byte
	n, firstErr := reader.Read(first[:])
	if firstErr != nil || n != 1 {
		if firstErr == nil {
			firstErr = io.ErrUnexpectedEOF
		}
		result.Err = errors.NewDecryptionErrorWithCause("v3: first record authentication", firstErr)
		result.FailureReason = "decrypt_validation_failed"
		result.NoLearning = true
		return result
	}
	bodyReader = io.MultiReader(bytes.NewReader(first[:]), reader)
	if p := v3Plan(req); p != nil && len(p.readers) > 0 {
		parts := append([]io.Reader(nil), p.readers...)
		parts = append(parts, bodyReader)
		bodyReader = io.MultiReader(parts...)
	}

	sniffOffset := int64(0)
	switch {
	case activeRange != nil:
		sniffOffset = activeRange.Start
	case fullRequestedRange != nil:
		sniffOffset = fullRequestedRange.Start
	}

	enableSniff := true
	if s != nil && s.cfg != nil {
		enableSniff = s.cfg.AlistServerSnapshot().EnableSniff
	}
	if shouldSniffDecryptedContent(req.Method, resp.Header.Get("Content-Type"), sniffOffset) && enableSniff {
		sniffed, ok := sniffDecrypted(bodyReader)
		if !ok {
			resp.Body.Close()
			return &StreamOutcome{
				Err:           errors.NewDecryptionError("decryption validation failed: output appears encrypted (wrong password or file size?)"),
				Retryable:     false,
				FailureReason: "decrypt_validation_failed",
				NoLearning:    true,
			}
		}
		bodyReader = sniffed
	}

	result.HeaderLatency = time.Since(streamStart)
	w.WriteHeader(statusCode)
	result.ResponseStarted = true

	buf := getBuffer()
	defer putBuffer(buf)
	written, err := copyStreamBody(w, bodyReader, *buf, result.ExpectedBytes)
	result.BytesWritten = written
	result.WallDuration = time.Since(streamStart)
	if result.WallDuration > 0 && written > 0 {
		result.BytesPerSecond = float64(written) / result.WallDuration.Seconds()
	}
	if err != nil {
		result.Err = err
		result.FailureReason = classifyStreamCopyError(req.Context(), err)
		if result.FailureReason == "client_disconnect" {
			log.Debug().Err(err).Int64("bytes_written", written).Msg("Client ended V3 decrypt stream")
		} else {
			log.Error().Err(err).Int64("bytes_written", written).Msg("Error streaming V3 decrypted content")
		}
	}
	// Once any successful response has started, body failures are terminal.
	// Never advertise a retry which could append another URL/strategy response.
	if result.Err != nil && result.ResponseStarted {
		result.Retryable = false
		result.NoLearning = true
	}
	if strategy == StreamStrategyRange && activeRange != nil && result.Err == nil {
		s.recordRangeSuccess(targetURL, compatStorageKey)
	}
	return result
}
