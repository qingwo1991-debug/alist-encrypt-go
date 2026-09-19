package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/shared/encryptcore"
	"github.com/rs/zerolog/log"
)

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
	if chunkSize <= 0 {
		chunkSize = encryption.V3DefaultChunkSize()
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
	key := encryption.DeriveV3Key(passwdInfo.Password, nonce, meta.KDFIterations)
	v3Cipher, err := encryption.NewV3ChunkCipher(key, nonce)
	if err != nil {
		result.Err = errors.NewDecryptionErrorWithCause("v3: create chunk cipher", err)
		return result
	}

	// A Range-strategy request must come back as the exact chunk window we
	// asked for; any other interval would decrypt at the wrong position.
	if strategy == StreamStrategyRange && activeRange != nil {
		cipherStart, cipherEnd := encryption.V3ChunkWindow(activeRange.Start, activeRange.End, chunkSize)
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
		if !valid || actual.Start != cipherStart || actual.End < cipherEnd {
			s.recordRangeFailure(targetURL, compatStorageKey, "range_unsupported")
			return &StreamOutcome{
				Err:           errors.NewProxyError(fmt.Sprintf("upstream Content-Range %q does not cover v3 chunk window %d-%d", contentRangeHeader, cipherStart, cipherEnd)),
				Retryable:     true,
				FailureReason: "range_unsupported",
				StatusCode:    resp.StatusCode,
			}
		}
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

	// Where the plaintext begins inside the upstream body:
	// - Range strategy: body starts at the window's first chunk record, so only
	//   the intra-chunk skip remains.
	// - Full strategy (Range denied upstream): body is the whole container, so
	//   discard the header and skip from the very first chunk.
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
	case activeRange != nil:
		firstChunk = activeRange.Start / chunkSize
		skip = activeRange.Start % chunkSize
		limit = activeRange.ContentLength()
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
	reader, err := encryption.NewV3StreamReader(resp.Body, v3Cipher, chunkSize, firstChunk, skip, limit)
	if err != nil {
		result.Err = errors.NewDecryptionErrorWithCause("failed to create v3 stream reader", err)
		return result
	}
	bodyReader = reader

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

	if req.Method == http.MethodGet && rangeHeader != "" && s != nil && s.blockCache != nil {
		baseKey := s.decryptedCacheBaseKey(targetURL, passwdInfo, fileSize, meta, compatStorageKey)
		bodyReader = newDecryptedCacheReader(bodyReader, s.blockCache, baseKey, sniffOffset)
	}

	result.HeaderLatency = time.Since(streamStart)
	w.WriteHeader(statusCode)
	result.ResponseStarted = true

	buf := getBuffer()
	defer putBuffer(buf)
	written, err := io.CopyBuffer(w, bodyReader, *buf)
	result.BytesWritten = written
	result.WallDuration = time.Since(streamStart)
	if result.WallDuration > 0 && written > 0 {
		result.BytesPerSecond = float64(written) / result.WallDuration.Seconds()
	}
	if err == nil && result.ExpectedBytes > 0 && written < result.ExpectedBytes {
		err = io.ErrUnexpectedEOF
		result.FailureReason = "upstream_truncated"
		result.Retryable = true
		result.NoLearning = true
	}
	if err != nil {
		result.Err = err
		reason, retryable := classifyStreamError(err)
		if reason == "client_disconnect" {
			log.Debug().Err(err).Int64("bytes_written", written).Msg("Client ended V3 decrypt stream")
		} else {
			log.Error().Err(err).Int64("bytes_written", written).Msg("Error streaming V3 decrypted content")
		}
		if result.FailureReason == "" {
			result.FailureReason = reason
			result.Retryable = retryable
		}
	}
	if strategy == StreamStrategyRange && activeRange != nil && result.Err == nil {
		s.recordRangeSuccess(targetURL, compatStorageKey)
	}
	return result
}
