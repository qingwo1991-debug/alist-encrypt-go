package proxy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/errors"
	"github.com/alist-encrypt-go/internal/httputil"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
	"github.com/rs/zerolog/log"
)

// Cached-prefix playback: real players mostly send open-ended ranges
// ("bytes=N-") or no Range at all. Those can never be served entirely from the
// bounded decrypted block cache. When the start of the requested interval is
// cached, answer the client from memory right away and splice an upstream
// continuation for the remainder into the same response. A seek back to an
// already-played position, or a player reopening the file at 0, then starts
// without waiting for an upstream round trip.

// Below this size the upstream round trip dominates; splicing is not worth it.
const minDecryptedPrefixBytes = 64 << 10

type decryptedCachePrefixKey struct{}

type continuationFunc func(http.ResponseWriter, *http.Request) *StreamOutcome

func (s *StreamProxy) tryServeDecryptedCachePrefix(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, rangeHeader, compatStorageKey string, strategy StreamStrategy, cont continuationFunc) (*StreamOutcome, bool) {
	if meta.IsV3() || s == nil || s.blockCache == nil || req == nil || cont == nil || req.Method != http.MethodGet || fileSize <= 0 {
		return nil, false
	}
	if strategy != StreamStrategyRange || req.Context().Value(decryptedCachePrefixKey{}) != nil {
		return nil, false
	}
	if s.shouldSkipRange(targetURL, compatStorageKey) {
		// The continuation needs an upstream Range; leave range-less upstreams
		// to the normal strategy fallback.
		return nil, false
	}
	if meta.PlainSize > 0 {
		fileSize = meta.PlainSize
	}
	start, end := int64(0), fileSize-1
	if rangeHeader != "" {
		parsed, err := httputil.ParseRange(rangeHeader, fileSize)
		if err != nil || parsed == nil || len(parsed.Ranges) != 1 {
			return nil, false
		}
		start, end = parsed.Ranges[0].Start, parsed.Ranges[0].End
	}
	baseKey := s.decryptedCacheBaseKey(targetURL, passwdInfo, fileSize, meta, compatStorageKey)
	if baseKey == "" {
		return nil, false
	}
	prefix := s.blockCache.getPrefix(baseKey, start, end-start+1)
	if int64(len(prefix)) < minDecryptedPrefixBytes {
		return nil, false
	}
	contStart := start + int64(len(prefix))
	if contStart > end {
		// Fully cached intervals belong to tryServeDecryptedCache.
		return nil, false
	}

	creq := req.Clone(context.WithValue(req.Context(), decryptedCachePrefixKey{}, true))
	creq.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", contStart, end))
	log.Info().
		Str("category", "playback").
		Str("target_url", targetURL).
		Str("client_range", rangeHeader).
		Int64("prefix_bytes", int64(len(prefix))).
		Int64("continuation_start", contStart).
		Msg("Serving decrypted cache prefix with upstream continuation")

	// Commit headers and the cached prefix immediately: the first byte must not
	// wait for the continuation's upstream round trip. The continuation is
	// opened only afterwards, while the player is already consuming the prefix.
	// Trade-off: once the prefix is out, a failed continuation can no longer
	// fall back transparently; the response ends short and the player
	// re-requests from where it stopped (mainstream players do).
	h := w.Header()
	for _, name := range []string{"Content-Encoding", "Transfer-Encoding", "ETag", "Last-Modified"} {
		h.Del(name)
	}
	h.Set("Accept-Ranges", "bytes")
	status := http.StatusPartialContent
	if rangeHeader == "" {
		h.Del("Content-Range")
		h.Set("Content-Length", strconv.FormatInt(fileSize, 10))
		status = http.StatusOK
	} else {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
		h.Set("Content-Length", strconv.FormatInt(end-start+1, 10))
	}
	w.WriteHeader(status)
	n, err := w.Write(prefix)
	if err == nil && n < len(prefix) {
		err = errors.NewProxyError("short write of cached prefix")
	}
	if err == nil {
		_ = http.NewResponseController(w).Flush()
	}
	expected := end - start + 1
	if err != nil {
		return &StreamOutcome{
			ResponseStarted: true,
			StatusCode:      status,
			BytesWritten:    int64(n),
			ExpectedBytes:   expected,
			Err:             err,
			FailureReason:   classifyStreamCopyError(req.Context(), err),
			NoLearning:      true,
		}, true
	}

	cw := &continuationWriter{dst: w, header: make(http.Header), contStart: contStart, end: end}
	outcome := cont(cw, creq)
	if outcome == nil {
		outcome = &StreamOutcome{}
	}
	outcome.ResponseStarted = true
	outcome.StatusCode = status
	outcome.BytesWritten = int64(n) + cw.written
	outcome.ExpectedBytes = expected
	if cw.err != nil && outcome.Err == nil {
		outcome.Err = cw.err
		outcome.FailureReason = "continuation_mismatch"
	}
	if outcome.Err == nil && outcome.BytesWritten < expected {
		outcome.Err = errors.NewProxyError("cached prefix continuation ended early")
		outcome.FailureReason = "upstream_truncated"
	}
	if outcome.Err != nil {
		// Headers and prefix are committed: nothing may be appended by a retry.
		outcome.Retryable = false
		outcome.NoLearning = true
		if outcome.FailureReason == "" {
			outcome.FailureReason = "continuation_failed"
		}
	}
	return outcome, true
}

// continuationWriter receives the upstream continuation after the client
// response (headers + cached prefix) was already committed. The continuation's
// own headers go to a scratch map; its body is forwarded only if it really is
// a 206 for exactly [contStart, end], otherwise nothing is appended.
type continuationWriter struct {
	dst        http.ResponseWriter
	header     http.Header
	contStart  int64
	end        int64
	headerDone bool
	written    int64
	err        error
}

func (c *continuationWriter) Header() http.Header { return c.header }

func (c *continuationWriter) WriteHeader(status int) {
	if c.headerDone {
		return
	}
	c.headerDone = true
	if status != http.StatusPartialContent {
		c.err = errors.NewProxyError(fmt.Sprintf("continuation returned status %d", status))
		return
	}
	actual, ok := parseContentRange(c.header.Get("Content-Range"))
	if !ok || actual.Start != c.contStart || actual.End != c.end {
		log.Warn().
			Str("content_range", c.header.Get("Content-Range")).
			Int64("expected_start", c.contStart).
			Int64("expected_end", c.end).
			Msg("Continuation range mismatch; ending response after cached prefix")
		c.err = errors.NewProxyError("continuation range mismatch")
	}
}

func (c *continuationWriter) Write(b []byte) (int, error) {
	if !c.headerDone {
		c.WriteHeader(http.StatusOK)
	}
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.dst.Write(b)
	c.written += int64(n)
	return n, err
}

func (c *continuationWriter) Unwrap() http.ResponseWriter { return c.dst }

func (c *continuationWriter) Flush() {
	_ = http.NewResponseController(c.dst).Flush()
}
