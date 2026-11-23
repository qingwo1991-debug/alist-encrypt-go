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
	pw := &prefixResponseWriter{
		ResponseWriter: w,
		prefix:         prefix,
		start:          start,
		contStart:      contStart,
		end:            end,
		total:          fileSize,
		wholeBody:      rangeHeader == "",
	}
	log.Info().
		Str("category", "playback").
		Str("target_url", targetURL).
		Str("client_range", rangeHeader).
		Int64("prefix_bytes", int64(len(prefix))).
		Int64("continuation_start", contStart).
		Msg("Serving decrypted cache prefix with upstream continuation")

	outcome := cont(pw, creq)
	if outcome == nil {
		outcome = &StreamOutcome{}
	}
	if pw.prefixDone {
		outcome.ResponseStarted = true
		outcome.BytesWritten += pw.prefixWritten
		outcome.ExpectedBytes += int64(len(prefix))
		if pw.wholeBody {
			outcome.StatusCode = http.StatusOK
		}
		if pw.err != nil && outcome.Err == nil {
			outcome.Err = pw.err
			outcome.FailureReason = classifyStreamCopyError(req.Context(), pw.err)
			outcome.Retryable = false
			outcome.NoLearning = true
		}
	}
	return outcome, true
}

// prefixResponseWriter rewrites the continuation's 206 headers to describe the
// client's original interval, then writes the cached prefix before any
// continuation body bytes. If the continuation fails before committing headers,
// nothing reaches the client and the caller's retry/fallback logic still works.
type prefixResponseWriter struct {
	http.ResponseWriter
	prefix        []byte
	start         int64
	contStart     int64
	end           int64
	total         int64
	wholeBody     bool
	headerDone    bool
	prefixDone    bool
	prefixWritten int64
	err           error
}

func (p *prefixResponseWriter) WriteHeader(status int) {
	if p.headerDone {
		p.ResponseWriter.WriteHeader(status)
		return
	}
	p.headerDone = true
	h := p.ResponseWriter.Header()
	if status != http.StatusPartialContent {
		p.ResponseWriter.WriteHeader(status)
		return
	}
	actual, ok := parseContentRange(h.Get("Content-Range"))
	if !ok || actual.Start != p.contStart || actual.End != p.end {
		// Still a truthful 206 for the interval it describes.
		log.Warn().
			Str("content_range", h.Get("Content-Range")).
			Int64("expected_start", p.contStart).
			Int64("expected_end", p.end).
			Msg("Continuation range mismatch; passing through without cached prefix")
		p.ResponseWriter.WriteHeader(status)
		return
	}
	if p.wholeBody {
		h.Del("Content-Range")
		h.Set("Content-Length", strconv.FormatInt(p.total, 10))
		status = http.StatusOK
	} else {
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", p.start, p.end, p.total))
		h.Set("Content-Length", strconv.FormatInt(p.end-p.start+1, 10))
	}
	p.ResponseWriter.WriteHeader(status)
	p.prefixDone = true
	n, err := p.ResponseWriter.Write(p.prefix)
	p.prefixWritten = int64(n)
	if err == nil && n < len(p.prefix) {
		err = errors.NewProxyError("short write of cached prefix")
	}
	p.err = err
}

func (p *prefixResponseWriter) Write(b []byte) (int, error) {
	if !p.headerDone {
		p.WriteHeader(http.StatusOK)
	}
	if p.err != nil {
		return 0, p.err
	}
	return p.ResponseWriter.Write(b)
}

func (p *prefixResponseWriter) Unwrap() http.ResponseWriter { return p.ResponseWriter }

func (p *prefixResponseWriter) Flush() {
	_ = http.NewResponseController(p.ResponseWriter).Flush()
}
