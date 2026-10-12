package encrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	core "github.com/alist-encrypt-go/shared/encryptcore"
	"golang.org/x/sync/semaphore"
)

// V3PlaybackError is terminal. Callers must not append an error response or
// retry another strategy once ResponseStarted is true (including error headers).
// V3 failures are deliberately excluded from provider capability learning.
type V3PlaybackError struct {
	Err             error
	ResponseStarted bool
	StatusCode      int
	NoLearning      bool
	UpstreamStatus  int // internal precommit signed-URL refresh signal
}

func (e *V3PlaybackError) Error() string { return e.Err.Error() }
func (e *V3PlaybackError) Unwrap() error { return e.Err }

const v3PlaybackMemoryBytes int64 = 256 << 20
const v3PlaybackDefaultDiscardBytes int64 = 8 << 20

var v3PlaybackMemory = semaphore.NewWeighted(v3PlaybackMemoryBytes)

func v3PlaybackFailure(w http.ResponseWriter, status int, err error, unsatisfiedSize ...int64) error {
	for _, h := range []string{"Content-Length", "Content-Range", "Content-Type", "Content-Encoding", "Transfer-Encoding", "ETag", "Last-Modified", "Content-Disposition", "Accept-Ranges", "Digest", "Content-MD5"} {
		w.Header().Del(h)
	}
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "2")
	}
	if len(unsatisfiedSize) != 0 {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", unsatisfiedSize[0]))
	}
	w.WriteHeader(status)
	return &V3PlaybackError{Err: err, ResponseStarted: true, StatusCode: status, NoLearning: true}
}

// v3PlaybackRequest preserves origin credential isolation on every redirect.
// The configured stream transport supplies its body-idle timeout; the request
// context, not a total client timeout, owns the lifetime of a media stream.
func (p *ProxyServer) v3PlaybackRequest(r *http.Request, info *RedirectInfo, rangeHeader string) (*http.Response, error) {
	configured := p.streamClientSnapshot()
	if configured == nil {
		return nil, errors.New("v3: stream client unavailable")
	}
	client := *configured
	client.Timeout = 0
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	target := info.RedirectURL
	for redirects := 0; redirects <= 5; redirects++ {
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		p.applyRoutingHints(req, info.Provider, info.Driver)
		copyPlaybackStreamHeaders(req.Header, r.Header, info.Headers, target, p.getAlistURL())
		// Conditional responses cannot provide an authenticated record window.
		for _, h := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since"} {
			req.Header.Del(h)
		}
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			next, err := req.URL.Parse(strings.TrimSpace(resp.Header.Get("Location")))
			resp.Body.Close()
			if err != nil {
				return nil, err
			}
			if redirects == 5 || next.Scheme != "http" && next.Scheme != "https" || resp.Header.Get("Location") == "" {
				return nil, errors.New("v3: invalid upstream redirect")
			}
			target = next.String()
		default:
			return resp, nil
		}
	}
	return nil, errors.New("v3: too many upstream redirects")
}

func v3IdentityResponse(resp *http.Response) bool {
	encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
	return !resp.Uncompressed && (encoding == "" || strings.EqualFold(encoding, "identity"))
}

// Strict decimal Content-Range matching rejects wildcard totals and windows
// wider/narrower than requested: never decrypt bytes at a guessed chunk index.
func v3ExactContentRange(value string, start, end, total int64) bool {
	if !strings.HasPrefix(value, "bytes ") {
		return false
	}
	halves := strings.Split(strings.TrimPrefix(value, "bytes "), "/")
	if len(halves) != 2 {
		return false
	}
	bounds := strings.Split(halves[0], "-")
	if len(bounds) != 2 {
		return false
	}
	values := []string{bounds[0], bounds[1], halves[1]}
	expected := []int64{start, end, total}
	for i, text := range values {
		if text == "" {
			return false
		}
		for _, c := range text {
			if c < '0' || c > '9' {
				return false
			}
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil || n != expected[i] {
			return false
		}
	}
	return true
}

type v3ContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r v3ContextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(b)
}

// serveV3Playback requires authoritative, fully resolved header/trailer metadata.
// It never probes metadata, routes legacy requests, or passes ciphertext through.
func (p *ProxyServer) serveV3Playback(w http.ResponseWriter, r *http.Request, info *RedirectInfo, meta ContentMeta) error {
	err := p.serveV3PlaybackAttempt(w, r, info, meta, true)
	var failure *V3PlaybackError
	if !errors.As(err, &failure) || failure.ResponseStarted || failure.UpstreamStatus == 0 {
		return err
	}
	// The attempt has already closed its response and released its memory lease.
	// Only one signed-URL refresh is allowed, before any record/KDF/body output.
	if info == nil || strings.TrimSpace(info.EncryptedPath) == "" || r.Context().Err() != nil {
		return v3PlaybackFailure(w, http.StatusBadGateway, failure)
	}
	fresh, ok := p.refreshRedirectInfo(r.Context(), "", r.Header, info)
	if !ok {
		return v3PlaybackFailure(w, http.StatusBadGateway, errors.New("v3: signed URL refresh failed"))
	}
	// A resolver may return the same URL for a replaced object. The existing
	// refresh helper reprobes changed URLs; explicitly recheck an unchanged URL.
	if fresh.RedirectURL == info.RedirectURL {
		if fresh.PasswdInfo == nil || !fresh.PasswdInfo.Enable {
			return v3PlaybackFailure(w, http.StatusBadGateway, errors.New("v3: refreshed encryption configuration is unavailable"))
		}
		probeMeta, confirmed := p.inspectEncryptedContentWithFallbackConfirmed(r.Context(), fresh.RedirectURL, fresh.Headers, fresh.PasswdInfo, fresh.CiphertextSize, strings.TrimPrefix(encryptedDAVPath(fresh.EncryptedPath), "/dav"))
		if !confirmed || !probeMeta.IsV3() || ValidateV3ContentMeta(probeMeta) != nil {
			return v3PlaybackFailure(w, http.StatusBadGateway, errors.New("v3: refreshed object metadata could not be confirmed"))
		}
		fresh.ContentVersion = probeMeta.Version
		fresh.HeaderLen = probeMeta.HeaderLen
		fresh.FileSize = probeMeta.PlainSize
		fresh.CiphertextSize = probeMeta.CiphertextSize
		fresh.NonceField = cloneNonceField(probeMeta.NonceField)
		fresh.ChunkSize = probeMeta.ChunkSize
		fresh.KDFIterations = probeMeta.KDFIterations
	}
	freshMeta, complete := redirectInfoContentMeta(fresh)
	if !complete || !freshMeta.IsV3() {
		return v3PlaybackFailure(w, http.StatusBadGateway, errors.New("v3: refreshed object lacks complete V3 metadata"))
	}
	if err := ValidateV3ContentMeta(freshMeta); err != nil {
		return v3PlaybackFailure(w, http.StatusBadGateway, err)
	}
	// Reparse the original plaintext Range against the refreshed size/geometry.
	return p.serveV3PlaybackAttempt(w, r, fresh, freshMeta, false)
}

func (p *ProxyServer) serveV3PlaybackAttempt(w http.ResponseWriter, r *http.Request, info *RedirectInfo, meta ContentMeta, allowRefresh bool) error {
	started := time.Now()
	fail := func(status int, err error) error { return v3PlaybackFailure(w, status, err) }
	if err := ValidateV3ContentMeta(meta); err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrV3ResourceLimit) {
			status = http.StatusServiceUnavailable
		}
		return fail(status, err)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		return fail(http.StatusMethodNotAllowed, errors.New("v3: unsupported method"))
	}
	if info == nil || info.PasswdInfo == nil {
		return fail(http.StatusBadGateway, errors.New("v3: missing playback encryption configuration"))
	}
	rangeHeader := strings.TrimSpace(r.Header.Get("Range"))
	if strings.Contains(rangeHeader, ",") {
		return fail(http.StatusBadRequest, errors.New("v3: multiple ranges are unsupported"))
	}
	start, end, hasRange, err := parseSingleRange(rangeHeader, meta.PlainSize)
	if err != nil {
		return v3PlaybackFailure(w, http.StatusRequestedRangeNotSatisfiable, err, meta.PlainSize)
	}
	if !hasRange {
		start, end = 0, meta.PlainSize-1
	}
	length := meta.PlainSize
	status := http.StatusOK
	if hasRange {
		length = end - start + 1
		status = http.StatusPartialContent
	}
	timing, _ := r.Context().Value(playbackTimingKey{}).(*playbackTiming)
	if timing != nil {
		timing.rangeStart, timing.totalBytes = start, meta.PlainSize
		timing.streamStarted = started
	}
	commit := func() {
		for _, h := range []string{"Content-Range", "Content-Encoding", "Transfer-Encoding", "ETag", "Content-MD5", "Digest"} {
			w.Header().Del(h)
		}
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		if hasRange {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, meta.PlainSize))
		}
		w.WriteHeader(status)
	}
	if r.Method == http.MethodHead || length == 0 {
		commit()
		return nil
	}
	if err := r.Context().Err(); err != nil {
		return fail(http.StatusBadGateway, err)
	}
	// Charge the record plus both small streaming buffers before KDF or body IO.
	memory := int64(meta.ChunkSize) + 16 + (64 << 10)
	if !v3PlaybackMemory.TryAcquire(memory) {
		return fail(http.StatusServiceUnavailable, errors.New("v3: playback memory budget exhausted"))
	}
	defer v3PlaybackMemory.Release(memory)
	chunk := int64(meta.ChunkSize)
	cipherStart, cipherEnd := core.V3ChunkWindow(start, end, chunk)
	upstreamStarted := time.Now()
	resp, err := p.v3PlaybackRequest(r, info, fmt.Sprintf("bytes=%d-%d", cipherStart, cipherEnd))
	if err != nil {
		return fail(http.StatusBadGateway, err)
	}
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()
	if allowRefresh && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound) {
		return &V3PlaybackError{Err: fmt.Errorf("v3: upstream signed URL rejected (%d)", resp.StatusCode), StatusCode: http.StatusBadGateway, UpstreamStatus: resp.StatusCode, NoLearning: true}
	}
	fallback := resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusRequestedRangeNotSatisfiable
	if fallback {
		cap := v3PlaybackDefaultDiscardBytes
		if cfg := p.configSnapshot(); cfg != nil && cfg.RangeSkipMaxBytes > 0 {
			cap = cfg.RangeSkipMaxBytes
		}
		// Includes record/tag amplification and front matter, not plaintext offset.
		// This check MUST precede KDF, full retry, body reads, and success headers.
		if cipherStart > cap {
			return fail(http.StatusBadGateway, fmt.Errorf("v3: fallback discard %d exceeds budget %d", cipherStart, cap))
		}
		if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
			resp.Body.Close()
			resp, err = p.v3PlaybackRequest(r, info, "")
			if err != nil {
				return fail(http.StatusBadGateway, err)
			}
		}
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Range") != "" || !v3IdentityResponse(resp) || resp.ContentLength != meta.CiphertextSize {
			return fail(http.StatusBadGateway, errors.New("v3: invalid full fallback representation"))
		}
	} else if resp.StatusCode != http.StatusPartialContent || !v3IdentityResponse(resp) || !v3ExactContentRange(resp.Header.Get("Content-Range"), cipherStart, cipherEnd, meta.CiphertextSize) || resp.ContentLength != cipherEnd-cipherStart+1 {
		return fail(http.StatusBadGateway, errors.New("v3: invalid upstream record window"))
	}
	if err := r.Context().Err(); err != nil {
		return fail(http.StatusBadGateway, err)
	}
	// Header latency measures only upstream request/validated-header readiness,
	// not handler metadata probes, KDF, first-record authentication, or body IO.
	if timing != nil {
		timing.headerLatencyMs = time.Since(upstreamStarted).Seconds() * 1000
	}
	cipher, err := core.NewV3ChunkCipher(core.DeriveV3Key(info.PasswdInfo.Password, meta.NonceField, meta.KDFIterations), meta.NonceField)
	if err != nil {
		return fail(http.StatusBadGateway, err)
	}
	body := v3ContextReader{r.Context(), resp.Body}
	if fallback {
		if _, err := io.CopyN(io.Discard, body, cipherStart); err != nil {
			return fail(http.StatusBadGateway, err)
		}
	}
	// The stream reader must never consume padding trailer or tail payload as a
	// record. Real plaintext limit also trims the last record's padded plaintext.
	reader, err := core.NewV3StreamReader(io.LimitReader(body, cipherEnd-cipherStart+1), cipher, chunk, start/chunk, start%chunk, length)
	if err != nil {
		return fail(http.StatusBadGateway, err)
	}
	var first [32 << 10]byte
	n, err := reader.Read(first[:]) // authenticates a complete first record before 2xx
	if err != nil || n == 0 {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fail(http.StatusBadGateway, err)
	}
	if err := r.Context().Err(); err != nil {
		return fail(http.StatusBadGateway, err)
	}
	commit()
	written, err := w.Write(first[:n])
	count := int64(written)
	if err == nil && written != n {
		err = io.ErrShortWrite
	}
	if err == nil {
		var buffer [32 << 10]byte
		var more int64
		more, err = io.CopyBuffer(w, reader, buffer[:])
		count += more
	}
	if err == nil && count != length {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return &V3PlaybackError{Err: err, ResponseStarted: true, StatusCode: status, NoLearning: true}
	}
	return nil
}
