package encrypt

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
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

// Separate ownership budgets: stream records use v3PlaybackMemory; immutable
// resident and evicted-but-pinned plaintext together use this 64 MiB cache.
// Without trustworthy revisions, keep same-exact-URL reuse short-lived.
var mobileV3Records = core.NewV3AuthenticatedRecordCache(64<<20, 30*time.Second)

// The route must authorize before calling serveV3Playback. Empty credentials
// have an explicit anonymous scope; an invalid target has no known scope/key.
// Exact URLs (including query/userinfo) remain bound until trusted revisions are
// available. Neither metadata nor an earlier cache hit is authorization proof.
func (p *ProxyServer) v3PlaybackCacheKey(r *http.Request, info *RedirectInfo, meta ContentMeta) (core.V3RecordCacheKey, error) {
	if p.strictFreshnessEnabled() {
		return core.V3RecordCacheKey{}, errors.New("v3: strict freshness has no trusted object revision")
	}
	target, err := url.Parse(info.RedirectURL)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		return core.V3RecordCacheKey{}, errors.New("v3: unknown cache target scope")
	}
	h := sha256.New()
	field := func(s string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		h.Write(size[:])
		h.Write([]byte(s))
	}
	field("mobile-v3-authorized-scope/v2")
	// Providers may authorize or select objects with arbitrary custom headers.
	// Bind both source sets conservatively, even headers currently not forwarded.
	// Range and Accept-Encoding alone are omitted: this service overwrites them
	// with its record window and identity encoding, respectively.
	for source, headers := range []http.Header{r.Header, info.Headers} {
		field(strconv.Itoa(source))
		names := make([]string, 0, len(headers))
		for name := range headers {
			if strings.EqualFold(name, "Range") || strings.EqualFold(name, "Accept-Encoding") {
				continue
			}
			names = append(names, name)
		}
		// Stable canonical names with a raw-name tie break also bind malformed
		// maps containing duplicate differently cased names without map-order races.
		sort.Slice(names, func(i, j int) bool {
			a, b := strings.ToLower(names[i]), strings.ToLower(names[j])
			if a == b {
				return names[i] < names[j]
			}
			return a < b
		})
		field(strconv.Itoa(len(names)))
		for _, name := range names {
			field(strings.ToLower(name))
			values := headers[name]
			field(strconv.Itoa(len(values)))
			for _, value := range values {
				field(value)
			}
		}
	}
	object := info.EncryptedPath
	if object == "" {
		object = info.OriginalURL
	}
	if object == "" {
		object = info.RedirectURL
	}
	// Length-delimited components prevent ambiguous provider/config namespaces.
	provider := fmt.Sprintf("%d:%s%d:%s%d:%s%d:%s", len(p.getAlistURL()), p.getAlistURL(), len(info.Provider), info.Provider, len(info.Driver), info.Driver, len(target.Scheme+"://"+target.Host), target.Scheme+"://"+target.Host)
	return core.NewV3RecordCacheKey(core.V3RecordIdentity{
		Provider: provider, Object: object, URL: info.RedirectURL,
		Scope: fmt.Sprintf("explicit-anonymous-or-credential-sha256:%x", h.Sum(nil)), Password: info.PasswdInfo.Password,
		Version: int64(meta.Version), HeaderSize: meta.HeaderLen, PlainSize: meta.PlainSize,
		CipherSize: meta.CiphertextSize, ChunkSize: int64(meta.ChunkSize), KDFIterations: meta.KDFIterations, Nonce: meta.NonceField,
	})
}

// Pin only a bounded contiguous prefix, never copy a complete media segment.
// A partial prefix ends on a record boundary, ready for an exact tail window.
func v3PlaybackCachedPrefix(key core.V3RecordCacheKey, start, end, chunk int64) ([]*core.V3RecordLease, []io.Reader, int64) {
	var leases []*core.V3RecordLease
	var readers []io.Reader
	position, pinned := start, int64(0)
	for position <= end && pinned <= (64<<20)-chunk {
		lease, hit := mobileV3Records.Get(key, uint64(position/chunk))
		if !hit {
			break
		}
		skip := position % chunk
		length := lease.Len() - skip
		if length <= 0 {
			lease.Release()
			break
		}
		if length > end-position+1 {
			length = end - position + 1
		}
		leases = append(leases, lease)
		readers = append(readers, io.NewSectionReader(lease, skip, length))
		pinned += chunk
		position += length
	}
	return leases, readers, position - start
}

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

// Admission failures are terminal resource errors, never signed-URL refresh
// signals. Use the common failure writer to remove stale success headers.
func v3PlaybackKDFFailure(w http.ResponseWriter, err error) error {
	status := http.StatusBadGateway
	if errors.Is(err, core.ErrV3KDFBusy) {
		status = http.StatusServiceUnavailable
	}
	return v3PlaybackFailure(w, status, err)
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
			if resp.StatusCode >= 200 && resp.StatusCode < 300 && !p.validateConfirmedMetadataResponse(r.Context(), resp) {
				resp.Body.Close()
				return nil, errors.New("v3: confirmed representation changed")
			}
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
		if !p.authorizeLocalWebDAVMetadata(w, r, info.EncryptedPath, meta) {
			return errors.New("v3: origin authorization or representation rejected")
		}
		commit()
		return nil
	}
	if err := r.Context().Err(); err != nil {
		return fail(http.StatusBadGateway, err)
	}
	chunk := int64(meta.ChunkSize)
	key, keyErr := p.v3PlaybackCacheKey(r, info, meta)
	var cache *core.V3AuthenticatedRecordCache
	var prefixReaders []io.Reader
	var prefixBytes int64
	if keyErr == nil {
		cache = mobileV3Records
		leases, readers, count := v3PlaybackCachedPrefix(key, start, end, chunk)
		defer func() {
			for _, lease := range leases {
				lease.Release()
			}
		}()
		prefixReaders, prefixBytes = readers, count
	}
	if prefixBytes == length {
		if !p.authorizeConfirmedMetadataCacheHit(w, r, info.EncryptedPath) {
			return errors.New("v3: cached-body origin authorization rejected")
		}
		// No media request/KDF: headerLatencyMs is deliberately not populated
		// with a fabricated provider measurement. Writer tracks actual first byte.
		commit()
		var buffer [32 << 10]byte
		count, err := io.CopyBuffer(w, v3ContextReader{r.Context(), io.MultiReader(prefixReaders...)}, buffer[:])
		if err == nil && count != length {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return &V3PlaybackError{Err: err, ResponseStarted: true, StatusCode: status, NoLearning: true}
		}
		return nil
	}
	// Prepare and authenticate the cold tail before committing a cached prefix.
	// One HTTP body covers all remaining records; no per-record HTTP regression.
	tailStart := start + prefixBytes
	// Preserve fast overload rejection without holding any record reservation
	// while a request waits for KDF admission. Actual ownership is acquired only
	// after successful derivation, before allocating records or reading bodies.
	memory := int64(meta.ChunkSize) + 16 + (64 << 10)
	if !v3PlaybackMemory.TryAcquire(memory) {
		return fail(http.StatusServiceUnavailable, errors.New("v3: playback memory budget exhausted"))
	}
	v3PlaybackMemory.Release(memory)
	cipherStart, cipherEnd := core.V3ChunkWindow(tailStart, end, chunk)
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
	keyBytes, err := core.DeriveV3KeyContext(r.Context(), info.PasswdInfo.Password, meta.NonceField, meta.KDFIterations, core.V3KDFForeground)
	if err != nil {
		return v3PlaybackKDFFailure(w, err)
	}
	if err := r.Context().Err(); err != nil {
		return v3PlaybackKDFFailure(w, err)
	}
	if !v3PlaybackMemory.TryAcquire(memory) {
		return fail(http.StatusServiceUnavailable, errors.New("v3: playback memory budget exhausted"))
	}
	defer v3PlaybackMemory.Release(memory)
	cipher, err := core.NewV3ChunkCipher(keyBytes, meta.NonceField)
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
	window := io.LimitReader(body, cipherEnd-cipherStart+1)
	nextRaw := uint64(tailStart / chunk)
	var raw []byte
	loader := func(ctx context.Context, index uint64) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if index < nextRaw {
			return nil, errors.New("v3: out-of-order record loader")
		}
		// A later cached record is not read by the record reader; advance this
		// same body only when a subsequent miss needs the next raw record.
		if index > nextRaw {
			if _, err := io.CopyN(io.Discard, window, int64(index-nextRaw)*(chunk+16)); err != nil {
				return nil, err
			}
		}
		if raw == nil {
			raw = make([]byte, chunk+16)
		}
		if _, err := io.ReadFull(window, raw); err != nil {
			return nil, err
		}
		nextRaw = index + 1
		return raw, nil
	}
	var reader *core.V3StreamReader
	if cache == nil {
		reader, err = core.NewV3StreamReader(window, cipher, chunk, tailStart/chunk, tailStart%chunk, length-prefixBytes)
	} else {
		reader, err = core.NewV3RecordReader(r.Context(), cipher, chunk, tailStart/chunk, tailStart%chunk, length-prefixBytes, meta.PlainSize, cache, key, loader)
	}
	if err != nil {
		return fail(http.StatusBadGateway, err)
	}
	defer reader.Close()
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
	count := int64(0)
	if prefixBytes != 0 {
		var buffer [32 << 10]byte
		count, err = io.CopyBuffer(w, v3ContextReader{r.Context(), io.MultiReader(prefixReaders...)}, buffer[:])
		if err == nil && count != prefixBytes {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			return &V3PlaybackError{Err: err, ResponseStarted: true, StatusCode: status, NoLearning: true}
		}
	}
	written, err := w.Write(first[:n])
	count += int64(written)
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
