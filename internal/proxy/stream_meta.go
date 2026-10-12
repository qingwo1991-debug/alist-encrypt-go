package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

type contentMetaContextKey struct{}

// ContentInspectionResult preserves whether a prefix probe conclusively
// identified the content format. A legacy-looking ContentMeta alone is
// ambiguous: it can mean either a complete V1 prefix or a failed/short probe.
// StatusCode is the final upstream HTTP status (zero for transport failures).
type ContentInspectionResult struct {
	Meta       encryption.ContentMeta
	Confirmed  bool
	StatusCode int
}

type uploadMetaEntry struct {
	Meta      encryption.ContentMeta
	ExpiresAt time.Time
}

const uploadMetaTTL = 30 * time.Minute

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
	return s.inspectEncryptedContentResult(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize).Meta
}

func (s *StreamProxy) inspectEncryptedContentConfirmed(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) (encryption.ContentMeta, bool) {
	result := s.inspectEncryptedContentResult(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize)
	return result.Meta, result.Confirmed
}

func (s *StreamProxy) inspectEncryptedContentResult(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) ContentInspectionResult {
	encType := encryption.EncType("")
	if passwdInfo != nil {
		encType = encryption.EncType(passwdInfo.EncType)
	}
	meta := encryption.LegacyContentMeta(encType, ciphertextSize)
	result := ContentInspectionResult{Meta: meta}
	if s == nil || passwdInfo == nil || !passwdInfo.Enable || strings.TrimSpace(targetURL) == "" {
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Streaming clients intentionally have no overall HTTP timeout. Tiny probes
	// need a separate wall-clock budget including body reads, redirects, and
	// V3 header/trailer follow-ups; never restart that budget per request.
	budget := 8 * time.Second
	if s.cfg != nil {
		if seconds := s.cfg.AlistServerSnapshot().RangeProbeTimeoutSeconds; seconds > 0 {
			budget = time.Duration(seconds) * time.Second
		}
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	currentURL := strings.TrimSpace(targetURL)
	currentAuth := authHeaders
	maxHops := 2
	if s.cfg != nil {
		if configured := s.cfg.AlistServerSnapshot().RedirectMaxHops; configured > 0 {
			maxHops = configured
		}
	}
	for hop := 0; hop <= maxHops; hop++ {
		req, err := httputil.NewRequest(http.MethodGet, currentURL).
			WithContext(ctx).
			Build()
		if err != nil {
			return result
		}
		// Keep V1/V2 to one prefix range. V3 completes its 48-byte header
		// separately, and streaming V3 also resolves its EOF size trailer.
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", encryption.ContentHeaderSize()-1))
		req.Header.Set("Accept-Encoding", "identity")
		copyProbeAuthHeaders(req, currentAuth)

		resp, err := s.client.Do(req)
		if err != nil {
			return result
		}
		result.StatusCode = resp.StatusCode
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			resp.Body.Close()
			if location == "" {
				return result
			}
			nextURL, err := resolveRedirectTarget(currentURL, location)
			if err != nil {
				return result
			}
			previous, previousErr := url.Parse(currentURL)
			next, nextErr := url.Parse(nextURL)
			if previousErr != nil || nextErr != nil || !sameRedirectOrigin(previous, next) {
				currentAuth = make(http.Header)
			}
			currentURL = nextURL
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= http.StatusBadRequest {
			return result
		}
		// Probe enough bytes to recognize either a V1/V2 header or a V3
		// container prefix (48 bytes); V3 must never be mislabeled as legacy.
		probePrefixLen := int64(encryption.ContentHeaderSize())
		if probePrefixLen < encryption.V3HeaderSize {
			probePrefixLen = int64(encryption.V3HeaderSize)
		}
		prefix, err := io.ReadAll(io.LimitReader(resp.Body, probePrefixLen))
		resp.Body.Close()
		if err != nil {
			return result
		}
		if total := parseContentRangeTotal(resp.Header.Get("Content-Range")); total > 0 {
			meta.CiphertextSize = total
			meta.PlainSize = total
		} else if meta.CiphertextSize <= 0 {
			cl := resp.Header.Get("Content-Length")
			if total, err := strconv.ParseInt(cl, 10, 64); err == nil && total > 0 && resp.StatusCode == http.StatusOK {
				meta.CiphertextSize = total
				meta.PlainSize = total
			}
		}
		// Require only the V1/V2 header length to proceed; V3 recognition is
		// an opportunistic bonus when the probe actually received 48 bytes.
		expectedPrefix := int64(encryption.ContentHeaderSize())
		if meta.CiphertextSize > 0 && meta.CiphertextSize < expectedPrefix {
			expectedPrefix = meta.CiphertextSize
		}
		if expectedPrefix <= 0 || int64(len(prefix)) < expectedPrefix {
			// io.ReadAll on a LimitReader reports no error for a short body. Do not
			// classify a truncated probe as a confirmed legacy file, because resumed
			// encryption would then use incompatible metadata.
			result.Meta = meta
			return result
		}
		if encryption.IsV3Prefix(prefix) {
			if resp.StatusCode == http.StatusPartialContent {
				actual, valid := parseContentRange(resp.Header.Get("Content-Range"))
				if !valid || !actual.TotalKnown || actual.Start != 0 || actual.End != int64(len(prefix))-1 || actual.Total != meta.CiphertextSize {
					return result
				}
			} else if resp.StatusCode != http.StatusOK {
				return result
			}
			// A recognized but incomplete V3 container is never confirmed legacy.
			if len(prefix) < int(encryption.V3HeaderSize) {
				prefix, err = s.probeV3Tail(ctx, currentURL, currentAuth, prefix, meta.CiphertextSize)
				if err != nil {
					result.StatusCode = v3ProbeFailureStatus(err)
					return result
				}
			}
			parsed, ok, parseErr := encryption.ParseFrontMatter(encType, prefix, meta.CiphertextSize)
			if parseErr != nil || !ok || !validV3ProbeHeader(prefix, parsed) {
				return result
			}
			if parsed.PlainSize == 0 && parsed.CiphertextSize != parsed.HeaderLen {
				trailer, trailerErr := s.probeV3Range(ctx, currentURL, currentAuth, meta.CiphertextSize-16, meta.CiphertextSize-1, meta.CiphertextSize)
				if trailerErr != nil {
					result.StatusCode = v3ProbeFailureStatus(trailerErr)
					return result
				}
				if len(trailer) != 16 || string(trailer[:4]) != "V3E4" || binary.BigEndian.Uint32(trailer[4:8]) != 0 {
					return result
				}
				parsed.PlainSize = int64(binary.BigEndian.Uint64(trailer[8:16]))
				if !validV3ProbeGeometry(parsed, true) {
					return result
				}
			} else if !validV3ProbeGeometry(parsed, false) {
				return result
			}
			result.Meta, result.Confirmed = parsed, true
			return result
		}
		parsed, ok, err := encryption.ParseFrontMatter(encType, prefix, meta.CiphertextSize)
		if err != nil {
			result.Meta = meta
			return result
		}
		if ok {
			result.Meta = parsed
			result.Confirmed = true
			return result
		}
		result.Meta = meta
		result.Confirmed = true
		return result
	}
	return result
}

func (s *StreamProxy) InspectEncryptedContent(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) encryption.ContentMeta {
	return s.inspectEncryptedContent(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize)
}

// InspectEncryptedContentResult returns both parsed metadata and the probe's
// certainty/status so callers can stop after a confirmed V1 result and only
// retry authentication when the upstream actually rejected it.
func (s *StreamProxy) InspectEncryptedContentResult(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) ContentInspectionResult {
	return s.inspectEncryptedContentResult(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize)
}

// probeV3Tail completes a partial V3 header probe: it fetches the remaining
// header bytes (48 total, 16 beyond the legacy 32) so the front matter can be
// certified as V3. The returned slice is the full 48-byte prefix on success.
func (s *StreamProxy) probeV3Tail(ctx context.Context, targetURL string, authHeaders http.Header, prefix []byte, total int64) ([]byte, error) {
	tail, err := s.probeV3Range(ctx, targetURL, authHeaders, int64(len(prefix)), encryption.V3HeaderSize-1, total)
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), prefix...), tail...), nil
}

// v3ProbeError preserves the follow-up response status for auth negotiation.
// A transport failure has status zero, not the successful prefix's stale 206.
type v3ProbeError struct {
	status int
	err    error
}

func (e *v3ProbeError) Error() string { return e.err.Error() }
func (e *v3ProbeError) Unwrap() error { return e.err }

func v3ProbeFailureStatus(err error) int {
	var probeErr *v3ProbeError
	if errors.As(err, &probeErr) {
		return probeErr.status
	}
	return 0
}

// probeV3Range never accepts a full-body response or reads beyond the tiny
// requested window. Header completion and EOF probing retain the caller's
// cancellation/deadline, including the inspection's single total probe budget.
func (s *StreamProxy) probeV3Range(ctx context.Context, targetURL string, authHeaders http.Header, start, end, total int64) ([]byte, error) {
	if start < 0 || end < start || total <= end || end-start >= encryption.V3HeaderSize {
		return nil, fmt.Errorf("v3 probe: invalid range geometry")
	}
	req, err := httputil.NewRequest(http.MethodGet, targetURL).WithContext(ctx).Build()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	req.Header.Set("Accept-Encoding", "identity")
	copyProbeAuthHeaders(req, authHeaders)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	failure := func(err error) ([]byte, error) {
		return nil, &v3ProbeError{status: resp.StatusCode, err: err}
	}
	actual, valid := parseContentRange(resp.Header.Get("Content-Range"))
	if resp.StatusCode != http.StatusPartialContent || !valid || !actual.TotalKnown || actual.Start != start || actual.End != end || actual.Total != total {
		return failure(fmt.Errorf("v3 probe: upstream did not return the exact requested range"))
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return failure(fmt.Errorf("v3 probe: encoded range response"))
	}
	length := end - start + 1
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		n, parseErr := strconv.ParseInt(cl, 10, 64)
		if parseErr != nil || n != length {
			return failure(fmt.Errorf("v3 probe: incorrect content length"))
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, length+1))
	if err != nil {
		return failure(fmt.Errorf("v3 probe: read body: %w", err))
	}
	if int64(len(body)) != length {
		return failure(fmt.Errorf("v3 probe: short or oversized body"))
	}
	return body, nil
}

func validV3ProbeHeader(prefix []byte, meta encryption.ContentMeta) bool {
	return len(prefix) == int(encryption.V3HeaderSize) &&
		binary.BigEndian.Uint32(prefix[32:36]) == meta.ChunkSize && meta.ChunkSize > 0 &&
		binary.BigEndian.Uint32(prefix[36:40]) == 16 && meta.PlainSize >= 0
}

func validV3ProbeGeometry(meta encryption.ContentMeta, trailer bool) bool {
	bodySize := meta.CiphertextSize - meta.HeaderLen
	if trailer {
		bodySize -= 16
	}
	recordSize := int64(meta.ChunkSize) + 16
	if bodySize < 0 || bodySize%recordSize != 0 || meta.PlainSize < 0 {
		return false
	}
	// Avoid overflow from ceil(size/chunk) and multiplication on untrusted
	// uint64 trailer sizes. Compare record counts using division instead.
	chunks := meta.PlainSize / int64(meta.ChunkSize)
	if meta.PlainSize%int64(meta.ChunkSize) != 0 {
		chunks++
	}
	return bodySize/recordSize == chunks
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
	if meta.IsV3() {
		return buildV3UpstreamRangeHeader(rangeHeader, meta)
	}
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
		if meta.PlainSize <= 0 {
			return rangeHeader
		}
		suffixLen, err := strconv.ParseInt(endText, 10, 64)
		if err != nil || suffixLen <= 0 {
			return rangeHeader
		}
		if suffixLen > meta.PlainSize {
			suffixLen = meta.PlainSize
		}
		start := meta.HeaderLen + meta.PlainSize - suffixLen
		end := meta.HeaderLen + meta.PlainSize - 1
		return fmt.Sprintf("bytes=%d-%d", start, end)
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

// buildV3UpstreamRangeHeader0 translates a client plaintext Range into the
// contiguous ciphertext chunk window covering it. Records are fixed width, so
// one upstream range serves any number of chunk records contiguously; the
// stream reader slices the requested plain after per-chunk AEAD.
func buildV3UpstreamRangeHeader(headRange string, meta encryption.ContentMeta) string {
	headRange = strings.TrimSpace(headRange)
	if headRange == "" || !strings.HasPrefix(headRange, "bytes=") {
		return headRange
	}
	parts := strings.SplitN(strings.TrimPrefix(headRange, "bytes="), ",", 2)
	if len(parts) == 0 {
		return headRange
	}
	spec := strings.TrimSpace(parts[0])
	bounds := strings.SplitN(spec, "-", 2)
	if len(bounds) != 2 {
		return headRange
	}
	startText := strings.TrimSpace(bounds[0])
	endText := strings.TrimSpace(bounds[1])
	chunkSize := int64(meta.ChunkSize)
	if chunkSize <= 0 {
		chunkSize = encryption.V3DefaultChunkSize()
	}
	var start, end int64
	if startText == "" {
		if meta.PlainSize <= 0 {
			return headRange
		}
		suffixLen, err := strconv.ParseInt(endText, 10, 64)
		if err != nil || suffixLen <= 0 {
			return headRange
		}
		start = meta.PlainSize - suffixLen
		if start < 0 {
			start = 0
		}
		end = meta.PlainSize - 1
	} else {
		var err error
		start, err = strconv.ParseInt(startText, 10, 64)
		if err != nil || start < 0 {
			return headRange
		}
		if endText != "" {
			end, err = strconv.ParseInt(endText, 10, 64)
			if err != nil || end < start {
				return headRange
			}
		} else {
			if meta.PlainSize <= 0 {
				return headRange
			}
			end = meta.PlainSize - 1
		}
		if meta.PlainSize > 0 && end >= meta.PlainSize {
			end = meta.PlainSize - 1
		}
	}
	cstart, cend := encryption.V3ChunkWindow(start, end, chunkSize)
	return fmt.Sprintf("bytes=%d-%d", cstart, cend)
}

func normalizeV2ClientRangeHeader(rangeHeader string, meta encryption.ContentMeta) string {
	if !meta.IsV2() || meta.PlainSize <= 0 || meta.HeaderLen <= 0 {
		return rangeHeader
	}
	ciphertextSize := meta.TotalCiphertextSize()
	if ciphertextSize <= meta.PlainSize {
		return rangeHeader
	}
	rangeHeader = strings.TrimSpace(rangeHeader)
	if rangeHeader == "" || !strings.HasPrefix(rangeHeader, "bytes=") {
		return rangeHeader
	}
	if strings.Contains(rangeHeader, ",") {
		return rangeHeader
	}
	spec := strings.TrimSpace(strings.TrimPrefix(rangeHeader, "bytes="))
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
	if err != nil || start < meta.PlainSize || start >= ciphertextSize {
		return rangeHeader
	}
	start -= meta.HeaderLen
	if start < 0 {
		start = 0
	}
	if start >= meta.PlainSize {
		start = meta.PlainSize - 1
	}
	if endText == "" {
		return fmt.Sprintf("bytes=%d-", start)
	}
	end, err := strconv.ParseInt(endText, 10, 64)
	if err != nil || end < 0 {
		return rangeHeader
	}
	if end >= ciphertextSize {
		end = ciphertextSize - 1
	}
	end -= meta.HeaderLen
	if end >= meta.PlainSize {
		end = meta.PlainSize - 1
	}
	if end < start {
		end = start
	}
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
			if stored.PlainSize <= 0 && !isEmptyV3Meta(stored) {
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

func uploadMetaKey(targetURL, filePath string) string {
	parsed, err := url.Parse(targetURL)
	baseKey := targetURL
	if err == nil {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		baseKey = parsed.String()
	}
	filePath = strings.TrimSpace(filePath)
	if decoded, decodeErr := url.QueryUnescape(filePath); decodeErr == nil {
		filePath = strings.TrimSpace(decoded)
	}
	if filePath == "" {
		return baseKey
	}
	return fmt.Sprintf("%s\x00file-path:%s", baseKey, filePath)
}

func (s *StreamProxy) getUploadMeta(targetURL, filePath string) (encryption.ContentMeta, bool) {
	if s == nil {
		return encryption.ContentMeta{}, false
	}
	key := uploadMetaKey(targetURL, filePath)
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
	entry.ExpiresAt = time.Now().Add(uploadMetaTTL)
	s.uploadMeta[key] = entry
	return entry.Meta, true
}

func (s *StreamProxy) putUploadMeta(targetURL, filePath string, meta encryption.ContentMeta) {
	if s == nil || !meta.IsV2() {
		return
	}
	key := uploadMetaKey(targetURL, filePath)
	s.uploadMetaMu.Lock()
	defer s.uploadMetaMu.Unlock()
	s.uploadMeta[key] = uploadMetaEntry{
		Meta:      meta,
		ExpiresAt: time.Now().Add(uploadMetaTTL),
	}
}

func (s *StreamProxy) deleteUploadMeta(targetURL, filePath string) {
	if s == nil {
		return
	}
	key := uploadMetaKey(targetURL, filePath)
	s.uploadMetaMu.Lock()
	delete(s.uploadMeta, key)
	s.uploadMetaMu.Unlock()
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

type parsedContentRange struct {
	Start      int64
	End        int64
	Total      int64
	TotalKnown bool
}

func parseContentRange(contentRange string) (parsedContentRange, bool) {
	fields := strings.Fields(strings.TrimSpace(contentRange))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "bytes") {
		return parsedContentRange{}, false
	}
	rangeAndTotal := strings.SplitN(fields[1], "/", 2)
	if len(rangeAndTotal) != 2 || strings.TrimSpace(rangeAndTotal[1]) == "" {
		return parsedContentRange{}, false
	}
	bounds := strings.SplitN(rangeAndTotal[0], "-", 2)
	if len(bounds) != 2 {
		return parsedContentRange{}, false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(bounds[0]), 10, 64)
	if err != nil || start < 0 {
		return parsedContentRange{}, false
	}
	end, err := strconv.ParseInt(strings.TrimSpace(bounds[1]), 10, 64)
	if err != nil || end < start {
		return parsedContentRange{}, false
	}
	parsed := parsedContentRange{Start: start, End: end}
	totalText := strings.TrimSpace(rangeAndTotal[1])
	if totalText != "*" {
		total, err := strconv.ParseInt(totalText, 10, 64)
		if err != nil || total <= 0 || end >= total {
			return parsedContentRange{}, false
		}
		parsed.Total = total
		parsed.TotalKnown = true
	}
	return parsed, true
}

func discardBytes(r io.Reader, n int64) error {
	if n <= 0 {
		return nil
	}
	if n > 4096 {
		buf := getBuffer()
		defer putBuffer(buf)
		written, err := io.CopyBuffer(io.Discard, io.LimitReader(r, n), *buf)
		if err != nil {
			return err
		}
		if written != n {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	written, err := io.CopyN(io.Discard, r, n)
	if written != n && (err == nil || err == io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

func isEmptyV3Meta(meta encryption.ContentMeta) bool {
	return meta.IsV3() && meta.PlainSize == 0 && meta.HeaderLen == encryption.V3HeaderSize &&
		len(meta.NonceField) == int(encryption.V3NonceFieldLen()) && meta.ChunkSize > 0 && meta.ChunkSize <= 1<<30 &&
		(meta.CiphertextSize == meta.HeaderLen || meta.CiphertextSize == meta.HeaderLen+16)
}

func normalizePlainFileSize(fileSize int64, meta *encryption.ContentMeta, contentRange string) int64 {
	if meta == nil {
		return fileSize
	}
	if meta.IsV3() {
		if isEmptyV3Meta(*meta) {
			return 0
		}
		// The wire size is the container (ciphertext) bytes. Remember it and
		// keep the authoritative plaintext size the metadata/cache agreed on.
		if fileSize > 0 && meta.PlainSize > 0 && fileSize != meta.PlainSize {
			meta.CiphertextSize = fileSize
		}
		if meta.PlainSize > 0 {
			return meta.PlainSize
		}
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
