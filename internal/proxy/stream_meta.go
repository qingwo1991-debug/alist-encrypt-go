package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/httputil"
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
		prefix, err := io.ReadAll(io.LimitReader(resp.Body, encryption.ContentHeaderSize()))
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
		expectedPrefix := encryption.ContentHeaderSize()
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
		parsed, ok, err := encryption.ParseContentHeader(encType, prefix, meta.CiphertextSize)
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
