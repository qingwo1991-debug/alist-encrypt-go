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
	encType := encryption.EncType(passwdInfo.EncType)
	meta := encryption.LegacyContentMeta(encType, ciphertextSize)
	if s == nil || passwdInfo == nil || !passwdInfo.Enable || strings.TrimSpace(targetURL) == "" {
		return meta
	}
	if ctx == nil {
		ctx = context.Background()
	}
	currentURL := strings.TrimSpace(targetURL)
	currentAuth := authHeaders
	maxHops := 2
	if s.cfg != nil && s.cfg.AlistServer.RedirectMaxHops > 0 {
		maxHops = s.cfg.AlistServer.RedirectMaxHops
	}
	for hop := 0; hop <= maxHops; hop++ {
		req, err := httputil.NewRequest(http.MethodGet, currentURL).
			WithContext(ctx).
			Build()
		if err != nil {
			return meta
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", encryption.ContentHeaderSize()-1))
		req.Header.Set("Accept-Encoding", "identity")
		copyProbeAuthHeaders(req, currentAuth)

		resp, err := s.client.Do(req)
		if err != nil {
			return meta
		}
		if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			resp.Body.Close()
			if location == "" {
				return meta
			}
			nextURL, err := resolveRedirectTarget(currentURL, location)
			if err != nil {
				return meta
			}
			currentURL = nextURL
			currentAuth = make(http.Header)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= http.StatusBadRequest {
			return meta
		}
		prefix, err := io.ReadAll(io.LimitReader(resp.Body, encryption.ContentHeaderSize()))
		if err != nil {
			return meta
		}
		if total := parseContentRangeTotal(resp.Header.Get("Content-Range")); total > 0 {
			meta.CiphertextSize = total
			meta.PlainSize = total
		} else if cl := resp.Header.Get("Content-Length"); cl != "" {
			if total, err := strconv.ParseInt(cl, 10, 64); err == nil && total > 0 && resp.StatusCode == http.StatusOK {
				meta.CiphertextSize = total
				meta.PlainSize = total
			}
		}
		if parsed, ok, err := encryption.ParseContentHeader(encType, prefix, meta.CiphertextSize); err == nil && ok {
			return parsed
		}
		return meta
	}
	return meta
}

func (s *StreamProxy) InspectEncryptedContent(ctx context.Context, targetURL string, authHeaders http.Header, passwdInfo *config.PasswdInfo, ciphertextSize int64) encryption.ContentMeta {
	return s.inspectEncryptedContent(ctx, targetURL, authHeaders, passwdInfo, ciphertextSize)
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

func uploadMetaKey(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func (s *StreamProxy) getUploadMeta(targetURL string) (encryption.ContentMeta, bool) {
	if s == nil {
		return encryption.ContentMeta{}, false
	}
	key := uploadMetaKey(targetURL)
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
	return entry.Meta, true
}

func (s *StreamProxy) putUploadMeta(targetURL string, meta encryption.ContentMeta) {
	if s == nil || !meta.IsV2() {
		return
	}
	key := uploadMetaKey(targetURL)
	s.uploadMetaMu.Lock()
	defer s.uploadMetaMu.Unlock()
	s.uploadMeta[key] = uploadMetaEntry{
		Meta:      meta,
		ExpiresAt: time.Now().Add(uploadMetaTTL),
	}
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
	if n > 4096 {
		buf := getBuffer()
		defer putBuffer(buf)
		_, err := io.CopyBuffer(io.Discard, io.LimitReader(r, n), *buf)
		return err
	}
	_, err := io.CopyN(io.Discard, r, n)
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
