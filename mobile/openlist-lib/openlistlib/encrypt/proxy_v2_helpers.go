package encrypt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const unsupportedV3Playback = "unsupported V3 encrypted content: mobile playback supports V1/V2 only"

func uploadMetaKey(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func cloneNonceField(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func (p *ProxyServer) getUploadMeta(target string) (ContentMeta, bool) {
	if p == nil {
		return ContentMeta{}, false
	}
	key := uploadMetaKey(target)
	p.uploadMetaMu.Lock()
	defer p.uploadMetaMu.Unlock()
	entry, ok := p.uploadMeta[key]
	if !ok {
		return ContentMeta{}, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(p.uploadMeta, key)
		return ContentMeta{}, false
	}
	return entry.Meta, true
}

func (p *ProxyServer) putUploadMeta(target string, meta ContentMeta) {
	if p == nil || !meta.IsV2() {
		return
	}
	key := uploadMetaKey(target)
	p.uploadMetaMu.Lock()
	defer p.uploadMetaMu.Unlock()
	p.uploadMeta[key] = uploadMetaEntry{
		Meta:      meta,
		ExpiresAt: time.Now().Add(time.Duration(uploadMetaTTLSeconds) * time.Second),
	}
}

func (p *ProxyServer) inspectEncryptedContent(ctx context.Context, target string, authHeaders http.Header, encPath *EncryptPath, ciphertextSize int64) ContentMeta {
	meta, _ := p.inspectEncryptedContentConfirmed(ctx, target, authHeaders, encPath, ciphertextSize)
	return meta
}

func (p *ProxyServer) inspectEncryptedContentConfirmed(ctx context.Context, target string, authHeaders http.Header, encPath *EncryptPath, ciphertextSize int64) (ContentMeta, bool) {
	encType := EncryptionType("")
	if encPath != nil {
		encType = EncryptionType(encPath.EncType)
	}
	meta := LegacyContentMeta(encType, ciphertextSize)
	if p == nil || encPath == nil || !encPath.Enable || strings.TrimSpace(target) == "" {
		log.Infof("[v2-inspect] skipped: p=%v encPath=%v enable=%v target=%q", p != nil, encPath != nil, encPath != nil && encPath.Enable, safeURLForLog(target))
		return meta, false
	}
	// 观测：一次 V2 元数据探测流程（Range 头请求）。无论成败都计数。
	atomic.AddUint64(&p.probeV2Attempts, 1)
	if ctx == nil {
		ctx = context.Background()
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Redirect-following loop (up to 2 hops), matching Docker's StreamProxy.inspectEncryptedContent.
	// When probing alist /dav/ or /d/ paths, alist returns 302 → CDN URL.
	// Without following the redirect, we get HTML (302 body) instead of the actual file bytes.
	const maxHops = 2
	client := p.streamClientSnapshot()
	if client == nil {
		return meta, false
	}
	probeClient := *client
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	client = &probeClient
	currentURL := target
	currentAuth := authHeaders
	if !isInternalAlistTarget(currentURL, p.getAlistURL()) {
		currentAuth = authHeaders.Clone()
		for _, key := range sensitivePlaybackHeaders {
			currentAuth.Del(key)
		}
	}
	for hop := 0; hop <= maxHops; hop++ {
		req, err := http.NewRequestWithContext(inspectCtx, http.MethodGet, currentURL, nil)
		if err != nil {
			log.Infof("[v2-inspect] request creation failed: err=%v", err)
			return meta, false
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", V3HeaderSize-1))
		req.Header.Set("Accept-Encoding", "identity")
		if currentAuth != nil {
			if auth := currentAuth.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
			if cookie := currentAuth.Get("Cookie"); cookie != "" {
				req.Header.Set("Cookie", cookie)
			}
		}
		if ua := authHeaders.Get("User-Agent"); ua != "" {
			req.Header.Set("User-Agent", ua)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Infof("[v2-inspect] upstream request failed: target=%s err=%v", safeURLForLog(currentURL), err)
			return meta, false
		}
		// Follow redirects (301/302/307/308) — drop auth after first hop (CDN doesn't need alist auth)
		if hop < maxHops && (resp.StatusCode == http.StatusMovedPermanently ||
			resp.StatusCode == http.StatusFound ||
			resp.StatusCode == http.StatusTemporaryRedirect ||
			resp.StatusCode == http.StatusPermanentRedirect) {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			resp.Body.Close()
			if location == "" {
				log.Infof("[v2-inspect] redirect with empty location: target=%s status=%d", safeURLForLog(currentURL), resp.StatusCode)
				return meta, false
			}
			if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
				// Relative redirect — resolve against current URL
				base, pErr := url.Parse(currentURL)
				if pErr == nil {
					ref, rErr := url.Parse(location)
					if rErr == nil {
						currentURL = base.ResolveReference(ref).String()
					} else {
						currentURL = location
					}
				} else {
					currentURL = location
				}
			} else {
				currentURL = location
			}
			// Drop auth headers after redirect — CDN URLs don't need alist auth
			currentAuth = nil
			log.Debugf("[v2-inspect] following redirect hop=%d target=%s", hop+1, safeURLForLog(currentURL))
			continue
		}
		if resp.StatusCode >= http.StatusBadRequest {
			resp.Body.Close()
			// Use Debugf for error statuses — 401/403 on internal probe paths (like /d/) is expected
			// when the proxy lacks alist auth credentials. These are not actionable errors.
			log.Debugf("[v2-inspect] upstream returned error status: target=%s status=%d", safeURLForLog(currentURL), resp.StatusCode)
			return meta, false
		}
		// A 200 ignores Range: consume only the header and close immediately.
		// A 206 gets one extra byte to detect an overlong tiny range response.
		readLimit := int64(V3HeaderSize)
		if resp.StatusCode == http.StatusPartialContent {
			readLimit++
		}
		prefix, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
		resp.Body.Close()
		interval, rangeOK := parseContentRange(resp.Header.Get("Content-Range"))
		if rangeOK && interval.TotalKnown {
			meta.CiphertextSize = interval.Total
		} else if resp.StatusCode == http.StatusOK {
			meta.CiphertextSize = resp.ContentLength
		} else {
			meta.CiphertextSize = 0
		}
		meta.PlainSize = meta.CiphertextSize
		validResponse := inspectHeaderResponseValid(resp, interval, rangeOK, int64(len(prefix)))
		if len(prefix) >= 6 && string(prefix[:6]) == "V3GCM3" {
			// The bool means recognized here, even on failure: returning false
			// would let URL fallback reinterpret a damaged V3 object as legacy.
			invalid := ContentMeta{EncType: normalizeContentEncType(encType), Version: ContentVersionV3, CiphertextSize: meta.CiphertextSize}
			if err != nil || !validResponse {
				return invalid, true
			}
			parsed, recognized, parseErr := ParseV3ContentHeader(encType, prefix, meta.CiphertextSize)
			if errors.Is(parseErr, ErrV3ResourceLimit) {
				// Preserve bounded parameters so the route can report the typed
				// local resource error without attempting KDF or provider learning.
				return parsed, true
			}
			if !recognized || parseErr != nil {
				return invalid, true
			}
			if parsed.PlainSize == 0 && parsed.CiphertextSize > V3HeaderSize {
				trailer, tailErr := inspectV3Trailer(inspectCtx, client, currentURL, currentAuth, authHeaders.Get("User-Agent"), prefix, parsed.CiphertextSize)
				if tailErr != nil {
					return invalid, true
				}
				parsed, parseErr = CompleteV3ContentMeta(parsed, trailer)
			}
			if parseErr != nil || ValidateV3ContentMeta(parsed) != nil {
				return invalid, true
			}
			atomic.AddUint64(&p.probeV2Success, 1)
			return parsed, true
		}
		if !validResponse {
			return meta, false
		}
		if err != nil {
			log.Infof("[v2-inspect] failed to read prefix bytes: target=%s err=%v", safeURLForLog(currentURL), err)
			return meta, false
		}
		expectedPrefix := ContentHeaderSize()
		if meta.CiphertextSize > 0 && meta.CiphertextSize < expectedPrefix {
			expectedPrefix = meta.CiphertextSize
		}
		if expectedPrefix <= 0 || int64(len(prefix)) < expectedPrefix {
			log.Infof("[v2-inspect] incomplete prefix: target=%s prefixLen=%d expected=%d status=%d contentRange=%q",
				safeURLForLog(currentURL), len(prefix), expectedPrefix, resp.StatusCode, resp.Header.Get("Content-Range"))
			return meta, false
		}
		if parsed, ok, err := ParseContentHeader(encType, prefix, meta.CiphertextSize); err == nil && ok {
			log.Infof("[v2] detected content header target=%s encType=%s headerLen=%d cipherSize=%d plainSize=%d",
				safeURLForLog(currentURL), parsed.EncType, parsed.HeaderLen, parsed.CiphertextSize, parsed.PlainSize)
			atomic.AddUint64(&p.probeV2Success, 1)
			return parsed, true
		} else {
			log.Infof("[v2-inspect] header not detected: target=%s encType=%q prefixLen=%d status=%d contentRange=%q ok=%v parseErr=%v first6=%x",
				safeURLForLog(currentURL), encType, len(prefix), resp.StatusCode, resp.Header.Get("Content-Range"), ok, err, prefix[:min(len(prefix), 6)])
			if err != nil {
				return meta, false
			}
		}
		atomic.AddUint64(&p.probeV2Success, 1)
		return meta, true
	}
	return meta, false
}

// inspectHeaderResponseValid validates the representation before any format is
// confirmed. Unknown totals and encoded bodies cannot establish container geometry.
func inspectHeaderResponseValid(resp *http.Response, interval parsedContentRange, rangeOK bool, bytesRead int64) bool {
	if encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return false
	}
	if resp.Uncompressed {
		return false
	}
	switch resp.StatusCode {
	case http.StatusPartialContent:
		if !rangeOK || !interval.TotalKnown || interval.Start != 0 || interval.End != min(int64(V3HeaderSize)-1, interval.Total-1) {
			return false
		}
		expected := interval.End + 1
		return bytesRead == expected && (resp.ContentLength < 0 || resp.ContentLength == expected)
	case http.StatusOK:
		total := resp.ContentLength
		if rangeOK && interval.TotalKnown {
			total = interval.Total
		}
		return total > 0 && bytesRead == min(int64(V3HeaderSize), total)
	default:
		return false
	}
}

const v3InspectSpoolMaxBytes int64 = 8 << 20

func inspectV3Trailer(ctx context.Context, client *http.Client, target string, auth http.Header, userAgent string, header []byte, size int64) ([]byte, error) {
	if size < V3HeaderSize+V3TrailerSize {
		return nil, fmt.Errorf("v3 inspect: truncated streaming container")
	}
	// Follow-ups use exactly the final header URL and final credentials. Do not
	// allow the client to auto-follow another redirect with origin credentials.
	followupClient := *client
	followupClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request := func(rangeValue string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept-Encoding", "identity")
		if rangeValue != "" {
			req.Header.Set("Range", rangeValue)
		}
		for _, key := range []string{"Authorization", "Cookie"} {
			if value := auth.Get(key); value != "" {
				req.Header.Set(key, value)
			}
		}
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		return followupClient.Do(req)
	}
	identity := func(resp *http.Response) bool {
		encoding := strings.TrimSpace(resp.Header.Get("Content-Encoding"))
		return !resp.Uncompressed && (encoding == "" || strings.EqualFold(encoding, "identity"))
	}
	resp, err := request(fmt.Sprintf("bytes=%d-%d", size-V3TrailerSize, size-1))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusPartialContent {
		defer resp.Body.Close()
		interval, ok := parseContentRange(resp.Header.Get("Content-Range"))
		if !identity(resp) || !ok || !interval.TotalKnown || interval.Total != size || interval.Start != size-V3TrailerSize || interval.End != size-1 || (resp.ContentLength >= 0 && resp.ContentLength != V3TrailerSize) {
			return nil, fmt.Errorf("v3 inspect: invalid trailer range")
		}
		tail, err := io.ReadAll(io.LimitReader(resp.Body, V3TrailerSize+1))
		if err != nil || int64(len(tail)) != V3TrailerSize {
			return nil, fmt.Errorf("v3 inspect: incomplete or overlong trailer: %w", err)
		}
		return tail, nil
	}
	refused := identity(resp) && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusRequestedRangeNotSatisfiable)
	resp.Body.Close()
	if !refused || size > v3InspectSpoolMaxBytes {
		return nil, fmt.Errorf("v3 inspect: trailer range refused or spool budget exceeded")
	}
	// A 200 trailer response starts at zero, never at the requested offset.
	// Reopen the entire small representation under an explicit total budget.
	resp, err = request("")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !identity(resp) || (resp.ContentLength >= 0 && resp.ContentLength != size) {
		return nil, fmt.Errorf("v3 inspect: invalid full-container response")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, size+1))
	if err != nil || int64(len(body)) != size || len(header) != V3HeaderSize || string(body[:min(len(body), V3HeaderSize)]) != string(header) {
		return nil, fmt.Errorf("v3 inspect: full-container length or identity changed")
	}
	return append([]byte(nil), body[len(body)-V3TrailerSize:]...), nil
}

func (p *ProxyServer) inspectEncryptedContentWithFallbackConfirmed(
	ctx context.Context,
	target string,
	authHeaders http.Header,
	encPath *EncryptPath,
	ciphertextSize int64,
	encryptedPath string,
) (ContentMeta, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Candidate URLs share the same metadata deadline; fallback must not
	// multiply the per-inspection budget by the number of alternate routes.
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	meta, confirmed := p.inspectEncryptedContentConfirmed(ctx, target, authHeaders, encPath, ciphertextSize)
	if confirmed {
		return meta, true
	}
	if p == nil || encPath == nil || strings.TrimSpace(encryptedPath) == "" {
		return meta, false
	}
	// Defensive: strip any leading /dav or /d prefix so candidates don't double up
	if strings.HasPrefix(encryptedPath, "/dav") {
		encryptedPath = strings.TrimPrefix(encryptedPath, "/dav")
	} else if strings.HasPrefix(encryptedPath, "/d") {
		encryptedPath = strings.TrimPrefix(encryptedPath, "/d")
	}
	if encryptedPath == "" {
		return meta, false
	}
	alistURL := strings.TrimSpace(p.getAlistURL())
	if alistURL == "" {
		return meta, false
	}
	candidates := []string{
		alistURL + "/dav" + encryptedPath,
		alistURL + "/d" + encryptedPath,
	}
	seen := map[string]struct{}{}
	if trimmed := strings.TrimSpace(target); trimmed != "" {
		seen[trimmed] = struct{}{}
	}
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		fallback, fallbackConfirmed := p.inspectEncryptedContentConfirmed(ctx, candidate, authHeaders, encPath, ciphertextSize)
		if fallbackConfirmed {
			if fallback.IsV2() && fallback.PlainSize > 0 {
				log.Infof("[v2] detected content header via fallback target=%s encType=%s headerLen=%d cipherSize=%d plainSize=%d",
					safeURLForLog(candidate), fallback.EncType, fallback.HeaderLen, fallback.CiphertextSize, fallback.PlainSize)
			}
			return fallback, true
		}
	}
	return meta, false
}

func (p *ProxyServer) inspectEncryptedContentWithFallback(ctx context.Context, target string, authHeaders http.Header, encPath *EncryptPath, ciphertextSize int64, encryptedPath string) ContentMeta {
	meta, _ := p.inspectEncryptedContentWithFallbackConfirmed(ctx, target, authHeaders, encPath, ciphertextSize, encryptedPath)
	return meta
}

func parseUploadStartOffset(contentRange string) int64 {
	contentRange = strings.TrimSpace(contentRange)
	if contentRange == "" {
		return 0
	}
	if !strings.HasPrefix(strings.ToLower(contentRange), "bytes ") {
		return 0
	}
	spec := strings.TrimSpace(contentRange[len("bytes "):])
	slash := strings.Index(spec, "/")
	if slash <= 0 {
		return 0
	}
	rangePart := strings.TrimSpace(spec[:slash])
	parts := strings.SplitN(rangePart, "-", 2)
	if len(parts) != 2 {
		return 0
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 {
		return 0
	}
	return start
}
