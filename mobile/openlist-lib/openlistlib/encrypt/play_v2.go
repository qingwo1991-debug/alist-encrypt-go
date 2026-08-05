package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type PlayOrchestrator struct {
	proxy *ProxyServer
}

func newPlayOrchestrator(p *ProxyServer) *PlayOrchestrator {
	return &PlayOrchestrator{proxy: p}
}

func (p *ProxyServer) streamEngineVersion() int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.config == nil || p.config.StreamEngineVersion <= 0 {
		return defaultStreamEngineVersion
	}
	return p.config.StreamEngineVersion
}

func (p *ProxyServer) streamEngineV2Enabled() bool {
	return p.streamEngineVersion() >= 2
}

func remapRequestPath(r *http.Request, fromPrefix, toPrefix string) *http.Request {
	if r == nil || r.URL == nil {
		return r
	}
	if !strings.HasPrefix(r.URL.Path, fromPrefix) {
		return r
	}
	cloned := r.Clone(r.Context())
	clonedURL := *r.URL
	clonedURL.Path = toPrefix + strings.TrimPrefix(r.URL.Path, fromPrefix)
	if r.URL.RawPath != "" && strings.HasPrefix(r.URL.RawPath, fromPrefix) {
		clonedURL.RawPath = toPrefix + strings.TrimPrefix(r.URL.RawPath, fromPrefix)
	}
	cloned.URL = &clonedURL
	return cloned
}

func cloneHeader(dst http.Header, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

var (
	privateOriginHeaders     = []string{"Authorization", "Cookie"}
	sensitivePlaybackHeaders = []string{"Authorization", "Cookie", "Proxy-Authorization"}
)

func headersWithStoredOriginCredentials(base, stored http.Header) http.Header {
	headers := make(http.Header)
	cloneHeader(headers, base)
	headers.Del("Proxy-Authorization")
	for _, key := range privateOriginHeaders {
		values := stored.Values(key)
		if len(values) == 0 {
			continue
		}
		headers.Del(key)
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	return headers
}

// copyPlaybackStreamHeaders copies ordinary client headers while keeping
// OpenList credentials on the local origin. Signed CDN URLs are bearer
// capabilities and must never receive local cookies or authorization headers.
func copyPlaybackStreamHeaders(dst, clientHeaders, storedHeaders http.Header, target, alistURL string) {
	for key, values := range clientHeaders {
		switch strings.ToLower(key) {
		case "host", "referer", "authorization", "cookie", "proxy-authorization":
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	if !isInternalAlistTarget(target, alistURL) {
		return
	}
	for _, key := range privateOriginHeaders {
		values := storedHeaders.Values(key)
		if len(values) == 0 {
			values = clientHeaders.Values(key)
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// applyPlaybackOriginCredentials removes every credential-like header first,
// then restores only OpenList origin credentials for the configured internal
// origin. Proxy-Authorization is hop-by-hop and is never forwarded.
func applyPlaybackOriginCredentials(dst, originHeaders http.Header, target, alistURL string) {
	if dst == nil {
		return
	}
	internalTarget := isInternalAlistTarget(target, alistURL)
	originValues := make(map[string][]string, len(privateOriginHeaders))
	if internalTarget {
		for _, key := range privateOriginHeaders {
			originValues[key] = append([]string(nil), originHeaders.Values(key)...)
		}
	}
	for _, key := range sensitivePlaybackHeaders {
		dst.Del(key)
	}
	if !internalTarget {
		return
	}
	for _, key := range privateOriginHeaders {
		for _, value := range originValues[key] {
			dst.Add(key, value)
		}
	}
}

const (
	firstFrameWindowBytes     int64 = 2 * 1024 * 1024
	firstFrameStartSlackBytes int64 = 1024
)

// isFirstFrameRangeHint deliberately mirrors the server playback policy:
// signed provider URLs are only a fast path for small reads at the beginning
// of a file. Full GETs and ordinary seeks stay on OpenList's stable /dav path.
func isFirstFrameRangeHint(method, rangeHeader string) bool {
	if method != http.MethodGet {
		return false
	}
	rangeHeader = strings.TrimSpace(rangeHeader)
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return false
	}
	rangeSpec := strings.TrimSpace(strings.TrimPrefix(rangeHeader, "bytes="))
	if rangeSpec == "" || strings.Contains(rangeSpec, ",") {
		return false
	}
	parts := strings.SplitN(rangeSpec, "-", 2)
	if len(parts) != 2 {
		return false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	if err != nil || start < 0 || start > firstFrameStartSlackBytes {
		return false
	}
	endText := strings.TrimSpace(parts[1])
	if endText == "" {
		return true
	}
	end, err := strconv.ParseInt(endText, 10, 64)
	if err != nil || end < start {
		return false
	}
	return end-start+1 <= firstFrameWindowBytes
}

func isOpenEndedByteRange(rangeHeader string) bool {
	rangeHeader = strings.TrimSpace(rangeHeader)
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return false
	}
	rangeSpec := strings.TrimSpace(strings.TrimPrefix(rangeHeader, "bytes="))
	if rangeSpec == "" || strings.Contains(rangeSpec, ",") {
		return false
	}
	parts := strings.SplitN(rangeSpec, "-", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) != "" {
		return false
	}
	start, err := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	return err == nil && start >= 0
}

func encryptedDAVPath(encryptedPath string) string {
	encryptedPath = strings.TrimSpace(encryptedPath)
	if encryptedPath == "" {
		return ""
	}
	if parsed, err := url.Parse(encryptedPath); err == nil && parsed.IsAbs() {
		encryptedPath = parsed.Path
	}
	if decoded, err := url.PathUnescape(encryptedPath); err == nil {
		encryptedPath = decoded
	}
	if !strings.HasPrefix(encryptedPath, "/") {
		encryptedPath = "/" + encryptedPath
	}
	switch {
	case encryptedPath == "/dav" || strings.HasPrefix(encryptedPath, "/dav/"):
		return encryptedPath
	case encryptedPath == "/dav2":
		return "/dav"
	case strings.HasPrefix(encryptedPath, "/dav2/"):
		return "/dav/" + strings.TrimPrefix(encryptedPath, "/dav2/")
	case encryptedPath == "/d" || encryptedPath == "/p":
		return "/dav"
	case strings.HasPrefix(encryptedPath, "/d/"):
		return "/dav/" + strings.TrimPrefix(encryptedPath, "/d/")
	case strings.HasPrefix(encryptedPath, "/p/"):
		return "/dav/" + strings.TrimPrefix(encryptedPath, "/p/")
	default:
		return "/dav" + encryptedPath
	}
}

func (p *ProxyServer) encryptedDAVTargetURL(encryptedPath, rawQuery string) string {
	if p == nil {
		return ""
	}
	davPath := encryptedDAVPath(encryptedPath)
	if davPath == "" {
		return ""
	}
	target := strings.TrimRight(p.getAlistURL(), "/") + davPath
	if strings.TrimSpace(rawQuery) != "" {
		target += "?" + strings.TrimPrefix(rawQuery, "?")
	}
	return target
}

func redirectOriginalRawQuery(info *RedirectInfo) string {
	if info == nil {
		return ""
	}
	for _, candidate := range []string{info.OriginalURL, info.EncryptedPath} {
		parsed, err := url.Parse(strings.TrimSpace(candidate))
		if err == nil && parsed.RawQuery != "" {
			return parsed.RawQuery
		}
	}
	return ""
}

func isInternalAlistTarget(target, alistURL string) bool {
	targetURL, targetErr := url.Parse(strings.TrimSpace(target))
	alistTarget, alistErr := url.Parse(strings.TrimSpace(alistURL))
	if targetErr != nil || alistErr != nil || targetURL.Host == "" || alistTarget.Host == "" {
		return false
	}
	return strings.EqualFold(targetURL.Scheme, alistTarget.Scheme) &&
		strings.EqualFold(targetURL.Host, alistTarget.Host)
}

func isExpiredSignedURLStatus(status int) bool {
	return status == http.StatusUnauthorized ||
		status == http.StatusForbidden ||
		status == http.StatusNotFound
}

func rewriteRawURLForV2(body []byte, host, scheme string) []byte {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return body
	}
	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		return body
	}
	rawURL, _ := data["raw_url"].(string)
	if strings.TrimSpace(rawURL) == "" {
		return body
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return body
	}
	pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(pathParts) < 2 || pathParts[0] != "redirect" || strings.TrimSpace(pathParts[1]) == "" {
		return body
	}
	token := pathParts[1]
	data["play_token"] = token
	playURL := fmt.Sprintf("%s://%s/api/play/stream/%s", scheme, host, token)
	if parsed.RawQuery != "" {
		playURL += "?" + parsed.RawQuery
	}
	data["raw_url"] = playURL
	data["stream_engine"] = "v2"
	payload["data"] = data
	out, err := json.Marshal(payload)
	if err != nil {
		return body
	}
	return out
}

func (o *PlayOrchestrator) resolveViaFsGet(ctx context.Context, host, scheme string, srcHeaders http.Header, body []byte) (int, []byte) {
	if o == nil || o.proxy == nil {
		return http.StatusInternalServerError, []byte(`{"code":500,"message":"play orchestrator unavailable"}`)
	}
	targetURL := fmt.Sprintf("%s://%s/api/fs/get", scheme, host)
	req := httptest.NewRequest(http.MethodPost, targetURL, bytes.NewReader(body)).WithContext(ctx)
	cloneHeader(req.Header, srcHeaders)
	req.Header.Del("Proxy-Authorization")
	rec := httptest.NewRecorder()
	o.proxy.handleFsGet(rec, req)
	respBody := rewriteRawURLForV2(rec.Body.Bytes(), host, scheme)
	return rec.Code, respBody
}

func (p *ProxyServer) resolveRawURLViaFsGet(ctx context.Context, srcHeaders http.Header, displayPath string) (string, int64) {
	if p == nil || strings.TrimSpace(displayPath) == "" {
		return "", 0
	}
	body, _ := json.Marshal(map[string]string{"path": displayPath})
	req := httptest.NewRequest(http.MethodPost, "http://proxy.local/api/fs/get", bytes.NewReader(body)).WithContext(ctx)
	cloneHeader(req.Header, srcHeaders)
	req.Header.Del("Proxy-Authorization")
	rec := httptest.NewRecorder()
	p.handleFsGet(rec, req)
	if cached, ok := p.loadFileCache(displayPath); ok && cached != nil {
		if rawURL := strings.TrimSpace(cached.RawURL); rawURL != "" {
			return rawURL, cached.Size
		}
	}
	return "", 0
}

// resolveEncryptedRawURLViaFsGet bypasses the display-path fallback machinery.
// The request body contains only the already encrypted object path, so a stale
// signed URL can never cause a retry against a plaintext filename.
func (p *ProxyServer) resolveEncryptedRawURLViaFsGet(ctx context.Context, srcHeaders http.Header, encryptedPath string) (string, int64) {
	if p == nil {
		return "", 0
	}
	apiPath := encryptedDAVPath(encryptedPath)
	apiPath = strings.TrimPrefix(apiPath, "/dav")
	if apiPath == "" {
		apiPath = "/"
	}
	body, err := json.Marshal(map[string]string{"path": apiPath})
	if err != nil {
		return "", 0
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.getAlistURL(), "/")+"/api/fs/get", bytes.NewReader(body))
	if err != nil {
		return "", 0
	}
	cloneHeader(req.Header, srcHeaders)
	req.Header.Del("Host")
	req.Header.Del("Range")
	req.Header.Del("Content-Length")
	req.Header.Del("Proxy-Authorization")
	req.Header.Set("Content-Type", "application/json")
	client := p.httpClientSnapshot()
	if client == nil {
		return "", 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", 0
	}
	respBody, err := readLimitedBody(resp.Body, maxBufferedJSONBody)
	if err != nil {
		return "", 0
	}
	var payload struct {
		Code int `json:"code"`
		Data struct {
			RawURL string  `json:"raw_url"`
			Size   float64 `json:"size"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil || (payload.Code != 0 && payload.Code != http.StatusOK) {
		return "", 0
	}
	rawURL := strings.TrimSpace(payload.Data.RawURL)
	if rawURL == "" {
		return "", 0
	}
	size := int64(payload.Data.Size)
	if size < 0 {
		size = 0
	}
	return rawURL, size
}

func (o *PlayOrchestrator) streamViaRedirect(ctx context.Context, w http.ResponseWriter, srcReq *http.Request, token string) {
	if o == nil || o.proxy == nil {
		http.Error(w, "play orchestrator unavailable", http.StatusInternalServerError)
		return
	}
	host := srcReq.Host
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	redirectURL := fmt.Sprintf("http://%s/redirect/%s", host, token)
	if srcReq.URL != nil && srcReq.URL.RawQuery != "" {
		redirectURL += "?" + srcReq.URL.RawQuery
	}
	req := httptest.NewRequest(srcReq.Method, redirectURL, srcReq.Body).WithContext(ctx)
	cloneHeader(req.Header, srcReq.Header)
	o.ServeRedirect(w, req)
}

func (o *PlayOrchestrator) ServePlayback(w http.ResponseWriter, r *http.Request) {
	if o == nil || o.proxy == nil {
		http.Error(w, "play orchestrator unavailable", http.StatusInternalServerError)
		return
	}
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	switch {
	case strings.HasPrefix(path, "/redirect/"):
		o.ServeRedirect(w, r)
	case strings.HasPrefix(path, "/dav2/") || path == "/dav2":
		o.proxy.handleWebDAVLegacy(w, remapRequestPath(r, "/dav2", "/dav"))
	case strings.HasPrefix(path, "/dav/") || path == "/dav":
		o.proxy.handleWebDAVLegacy(w, r)
	case strings.HasPrefix(path, "/d/") || strings.HasPrefix(path, "/p/"):
		o.proxy.handleDownloadLegacy(w, r)
	default:
		http.Error(w, "unsupported playback route", http.StatusNotFound)
	}
}

func parseSingleRange(header string, size int64) (start, end int64, hasRange bool, err error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, 0, false, nil
	}
	if size <= 0 || !strings.HasPrefix(header, "bytes=") {
		return 0, 0, false, fmt.Errorf("invalid byte range %q", header)
	}

	spec := strings.TrimSpace(strings.TrimPrefix(header, "bytes="))
	if spec == "" || strings.Contains(spec, ",") {
		return 0, 0, false, fmt.Errorf("multiple or empty byte ranges are not supported")
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 || strings.IndexByte(spec[dash+1:], '-') >= 0 {
		return 0, 0, false, fmt.Errorf("invalid byte range %q", header)
	}
	startText := strings.TrimSpace(spec[:dash])
	endText := strings.TrimSpace(spec[dash+1:])

	parseDecimal := func(value string) (int64, error) {
		if value == "" {
			return 0, fmt.Errorf("empty range value")
		}
		for _, ch := range value {
			if ch < '0' || ch > '9' {
				return 0, fmt.Errorf("invalid range value %q", value)
			}
		}
		parsed, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return 0, parseErr
		}
		return parsed, nil
	}

	if startText == "" {
		suffixLength, parseErr := parseDecimal(endText)
		if parseErr != nil || suffixLength <= 0 {
			return 0, 0, false, fmt.Errorf("invalid suffix byte range %q", header)
		}
		if suffixLength >= size {
			return 0, size - 1, true, nil
		}
		return size - suffixLength, size - 1, true, nil
	}

	start, err = parseDecimal(startText)
	if err != nil || start >= size {
		return 0, 0, false, fmt.Errorf("byte range %q does not overlap representation", header)
	}
	if endText == "" {
		return start, size - 1, true, nil
	}
	end, err = parseDecimal(endText)
	if err != nil || start > end {
		return 0, 0, false, fmt.Errorf("invalid byte range %q", header)
	}
	if end >= size {
		end = size - 1
	}
	return start, end, true, nil
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

// parseRange is retained for legacy call sites. Playback V2 uses
// parseSingleRange directly so malformed or unsupported ranges can produce a
// proper 416 instead of being mistaken for a request for the full file.
func parseRange(header string, size int64) (start, end int64, hasRange bool) {
	start, end, hasRange, err := parseSingleRange(header, size)
	if err != nil {
		return 0, 0, false
	}
	return start, end, hasRange
}

func writeRangeNotSatisfiable(w http.ResponseWriter, size int64) {
	if size < 0 {
		size = 0
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
	w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
}

func shouldDecryptRedirect(r *http.Request, info *RedirectInfo) bool {
	if info == nil || info.PasswdInfo == nil || !info.PasswdInfo.Enable {
		return false
	}
	return r == nil || r.URL == nil || r.URL.Query().Get("decode") != "0"
}

func redirectRawFileSize(info *RedirectInfo, fallback int64) int64 {
	if info == nil || info.ContentVersion != ContentVersionV2 {
		return fallback
	}
	if info.CiphertextSize > 0 {
		return info.CiphertextSize
	}
	if info.FileSize > 0 && info.HeaderLen > 0 && info.FileSize <= (1<<63-1)-info.HeaderLen {
		return info.FileSize + info.HeaderLen
	}
	return fallback
}

func appendUniquePathVariant(out []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return out
	}
	if u, err := url.Parse(value); err == nil && u.Path != "" && (u.Scheme != "" || strings.HasPrefix(value, "/")) {
		value = u.Path
	}
	if decoded, err := url.PathUnescape(value); err == nil {
		value = decoded
	}
	if value == "" {
		return out
	}
	candidates := []string{value}
	if strings.HasPrefix(value, "/dav/") {
		candidates = append(candidates, strings.TrimPrefix(value, "/dav"))
	} else if strings.HasPrefix(value, "dav/") {
		candidates = append(candidates, "/"+strings.TrimPrefix(value, "dav/"))
	} else if strings.HasPrefix(value, "/") {
		candidates = append(candidates, "/dav"+value)
	} else {
		candidates = append(candidates, "/"+value, "/dav/"+value)
	}
	for _, candidate := range candidates {
		candidate = normalizeCacheKey(candidate)
		if candidate == "" {
			continue
		}
		seen := false
		for _, existing := range out {
			if existing == candidate {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, candidate)
		}
	}
	return out
}

func playbackCachePathVariants(info *RedirectInfo) []string {
	var variants []string
	if info == nil {
		return variants
	}
	variants = appendUniquePathVariant(variants, info.OriginalURL)
	variants = appendUniquePathVariant(variants, info.EncryptedPath)
	return variants
}

func fileInfoContentMeta(cached *FileInfo, encType EncryptionType) (ContentMeta, bool) {
	if cached == nil || cached.ContentVersion != ContentVersionV2 || len(cached.NonceField) != 16 {
		return ContentMeta{}, false
	}
	cipherSize := cached.CiphertextSize
	if cipherSize <= 0 && cached.Size > 0 && cached.HeaderLen > 0 {
		cipherSize = cached.Size + cached.HeaderLen
	}
	return ContentMeta{
		EncType:        encType,
		Version:        ContentVersionV2,
		HeaderLen:      cached.HeaderLen,
		PlainSize:      cached.Size,
		CiphertextSize: cipherSize,
		NonceField:     cloneNonceField(cached.NonceField),
	}, true
}

// playbackFileInfoContentMeta accepts a cached V1 conclusion only when it is
// tied to the exact raw URL being played. A path-only V1 cache may be stale
// after a file is replaced by V2 content, while a same-URL conclusion safely
// eliminates the repeated 32-byte format probe on every seek.
func playbackFileInfoContentMeta(cached *FileInfo, encType EncryptionType, redirectURL string) (ContentMeta, bool) {
	if meta, ok := fileInfoContentMeta(cached, encType); ok {
		return meta, true
	}
	if cached == nil || cached.ContentVersion != ContentVersionV1 || cached.Size <= 0 {
		return ContentMeta{}, false
	}
	if strings.TrimSpace(cached.RawURL) == "" || strings.TrimSpace(cached.RawURL) != strings.TrimSpace(redirectURL) {
		return ContentMeta{}, false
	}
	cipherSize := cached.CiphertextSize
	if cipherSize <= 0 {
		cipherSize = cached.Size
	}
	return LegacyContentMeta(encType, cipherSize), true
}

func redirectInfoContentMeta(info *RedirectInfo) (ContentMeta, bool) {
	if info == nil || info.PasswdInfo == nil {
		return ContentMeta{}, false
	}
	encType := EncryptionType(info.PasswdInfo.EncType)
	switch info.ContentVersion {
	case ContentVersionV1:
		size := info.CiphertextSize
		if size <= 0 {
			size = info.FileSize
		}
		if size <= 0 {
			return ContentMeta{}, false
		}
		return LegacyContentMeta(encType, size), true
	case ContentVersionV2:
		if len(info.NonceField) != 16 || info.HeaderLen <= 0 {
			return ContentMeta{}, false
		}
		cipherSize := info.CiphertextSize
		plainSize := info.FileSize
		if cipherSize <= 0 && plainSize > 0 {
			cipherSize = plainSize + info.HeaderLen
		}
		if plainSize <= 0 && cipherSize > info.HeaderLen {
			plainSize = cipherSize - info.HeaderLen
		}
		if plainSize <= 0 || cipherSize <= 0 {
			return ContentMeta{}, false
		}
		return ContentMeta{
			EncType:        encType,
			Version:        ContentVersionV2,
			HeaderLen:      info.HeaderLen,
			PlainSize:      plainSize,
			CiphertextSize: cipherSize,
			NonceField:     cloneNonceField(info.NonceField),
		}, true
	default:
		return ContentMeta{}, false
	}
}

func cloneRedirectInfo(info *RedirectInfo) *RedirectInfo {
	if info == nil {
		return nil
	}
	cloned := *info
	cloned.NonceField = cloneNonceField(info.NonceField)
	cloned.Headers = info.Headers.Clone()
	if info.PasswdInfo != nil {
		passwd := *info.PasswdInfo
		cloned.PasswdInfo = &passwd
	}
	return &cloned
}

func redirectDisplayPath(info *RedirectInfo) string {
	if info == nil {
		return ""
	}
	displayPath := strings.TrimSpace(info.OriginalURL)
	if parsed, err := url.Parse(displayPath); err == nil && parsed.Path != "" {
		displayPath = parsed.Path
	}
	for _, prefix := range []string{"/dav/", "/dav2/", "/d/", "/p/"} {
		if strings.HasPrefix(displayPath, prefix) {
			displayPath = "/" + strings.TrimPrefix(displayPath, prefix)
			break
		}
	}
	if decoded, err := url.PathUnescape(displayPath); err == nil {
		displayPath = decoded
	}
	return normalizeCacheKey(displayPath)
}

func (p *ProxyServer) refreshRedirectInfo(ctx context.Context, redirectKey string, requestHeaders http.Header, info *RedirectInfo) (*RedirectInfo, bool) {
	if p == nil || info == nil || encryptedDAVPath(info.EncryptedPath) == "" {
		return nil, false
	}
	headers := make(http.Header)
	cloneHeader(headers, info.Headers)
	for key, values := range requestHeaders {
		if strings.EqualFold(key, "Range") ||
			strings.EqualFold(key, "Host") ||
			strings.EqualFold(key, "Content-Length") ||
			strings.EqualFold(key, "Proxy-Authorization") {
			continue
		}
		headers.Del(key)
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	rawURL, size := p.resolveEncryptedRawURLViaFsGet(ctx, headers, info.EncryptedPath)
	if strings.TrimSpace(rawURL) == "" {
		return nil, false
	}
	refreshed := cloneRedirectInfo(info)
	refreshed.RedirectURL = rawURL
	refreshed.Headers = headers
	rawIdentityChanged := strings.TrimSpace(rawURL) != strings.TrimSpace(info.RedirectURL)
	if rawIdentityChanged {
		// A new signed URL may point at a replacement object at the same path.
		// Never carry a V2 nonce across that identity boundary without
		// confirming the new 32-byte content header.
		refreshed.ContentVersion = 0
		refreshed.HeaderLen = 0
		refreshed.NonceField = nil
		refreshed.FileSize = size
		refreshed.CiphertextSize = size
		if refreshed.PasswdInfo != nil && refreshed.PasswdInfo.Enable {
			encProbePath := strings.TrimPrefix(encryptedDAVPath(refreshed.EncryptedPath), "/dav")
			meta, confirmed := p.inspectEncryptedContentWithFallbackConfirmed(
				ctx,
				rawURL,
				headers,
				refreshed.PasswdInfo,
				size,
				encProbePath,
			)
			if confirmed {
				refreshed.ContentVersion = meta.Version
				refreshed.HeaderLen = meta.HeaderLen
				refreshed.NonceField = cloneNonceField(meta.NonceField)
				refreshed.CiphertextSize = meta.TotalCiphertextSize()
				refreshed.FileSize = meta.PlainSize
			}
		}
	} else if size > 0 {
		if refreshed.ContentVersion == ContentVersionV2 && refreshed.HeaderLen > 0 {
			// The strict encrypted-path resolver reads OpenList directly, so size
			// is the ciphertext representation (including the V2 header).
			refreshed.CiphertextSize = size
			if size > refreshed.HeaderLen {
				refreshed.FileSize = size - refreshed.HeaderLen
			}
		} else {
			refreshed.FileSize = size
			refreshed.CiphertextSize = size
		}
	}
	if redirectKey != "" {
		p.storeRedirectCache(redirectKey, refreshed)
	}
	return refreshed, true
}

func (o *PlayOrchestrator) resolveFileSize(ctx context.Context, r *http.Request, info *RedirectInfo) int64 {
	if o == nil || o.proxy == nil || info == nil {
		return 0
	}
	fileSize := info.FileSize
	if fileSize > 0 {
		return fileSize
	}

	p := o.proxy
	if size, ok := p.lookupLocalSize(info.RedirectURL, info.OriginalURL); ok {
		fileSize = size
	}
	if fileSize > 0 {
		return fileSize
	}

	for _, cachePath := range playbackCachePathVariants(info) {
		if cached, ok := p.loadFileCache(cachePath); ok && !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
			break
		}
	}
	if fileSize > 0 {
		return fileSize
	}

	encPathPattern := ""
	if info.PasswdInfo != nil {
		encPathPattern = info.PasswdInfo.Path
	}
	if info.OriginalURL != "" {
		origPath := info.OriginalURL
		if u, err := url.Parse(info.OriginalURL); err == nil {
			origPath = u.Path
		}
		webdavPath := origPath
		if !strings.HasPrefix(webdavPath, "/dav") {
			webdavPath = "/dav" + webdavPath
		}
		webdavURL := p.getAlistURL() + webdavPath
		if size := p.fetchWebDAVFileSizeWithPathCtx(ctx, webdavURL, info.Headers, encPathPattern); size > 0 {
			fileSize = size
		}
	}
	if fileSize > 0 {
		return fileSize
	}

	var requestHeaders http.Header
	if r != nil {
		requestHeaders = r.Header
	}
	headers := headersWithStoredOriginCredentials(requestHeaders, info.Headers)
	applyPlaybackOriginCredentials(headers, headers, info.RedirectURL, p.getAlistURL())
	probed := p.forceProbeRemoteFileSizeWithPathCtx(ctx, info.RedirectURL, headers, encPathPattern)
	if probed > 0 {
		fileSize = probed
	}

	return fileSize
}

func (o *PlayOrchestrator) proxyDownloadDecryptWithStrategy(
	w http.ResponseWriter,
	r *http.Request,
	redirectKey string,
	info *RedirectInfo,
	fileSize int64,
	strategy StreamStrategy,
) *StreamOutcome {
	p := o.proxy
	ctx := r.Context()

	// Do not let failures from one signed cloud URL trip the process-wide
	// control-plane breaker. A newly selected video may use a healthy provider,
	// and request cancellation already bounds abandoned seek attempts.
	decodeDisabled := r.URL.Query().Get("decode") == "0"
	if decodeDisabled {
		fileSize = redirectRawFileSize(info, fileSize)
	}
	clientRangeHeader := strings.TrimSpace(r.Header.Get("Range"))
	openEndedClientRange := isOpenEndedByteRange(clientRangeHeader)
	upstreamRangeHeader := clientRangeHeader
	startPos, endPos, hasRange, rangeErr := parseSingleRange(clientRangeHeader, fileSize)
	if rangeErr != nil {
		writeRangeNotSatisfiable(w, fileSize)
		return &StreamOutcome{
			Err:             rangeErr,
			FailureReason:   "range_invalid",
			Retryable:       false,
			ResponseStarted: true,
			StatusCode:      http.StatusRequestedRangeNotSatisfiable,
		}
	}
	encType := EncryptionType("")
	if info.PasswdInfo != nil {
		encType = EncryptionType(info.PasswdInfo.EncType)
	}
	meta := LegacyContentMeta(encType, fileSize)
	trustedRedirectMeta := false
	if cachedMeta, ok := redirectInfoContentMeta(info); ok {
		meta = cachedMeta
		trustedRedirectMeta = true
	}
	if !decodeDisabled && info.PasswdInfo != nil && !trustedRedirectMeta {
		encProbePath := info.EncryptedPath
		if strings.HasPrefix(encProbePath, "/dav") {
			encProbePath = strings.TrimPrefix(encProbePath, "/dav")
		} else if strings.HasPrefix(encProbePath, "/d") {
			encProbePath = strings.TrimPrefix(encProbePath, "/d")
		}

		// --- Check file cache for previously inspected V2 metadata ---
		// This avoids redundant upstream probes for files we've already inspected
		// (both V1 and V2 results are cached, per-file, by display path).
		displayPath := info.OriginalURL
		if displayPath == "" {
			displayPath = info.EncryptedPath
		}
		cachedMetaLoaded := false
		for _, cacheKey := range playbackCachePathVariants(info) {
			if cached, ok := p.loadFileCache(cacheKey); ok && cached.ContentVersion > 0 {
				if cachedMeta, ok := playbackFileInfoContentMeta(cached, info.PasswdInfo.EncType, info.RedirectURL); ok {
					meta = cachedMeta
					cachedMetaLoaded = true
					log.Debugf("[v2-cache] loaded content meta from cache: path=%s version=%d headerLen=%d plainSize=%d cipherSize=%d",
						cacheKey, meta.Version, meta.HeaderLen, meta.PlainSize, meta.CiphertextSize)
					break
				} else if cached.ContentVersion == ContentVersionV1 {
					log.Debugf("[v2-cache] ignoring path-only V1 cache for encrypted playback path=%s (will inspect)", cacheKey)
				}
			}
		}

		if !cachedMetaLoaded {
			log.Debugf("[v2-diag] inspecting: encType=%q fileSize=%d redirectURL=%s encProbePath=%q",
				info.PasswdInfo.EncType, fileSize, safeURLForLog(info.RedirectURL), encProbePath)
			inspectHeaders := headersWithStoredOriginCredentials(r.Header, info.Headers)
			var metaConfirmed bool
			meta, metaConfirmed = p.inspectEncryptedContentWithFallbackConfirmed(
				ctx,
				info.RedirectURL,
				inspectHeaders,
				info.PasswdInfo,
				fileSize,
				encProbePath,
			)
			if !metaConfirmed {
				return &StreamOutcome{
					Err:           fmt.Errorf("unable to confirm encrypted content metadata"),
					FailureReason: "metadata_probe_failed",
					Retryable:     true,
				}
			}
			log.Debugf("[v2-diag] inspection result: isV2=%v version=%d plainSize=%d cipherSize=%d headerLen=%d",
				meta.IsV2(), meta.Version, meta.PlainSize, meta.CiphertextSize, meta.HeaderLen)

			// --- Cache inspection result for future requests ---
			// Store both V1 and V2 conclusions so subsequent requests skip the probe entirely.
			if displayPath != "" {
				cacheInfo := &FileInfo{
					Name:           path.Base(displayPath),
					Size:           meta.PlainSize,
					CiphertextSize: meta.CiphertextSize,
					ContentVersion: meta.Version,
					HeaderLen:      meta.HeaderLen,
					NonceField:     cloneNonceField(meta.NonceField),
					IsDir:          false,
					Path:           displayPath,
					RawURL:         info.RedirectURL,
				}
				for _, cachePath := range appendUniquePathVariant(nil, displayPath) {
					infoCopy := &FileInfo{
						Name:           cacheInfo.Name,
						Size:           cacheInfo.Size,
						CiphertextSize: cacheInfo.CiphertextSize,
						ContentVersion: cacheInfo.ContentVersion,
						HeaderLen:      cacheInfo.HeaderLen,
						NonceField:     cloneNonceField(cacheInfo.NonceField),
						IsDir:          false,
						Path:           cachePath,
						RawURL:         cacheInfo.RawURL,
					}
					p.storeFileCache(cachePath, infoCopy)
				}
				log.Debugf("[v2-cache] cached inspection result: path=%s version=%d plainSize=%d cipherSize=%d",
					displayPath, meta.Version, meta.PlainSize, meta.CiphertextSize)
			}
			if redirectKey != "" && meta.Version > 0 {
				updated := cloneRedirectInfo(info)
				updated.ContentVersion = meta.Version
				updated.HeaderLen = meta.HeaderLen
				updated.NonceField = cloneNonceField(meta.NonceField)
				updated.CiphertextSize = meta.CiphertextSize
				updated.FileSize = meta.PlainSize
				p.storeRedirectCache(redirectKey, updated)
				info = updated
			}
		}

		if meta.IsV2() {
			log.Debugf("V2 redirect meta (inspected): url=%s clientRange=%q headerLen=%d cipherSize=%d plainSize=%d",
				safeURLForLog(info.RedirectURL), clientRangeHeader, meta.HeaderLen, meta.CiphertextSize, meta.PlainSize)
		}
	}

	// Always apply V2 corrections — whether meta came from inspection, cache, or pre-population.
	// This ensures fileSize is plainSize and upstream range is shifted by headerLen.
	if meta.IsV2() && !decodeDisabled {
		if meta.PlainSize > 0 {
			fileSize = meta.PlainSize
		}
	}
	startPos, endPos, hasRange, rangeErr = parseSingleRange(clientRangeHeader, fileSize)
	if rangeErr != nil {
		writeRangeNotSatisfiable(w, fileSize)
		return &StreamOutcome{
			Err:             rangeErr,
			FailureReason:   "range_invalid",
			Retryable:       false,
			ResponseStarted: true,
			StatusCode:      http.StatusRequestedRangeNotSatisfiable,
		}
	}
	if meta.IsV2() && !decodeDisabled {
		if hasRange && strategy == StreamStrategyRange {
			// Canonicalize bounded and suffix client ranges to an explicit
			// ciphertext interval. Passing a suffix range through as-is would
			// count the V2 header as part of a small representation.
			rangeSpec := strings.TrimSpace(strings.TrimPrefix(clientRangeHeader, "bytes="))
			if strings.HasSuffix(rangeSpec, "-") && !strings.HasPrefix(rangeSpec, "-") {
				// Preserve open-ended ranges for compatibility with providers that
				// distinguish them from an explicit end at EOF.
				upstreamRangeHeader = fmt.Sprintf("bytes=%d-", meta.UpstreamOffset(startPos))
			} else {
				upstreamRangeHeader = fmt.Sprintf("bytes=%d-%d", meta.UpstreamOffset(startPos), meta.UpstreamOffset(endPos))
			}
		}
		log.Debugf("V2 redirect meta: url=%s clientRange=%q upstreamRange=%q headerLen=%d cipherSize=%d plainSize=%d",
			safeURLForLog(info.RedirectURL), clientRangeHeader, upstreamRangeHeader, meta.HeaderLen, meta.CiphertextSize, meta.PlainSize)
	}

	if hasRange {
		if strategy == StreamStrategyChunked || strategy == StreamStrategyFull {
			upstreamRangeHeader = ""
		}
	}

	if r.Method == http.MethodHead && !decodeDisabled {
		statusCode := http.StatusOK
		w.Header().Set("Accept-Ranges", "bytes")
		if hasRange {
			statusCode = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
			w.Header().Set("Content-Length", strconv.FormatInt(endPos-startPos+1, 10))
		} else {
			w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
		}
		w.WriteHeader(statusCode)
		return &StreamOutcome{StatusCode: statusCode, ResponseStarted: true}
	}

	client := p.streamClientSnapshot()
	if client == nil {
		return &StreamOutcome{Err: fmt.Errorf("stream client unavailable"), FailureReason: "stream_error", Retryable: true}
	}
	upstreamMethod := http.MethodGet
	if decodeDisabled {
		upstreamMethod = r.Method
	}
	buildRequest := func(targetURL string, current *RedirectInfo) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, upstreamMethod, targetURL, nil)
		if err != nil {
			return nil, err
		}
		p.applyRoutingHints(req, current.Provider, current.Driver)
		copyPlaybackStreamHeaders(req.Header, r.Header, current.Headers, targetURL, p.getAlistURL())
		if upstreamRangeHeader == "" {
			req.Header.Del("Range")
		} else {
			req.Header.Set("Range", upstreamRangeHeader)
		}
		if strings.Contains(targetURL, "baidupcs.com") {
			req.Header.Set("User-Agent", "pan.baidu.com")
		}
		return req, nil
	}
	doStreamRequest := func(current *RedirectInfo) (*http.Response, error) {
		targetURL := current.RedirectURL
		for redirectCount := 0; redirectCount <= 5; redirectCount++ {
			req, err := buildRequest(targetURL, current)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode < http.StatusMultipleChoices || resp.StatusCode >= http.StatusBadRequest {
				return resp, nil
			}
			location := strings.TrimSpace(resp.Header.Get("Location"))
			if location == "" || redirectCount == 5 {
				return resp, nil
			}
			next, err := req.URL.Parse(location)
			if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
				resp.Body.Close()
				if err == nil {
					err = fmt.Errorf("unsupported redirect scheme %q", next.Scheme)
				}
				return nil, err
			}
			resp.Body.Close()
			targetURL = next.String()
		}
		return nil, fmt.Errorf("too many upstream redirects")
	}

	resp, err := doStreamRequest(info)
	if err != nil {
		return &StreamOutcome{
			Err:           err,
			FailureReason: "network_error",
			Retryable:     true,
		}
	}
	if isExpiredSignedURLStatus(resp.StatusCode) {
		if refreshed, ok := p.refreshRedirectInfo(ctx, redirectKey, r.Header, info); ok {
			resp.Body.Close()
			info = refreshed
			resp, err = doStreamRequest(info)
			if err != nil {
				return &StreamOutcome{Err: err, FailureReason: "network_error", Retryable: true}
			}
		}
	}
	if isExpiredSignedURLStatus(resp.StatusCode) {
		// Some providers report expired signed URLs as 404. Bypass the stale
		// URL through the encrypted /dav object path; never derive this fallback
		// from OriginalURL because that is the plaintext display path.
		internalTarget := p.encryptedDAVTargetURL(info.EncryptedPath, redirectOriginalRawQuery(info))
		if internalTarget != "" && internalTarget != info.RedirectURL {
			resp.Body.Close()
			internalInfo := cloneRedirectInfo(info)
			internalInfo.RedirectURL = internalTarget
			resp, err = doStreamRequest(internalInfo)
			if err != nil {
				return &StreamOutcome{Err: err, FailureReason: "network_error", Retryable: true}
			}
			info = internalInfo
			if redirectKey != "" {
				p.storeRedirectCache(redirectKey, internalInfo)
			}
		}
	}
	defer resp.Body.Close()
	if decodeDisabled {
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if r.Method == http.MethodHead {
			return &StreamOutcome{StatusCode: resp.StatusCode, ResponseStarted: true}
		}
		if _, copyErr := copyWithBuffer(w, resp.Body); copyErr != nil {
			return &StreamOutcome{
				Err:             copyErr,
				FailureReason:   "stream_error",
				Retryable:       true,
				ResponseStarted: true,
				StatusCode:      resp.StatusCode,
			}
		}
		return &StreamOutcome{StatusCode: resp.StatusCode, ResponseStarted: true}
	}

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}
	upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
	log.Debugf("V2 redirect attempt: url=%s strategy=%s range=%q upstreamStatus=%d contentRange=%q contentLength=%q fileSize=%d",
		safeURLForLog(info.RedirectURL), strategy, clientRangeHeader, resp.StatusCode, resp.Header.Get("Content-Range"), resp.Header.Get("Content-Length"), fileSize)
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		return &StreamOutcome{
			Err:           fmt.Errorf("upstream range unsatisfiable"),
			FailureReason: "range_unsatisfiable",
			Retryable:     true,
			StatusCode:    resp.StatusCode,
		}
	}
	if resp.StatusCode >= http.StatusBadRequest && resp.StatusCode < http.StatusInternalServerError && resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		return &StreamOutcome{
			Err:           fmt.Errorf("upstream returned %d", resp.StatusCode),
			FailureReason: "upstream_4xx",
			Retryable:     false,
			StatusCode:    statusCode,
		}
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return &StreamOutcome{
			Err:           fmt.Errorf("upstream returned %d", resp.StatusCode),
			FailureReason: "upstream_5xx",
			Retryable:     true,
			StatusCode:    statusCode,
		}
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return &StreamOutcome{
			Err:           fmt.Errorf("upstream redirect failed with %d", resp.StatusCode),
			FailureReason: "redirect_invalid",
			Retryable:     true,
			StatusCode:    resp.StatusCode,
		}
	}

	// If we requested range, but upstream didn't support it, fail/retryable
	if clientRangeHeader != "" && strategy == StreamStrategyRange && !upstreamIsRange {
		p.markRangeIncompatible(info.RedirectURL, info.OriginalURL)
		return &StreamOutcome{
			Err:           fmt.Errorf("range unsupported by upstream"),
			FailureReason: "range_unsupported",
			Retryable:     true,
			StatusCode:    statusCode,
		}
	}

	actualWindowEnd := int64(-1)
	if clientRangeHeader != "" && strategy == StreamStrategyRange && upstreamIsRange {
		contentRangeHeader := resp.Header.Get("Content-Range")
		actualRange, validContentRange := parseContentRange(contentRangeHeader)
		expectedStart := startPos
		expectedEnd := endPos
		if meta.IsV2() {
			expectedStart = meta.UpstreamOffset(startPos)
			expectedEnd = meta.UpstreamOffset(endPos)
		}
		validOpenEndedWindow := openEndedClientRange &&
			validContentRange &&
			actualRange.Start == expectedStart &&
			actualRange.End >= expectedStart
		if !validContentRange || actualRange.Start != expectedStart || (actualRange.End < expectedEnd && !validOpenEndedWindow) {
			p.markRangeIncompatible(info.RedirectURL, info.OriginalURL)
			return &StreamOutcome{
				Err:           fmt.Errorf("upstream Content-Range %q does not cover requested interval %d-%d", contentRangeHeader, expectedStart, expectedEnd),
				FailureReason: "range_unsupported",
				Retryable:     true,
				StatusCode:    statusCode,
			}
		}
		if validOpenEndedWindow {
			actualWindowEnd = actualRange.End
			if meta.IsV2() {
				actualWindowEnd -= meta.HeaderLen
			}
			if actualWindowEnd < startPos {
				p.markRangeIncompatible(info.RedirectURL, info.OriginalURL)
				return &StreamOutcome{
					Err:           fmt.Errorf("upstream Content-Range %q maps before requested plaintext offset %d", contentRangeHeader, startPos),
					FailureReason: "range_unsupported",
					Retryable:     true,
					StatusCode:    statusCode,
				}
			}
		}
		p.markRangeCompatible(info.RedirectURL, info.OriginalURL)
	}

	// Copy response headers
	for key, values := range resp.Header {
		lowerKey := strings.ToLower(key)
		if lowerKey == "content-length" || lowerKey == "content-range" || lowerKey == "accept-ranges" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.Header().Set("Accept-Ranges", "bytes")
	// Decrypt filename in header
	lastUrl := r.URL.Query().Get("lastUrl")
	if lastUrl != "" && info.PasswdInfo != nil && info.PasswdInfo.EncName {
		if decoded, err := url.QueryUnescape(lastUrl); err == nil {
			lastUrl = decoded
		}
		fileName := path.Base(lastUrl)
		if decoded, err := url.PathUnescape(fileName); err == nil {
			fileName = decoded
		}
		ext := path.Ext(fileName)
		baseName := strings.TrimSuffix(fileName, ext)
		decryptedName := DecodeName(info.PasswdInfo.Password, info.PasswdInfo.EncType, baseName)
		if decryptedName != "" {
			cd := w.Header().Get("Content-Disposition")
			if cd != "" {
				cd = regexp.MustCompile(`filename\*?=[^;]*;?\s*`).ReplaceAllString(cd, "")
			}
			if cd == "" {
				cd = "attachment; "
			} else if !strings.HasSuffix(cd, "; ") && !strings.HasSuffix(cd, ";") {
				cd += "; "
			}
			w.Header().Set("Content-Disposition", cd+fmt.Sprintf("filename*=UTF-8''%s", url.PathEscape(decryptedName)))
		}
	}

	if info.PasswdInfo == nil {
		w.WriteHeader(statusCode)
		_, err = copyWithBuffer(w, resp.Body)
		if err != nil {
			return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true, ResponseStarted: true}
		}
		return &StreamOutcome{StatusCode: statusCode}
	}

	originalSize := fileSize
	fileSize = normalizePlainFileSize(fileSize, &meta, resp.Header.Get("Content-Range"))
	if meta.IsV2() {
		log.Debugf("V2 redirect normalized size: url=%s contentRange=%q fileSize=%d->%d cipherSize=%d plainSize=%d",
			safeURLForLog(info.RedirectURL), resp.Header.Get("Content-Range"), originalSize, fileSize, meta.CiphertextSize, meta.PlainSize)
	}
	startPos, endPos, hasRange, rangeErr = parseSingleRange(clientRangeHeader, fileSize)
	if rangeErr != nil {
		writeRangeNotSatisfiable(w, fileSize)
		return &StreamOutcome{
			Err:             rangeErr,
			FailureReason:   "range_invalid",
			Retryable:       false,
			ResponseStarted: true,
			StatusCode:      http.StatusRequestedRangeNotSatisfiable,
		}
	}
	if actualWindowEnd >= startPos && actualWindowEnd < endPos {
		endPos = actualWindowEnd
	}

	var encryptor FlowEncryptor
	if meta.IsV2() {
		encryptor, err = NewCipherV2(EncryptionType(info.PasswdInfo.EncType), info.PasswdInfo.Password, fileSize, meta.NonceField)
	} else {
		encryptor, err = NewFlowEncryptor(info.PasswdInfo.Password, info.PasswdInfo.EncType, fileSize)
	}
	if err != nil {
		return &StreamOutcome{Err: err, FailureReason: "decrypt_validation_failed", Retryable: false}
	}

	var readerToStream io.Reader = resp.Body
	upstreamPayloadRange := meta.IsV2() && strategy == StreamStrategyRange && hasRange && upstreamIsRange
	localRangePrepared := false

	if clientRangeHeader != "" {
		if strategy == StreamStrategyRange {
			if startPos > 0 {
				if err := encryptor.SetPosition(startPos); err != nil {
					return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: false}
				}
			}
		} else if strategy == StreamStrategyChunked {
			maxDiscard := p.rangeSkipMaxBytes()
			if maxDiscard > 0 && startPos > maxDiscard {
				return &StreamOutcome{
					Err:           fmt.Errorf("chunked seek offset too large"),
					FailureReason: "chunked_seek_too_large",
					Retryable:     true,
				}
			}
			discardLength := startPos
			if meta.IsV2() {
				discardLength += meta.HeaderLen
			}
			if discardLength > 0 {
				if _, err := io.CopyN(io.Discard, resp.Body, discardLength); err != nil {
					return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true}
				}
			}
			if err := encryptor.SetPosition(startPos); err != nil {
				return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: false}
			}
			length := endPos - startPos + 1
			readerToStream = io.LimitReader(resp.Body, length)
			localRangePrepared = true
			statusCode = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
			w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		} else if strategy == StreamStrategyFull {
			maxDiscard := p.rangeSkipMaxBytes()
			if maxDiscard > 0 && startPos > maxDiscard {
				return &StreamOutcome{
					Err:           fmt.Errorf("full seek offset too large"),
					FailureReason: "full_seek_too_large",
					Retryable:     true,
				}
			}
			discardLength := startPos
			if meta.IsV2() {
				discardLength += meta.HeaderLen
			}
			if discardLength > 0 {
				if _, err := io.CopyN(io.Discard, resp.Body, discardLength); err != nil {
					return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true}
				}
			}
			if err := encryptor.SetPosition(startPos); err != nil {
				return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: false}
			}
			length := endPos - startPos + 1
			readerToStream = io.LimitReader(resp.Body, length)
			localRangePrepared = true
			statusCode = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
			w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		}
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
	}

	if hasRange && strategy == StreamStrategyRange {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
		w.Header().Set("Content-Length", strconv.FormatInt(endPos-startPos+1, 10))
	} else if !hasRange {
		w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
	}

	if meta.IsV2() && !upstreamPayloadRange && !localRangePrepared {
		if err := discardBytes(readerToStream, meta.HeaderLen); err != nil {
			return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true}
		}
	}
	expectedLength := fileSize
	if hasRange {
		expectedLength = endPos - startPos + 1
	}
	if expectedLength < 0 {
		return &StreamOutcome{Err: fmt.Errorf("invalid expected stream length %d", expectedLength), FailureReason: "stream_error", Retryable: false}
	}
	readerToStream = io.LimitReader(readerToStream, expectedLength)

	decryptReader := NewDecryptReader(readerToStream, encryptor)
	// Write-through decrypted block cache: bytes produced for this redirect are
	// cached in 256KB blocks, so a later seek that lands inside an already-played
	// region is served from memory instead of re-fetching + re-decrypting from the
	// CDN. This directly counters the "repeated tail seek" stall pattern.
	streamStart := startPos
	if !hasRange {
		streamStart = 0
	}
	var streamSource io.Reader = decryptReader
	if cache := p.decryptedBlockCache; cache != nil {
		streamSource = newDecryptedCacheReader(decryptReader, cache, p.decryptedCacheBaseKey(info, meta), streamStart)
	}
	w.WriteHeader(statusCode)

	written, err := copyWithBuffer(w, streamSource)
	if err != nil {
		log.Warnf("V2 redirect stream copy failed: url=%s strategy=%s written=%d ctxErr=%v err=%v",
			safeURLForLog(info.RedirectURL), strategy, written, r.Context().Err(), err)
		return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true, ResponseStarted: true}
	}
	if written != expectedLength {
		err = fmt.Errorf("decrypted stream truncated: wrote %d of %d bytes: %w", written, expectedLength, io.ErrUnexpectedEOF)
		log.Warnf("V2 redirect stream truncated: url=%s strategy=%s written=%d expected=%d ctxErr=%v",
			safeURLForLog(info.RedirectURL), strategy, written, expectedLength, r.Context().Err())
		return &StreamOutcome{Err: err, FailureReason: "stream_truncated", Retryable: true, ResponseStarted: true}
	}
	log.Debugf("V2 redirect stream copy complete: url=%s strategy=%s written=%d status=%d",
		safeURLForLog(info.RedirectURL), strategy, written, statusCode)

	return &StreamOutcome{StatusCode: statusCode}
}

func (o *PlayOrchestrator) ServeRedirect(w http.ResponseWriter, r *http.Request) {
	if o == nil || o.proxy == nil || r == nil || r.URL == nil {
		http.Error(w, "play orchestrator unavailable", http.StatusInternalServerError)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		http.Error(w, "Invalid redirect key", http.StatusBadRequest)
		return
	}
	key := parts[2]

	info, ok := o.proxy.loadRedirectCache(key)
	if !ok {
		http.Error(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}
	info = cloneRedirectInfo(info)

	fileSize := o.resolveFileSize(r.Context(), r, info)
	decodeDisabled := r.URL.Query().Get("decode") == "0"
	if decodeDisabled {
		fileSize = redirectRawFileSize(info, fileSize)
	}
	refreshRangeInfo := func() bool {
		refreshed, refreshedOK := o.proxy.refreshRedirectInfo(r.Context(), key, r.Header, info)
		if !refreshedOK {
			return false
		}
		info = refreshed
		if decodeDisabled {
			fileSize = redirectRawFileSize(info, info.FileSize)
		} else if info.FileSize > 0 {
			fileSize = info.FileSize
		} else {
			fileSize = o.resolveFileSize(r.Context(), r, info)
		}
		return fileSize > 0
	}
	log.Debugf("V2 redirect resolve: original=%s redirect=%s size=%d range=%q", safeURLForLog(info.OriginalURL), safeURLForLog(info.RedirectURL), fileSize, r.Header.Get("Range"))
	if fileSize == 0 && shouldDecryptRedirect(r, info) && info.PasswdInfo != nil {
		inspectHeaders := headersWithStoredOriginCredentials(r.Header, info.Headers)
		encProbePath := strings.TrimPrefix(encryptedDAVPath(info.EncryptedPath), "/dav")
		meta, confirmed := o.proxy.inspectEncryptedContentWithFallbackConfirmed(
			r.Context(),
			info.RedirectURL,
			inspectHeaders,
			info.PasswdInfo,
			0,
			encProbePath,
		)
		if confirmed && meta.IsV2() && meta.PlainSize > 0 {
			info.ContentVersion = meta.Version
			info.HeaderLen = meta.HeaderLen
			info.NonceField = cloneNonceField(meta.NonceField)
			info.CiphertextSize = meta.CiphertextSize
			info.FileSize = meta.PlainSize
			fileSize = meta.PlainSize
			o.proxy.storeRedirectCache(key, info)
			log.Infof("V2 play: recovered unknown file size from encrypted header plainSize=%d cipherSize=%d", meta.PlainSize, meta.CiphertextSize)
		}
	}
	if fileSize == 0 {
		if shouldDecryptRedirect(r, info) {
			log.Warnf("V2 play: refusing encrypted passthrough because file size is unknown")
			http.Error(w, "unable to determine encrypted file size", http.StatusBadGateway)
			return
		}
		log.Warnf("V2 play: fileSize is 0, skipping decryption and proxying raw stream")
		req, err := http.NewRequestWithContext(r.Context(), r.Method, info.RedirectURL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		o.proxy.applyRoutingHints(req, info.Provider, info.Driver)
		copyPlaybackStreamHeaders(req.Header, r.Header, info.Headers, info.RedirectURL, o.proxy.getAlistURL())
		client := o.proxy.streamClientSnapshot()
		if client == nil {
			http.Error(w, "stream client unavailable", http.StatusBadGateway)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if r.Method != http.MethodHead {
			_, _ = copyWithBuffer(w, resp.Body)
		}
		return
	}
	rangeHeader := r.Header.Get("Range")
	if _, _, _, rangeErr := parseSingleRange(rangeHeader, fileSize); rangeErr != nil {
		rangeStart, hasRangeStart := parseRangeStart(rangeHeader)
		if !hasRangeStart || rangeStart < fileSize || !refreshRangeInfo() {
			writeRangeNotSatisfiable(w, fileSize)
			return
		}
		if _, _, _, refreshedRangeErr := parseSingleRange(rangeHeader, fileSize); refreshedRangeErr != nil {
			writeRangeNotSatisfiable(w, fileSize)
			return
		}
		log.Infof("V2 play: refreshed stale size before range validation start=%d size=%d", rangeStart, fileSize)
	}

	// Decrypted block cache hit: if the requested range is entirely inside an
	// already-played (and therefore already-decrypted) region, serve it straight
	// from memory. No upstream fetch, no CDN re-handshake, no re-decrypt.
	if cache := o.proxy.decryptedBlockCache; cache != nil && !decodeDisabled && r.Method == http.MethodGet && fileSize > 0 && shouldDecryptRedirect(r, info) && info.PasswdInfo != nil {
		if start, end, hasRange, rangeErr := parseSingleRange(rangeHeader, fileSize); rangeErr == nil && hasRange {
			meta := ContentMeta{
				Version:        info.ContentVersion,
				HeaderLen:      info.HeaderLen,
				NonceField:     info.NonceField,
				CiphertextSize: info.CiphertextSize,
				PlainSize:      fileSize,
			}
			length := end - start + 1
			if data, ok := cache.getRange(o.proxy.decryptedCacheBaseKey(info, meta), start, length); ok {
				w.Header().Set("Accept-Ranges", "bytes")
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, fileSize))
				w.Header().Set("Content-Length", strconv.FormatInt(int64(len(data)), 10))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(data)
				log.Debugf("V2 play: served %d bytes from decrypted block cache start=%d end=%d", len(data), start, end)
				return
			}
		}
	}

	provider := info.Provider
	if provider == "" {
		provider = ProviderKey(info.RedirectURL, "")
	}

	strategies := []StreamStrategy{StreamStrategyRange}
	if !decodeDisabled && o.proxy.strategySelector != nil {
		strategies = o.proxy.strategySelector.Select(provider)
	}
	rangeStart, hasRangeStart := parseRangeStart(rangeHeader)
	maxDiscard := o.proxy.rangeSkipMaxBytes()
	largeSeek := hasRangeStart && maxDiscard > 0 && rangeStart > maxDiscard
	if largeSeek {
		// Chunked/full strategies would have to discard an unbounded prefix.
		// A fresh signed URL may support this seek even when an old provider
		// capability sample did not, so Range is the only safe attempt.
		strategies = []StreamStrategy{StreamStrategyRange}
	}

	attempted := make(map[StreamStrategy]struct{}, len(strategies)+2)
	tryStrategy := func(strategy StreamStrategy) *StreamOutcome {
		attempted[strategy] = struct{}{}
		if latest, ok := o.proxy.loadRedirectCache(key); ok {
			info = cloneRedirectInfo(latest)
		}
		attemptSize := fileSize
		if info.ContentVersion == ContentVersionV1 && info.FileSize > 0 {
			attemptSize = info.FileSize
		}
		outcome := o.proxyDownloadDecryptWithStrategy(w, r, key, info, attemptSize, strategy)
		if outcome == nil {
			return &StreamOutcome{Err: fmt.Errorf("empty stream outcome"), FailureReason: "stream_error", Retryable: true}
		}
		if outcome != nil && outcome.Err != nil {
			log.Warnf("V2 redirect strategy failed: strategy=%s reason=%s retryable=%v responseStarted=%v err=%v",
				strategy, outcome.FailureReason, outcome.Retryable, outcome.ResponseStarted, outcome.Err)
		}
		if outcome.Err == nil && !outcome.Retryable {
			if o.proxy.strategySelector != nil {
				o.proxy.strategySelector.RecordSuccess(provider, strategy)
			}
			return outcome
		}
		if !outcome.ResponseStarted && outcome.Retryable {
			if o.proxy.strategySelector != nil {
				o.proxy.strategySelector.RecordFailure(provider, strategy, outcome.FailureReason)
			}
		}
		return outcome
	}

	var outcome *StreamOutcome
	rangeRefreshAttempted := false
	for _, strategy := range strategies {
		if _, alreadyAttempted := attempted[strategy]; alreadyAttempted {
			continue
		}
		outcome = tryStrategy(strategy)
		if outcome.Err == nil {
			return
		}
		if outcome.ResponseStarted {
			break
		}
		if outcome.FailureReason == "metadata_probe_failed" {
			break
		}
		if outcome.FailureReason == "range_unsupported" && strategy == StreamStrategyRange {
			if largeSeek {
				log.Warnf("V2 play: upstream ignored Range at offset=%d; refusing a no-Range retry above discard limit=%d", rangeStart, maxDiscard)
				break
			}
			if _, alreadyAttempted := attempted[StreamStrategyChunked]; !alreadyAttempted {
				log.Warnf("V2 play: range unsupported, falling back to chunked")
				outcome = tryStrategy(StreamStrategyChunked)
				if outcome.Err == nil {
					return
				}
				if outcome.ResponseStarted {
					break
				}
				if outcome.FailureReason == "chunked_seek_too_large" {
					log.Warnf("V2 play: chunked seek exceeds local discard limit; refusing an unbounded full-file fallback")
				}
			}
		} else if outcome.FailureReason == "range_unsatisfiable" && strategy == StreamStrategyRange {
			if !rangeRefreshAttempted {
				rangeRefreshAttempted = true
				if refreshRangeInfo() {
					delete(attempted, StreamStrategyRange)
					log.Warnf("V2 play: range unsatisfiable, refreshed signed URL and size before retry")
					outcome = tryStrategy(StreamStrategyRange)
					if outcome.Err == nil {
						return
					}
					if outcome.ResponseStarted {
						break
					}
				}
			}
			if outcome.FailureReason != "range_unsatisfiable" {
				break
			}
			if start, ok := parseRangeStart(rangeHeader); ok {
				maxDiscard := o.proxy.rangeSkipMaxBytes()
				if maxDiscard > 0 && start > maxDiscard {
					log.Warnf("V2 play: refreshed range remains unsatisfiable at offset=%d; refusing full discard above limit=%d", start, maxDiscard)
					break
				}
			}
			if _, alreadyAttempted := attempted[StreamStrategyFull]; !alreadyAttempted {
				log.Warnf("V2 play: refreshed range remains unsatisfiable, using bounded full fallback")
				outcome = tryStrategy(StreamStrategyFull)
				if outcome.Err == nil {
					return
				}
			}
		}
	}

	unsafeEncryptedPassthrough := shouldDecryptRedirect(r, info)
	cfg := o.proxy.runtimeSnapshot().config
	playFirstFallback := cfg != nil && cfg.PlayFirstFallback
	if outcome != nil && !outcome.ResponseStarted && playFirstFallback && !unsafeEncryptedPassthrough {
		log.Warnf("V2 play: all strategies failed, playing raw stream as final fallback")
		req, err := http.NewRequestWithContext(r.Context(), r.Method, info.RedirectURL, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		o.proxy.applyRoutingHints(req, info.Provider, info.Driver)
		copyPlaybackStreamHeaders(req.Header, r.Header, info.Headers, info.RedirectURL, o.proxy.getAlistURL())
		client := o.proxy.streamClientSnapshot()
		if client == nil {
			http.Error(w, "stream client unavailable", http.StatusBadGateway)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if r.Method != http.MethodHead {
			_, _ = copyWithBuffer(w, resp.Body)
		}
		return
	}
	if unsafeEncryptedPassthrough && outcome != nil && !outcome.ResponseStarted {
		log.Warnf("V2 play: refusing raw encrypted fallback for decode request")
	}

	if outcome != nil && outcome.Err != nil {
		if outcome.ResponseStarted {
			return
		}
		http.Error(w, outcome.Err.Error(), http.StatusBadGateway)
	} else {
		http.Error(w, "stream play failed", http.StatusBadGateway)
	}
}

func (p *ProxyServer) handlePlayResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(bytes.TrimSpace(body)) == 0 {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	host := r.Host
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	orch := newPlayOrchestrator(p)
	status, respBody := orch.resolveViaFsGet(r.Context(), host, scheme, r.Header, body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

func (p *ProxyServer) handlePlayStream(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/api/play/stream/"))
	if token == "" {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	orch := newPlayOrchestrator(p)
	orch.streamViaRedirect(r.Context(), w, r, token)
}

func (p *ProxyServer) handlePlayStats(w http.ResponseWriter, r *http.Request) {
	p.rangeProbeMu.Lock()
	targetCount := len(p.rangeProbeTargets)
	p.rangeProbeMu.Unlock()

	p.rangeCompatMu.RLock()
	rangeCompatCount := len(p.rangeCompat)
	p.rangeCompatMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"streamEngineVersion": p.streamEngineVersion(),
			"rangeCompatEntries":  rangeCompatCount,
			"rangeProbeTargets":   targetCount,
		},
	})
}

func (p *ProxyServer) handleWebDAVV2(w http.ResponseWriter, r *http.Request) {
	newPlayOrchestrator(p).ServePlayback(w, remapRequestPath(r, "/dav2", "/dav"))
}
