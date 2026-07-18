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
	rec := httptest.NewRecorder()
	p.handleFsGet(rec, req)
	if cached, ok := p.loadFileCache(displayPath); ok && cached != nil {
		if rawURL := strings.TrimSpace(cached.RawURL); rawURL != "" {
			return rawURL, cached.Size
		}
	}
	return "", 0
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

func isFirstFrameRangeHint(method, rangeHeader string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	if rangeHeader == "" {
		return true
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(rangeHeader, "bytes="), "-")
	if len(parts) == 0 {
		return false
	}
	startStr := strings.TrimSpace(parts[0])
	if startStr == "" {
		return false
	}
	start, err := strconv.ParseInt(startStr, 10, 64)
	if err != nil || start != 0 {
		return false
	}
	if len(parts) > 1 {
		endStr := strings.TrimSpace(parts[1])
		if endStr == "" {
			return true
		}
		end, err := strconv.ParseInt(endStr, 10, 64)
		if err == nil && end < 2*1024*1024 {
			return true
		}
	}
	return false
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
	displayPath := redirectDisplayPath(info)
	if p == nil || info == nil || displayPath == "" {
		return nil, false
	}
	headers := info.Headers.Clone()
	for key, values := range requestHeaders {
		if strings.EqualFold(key, "Range") || strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		headers.Del(key)
		for _, value := range values {
			headers.Add(key, value)
		}
	}
	rawURL, size := p.resolveRawURLViaFsGet(ctx, headers, displayPath)
	if strings.TrimSpace(rawURL) == "" {
		return nil, false
	}
	refreshed := cloneRedirectInfo(info)
	refreshed.RedirectURL = rawURL
	if size > 0 {
		if refreshed.ContentVersion == ContentVersionV2 && refreshed.HeaderLen > 0 {
			refreshed.CiphertextSize = size
			if size > refreshed.HeaderLen {
				refreshed.FileSize = size - refreshed.HeaderLen
			}
		} else {
			refreshed.FileSize = size
			refreshed.CiphertextSize = size
		}
	}
	refreshed.Headers = headers
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

	headers := info.Headers
	if r != nil {
		headers = r.Header
	}
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
	clientRangeHeader := strings.TrimSpace(r.Header.Get("Range"))
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
	if decode := r.URL.Query().Get("decode"); decode != "0" && info.PasswdInfo != nil && !trustedRedirectMeta {
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
			meta = p.inspectEncryptedContentWithFallback(ctx, info.RedirectURL, r.Header, info.PasswdInfo, fileSize, encProbePath)
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
	if meta.IsV2() {
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
	if meta.IsV2() {
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

	if r.Method == http.MethodHead {
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
	buildRequest := func(targetURL string, current *RedirectInfo) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil, err
		}
		p.applyRoutingHints(req, current.Provider, current.Driver)
		for key, values := range r.Header {
			lowerKey := strings.ToLower(key)
			if lowerKey == "host" || lowerKey == "referer" || lowerKey == "authorization" {
				continue
			}
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
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
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		if refreshed, ok := p.refreshRedirectInfo(ctx, redirectKey, r.Header, info); ok {
			info = refreshed
			resp, err = doStreamRequest(info)
			if err != nil {
				return &StreamOutcome{Err: err, FailureReason: "network_error", Retryable: true}
			}
		}
	}
	defer resp.Body.Close()

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

	if clientRangeHeader != "" && upstreamIsRange {
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

	decode := r.URL.Query().Get("decode")
	if decode == "0" || info.PasswdInfo == nil {
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
	w.WriteHeader(statusCode)

	written, err := copyWithBuffer(w, decryptReader)
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
	log.Debugf("V2 redirect resolve: original=%s redirect=%s size=%d range=%q", safeURLForLog(info.OriginalURL), safeURLForLog(info.RedirectURL), fileSize, r.Header.Get("Range"))
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
		for headerKey, values := range r.Header {
			lowerKey := strings.ToLower(headerKey)
			if lowerKey != "host" && lowerKey != "authorization" && lowerKey != "referer" {
				for _, value := range values {
					req.Header.Add(headerKey, value)
				}
			}
		}
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
	if _, _, _, err := parseSingleRange(r.Header.Get("Range"), fileSize); err != nil {
		writeRangeNotSatisfiable(w, fileSize)
		return
	}

	provider := info.Provider
	if provider == "" {
		provider = ProviderKey(info.RedirectURL, "")
	}

	strategies := []StreamStrategy{StreamStrategyRange}
	if o.proxy.strategySelector != nil {
		strategies = o.proxy.strategySelector.Select(provider)
	}

	firstFrameHint := isFirstFrameRangeHint(r.Method, r.Header.Get("Range"))

	tryStrategy := func(strategy StreamStrategy) *StreamOutcome {
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
	for _, strategy := range strategies {
		outcome = tryStrategy(strategy)
		if outcome.Err == nil {
			return
		}
		if outcome.ResponseStarted {
			break
		}
		if outcome.FailureReason == "range_unsupported" && firstFrameHint && strategy == StreamStrategyRange {
			log.Warnf("V2 play: range unsupported on first frame, falling back to chunked")
			outcome = tryStrategy(StreamStrategyChunked)
			if outcome.Err == nil {
				return
			}
		} else if outcome.FailureReason == "range_unsatisfiable" && strategy == StreamStrategyRange {
			log.Warnf("V2 play: range unsatisfiable, falling back to full")
			outcome = tryStrategy(StreamStrategyFull)
			if outcome.Err == nil {
				return
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
		for headerKey, values := range r.Header {
			lowerKey := strings.ToLower(headerKey)
			if lowerKey != "host" && lowerKey != "authorization" && lowerKey != "referer" {
				for _, value := range values {
					req.Header.Add(headerKey, value)
				}
			}
		}
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
