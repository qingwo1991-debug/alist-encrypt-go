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

func parseRange(header string, size int64) (start, end int64, hasRange bool) {
	if header == "" || !strings.HasPrefix(header, "bytes=") {
		return 0, 0, false
	}
	parts := strings.Split(strings.TrimPrefix(header, "bytes="), "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	sStr := strings.TrimSpace(parts[0])
	eStr := strings.TrimSpace(parts[1])

	start = 0
	if sStr != "" {
		if v, err := strconv.ParseInt(sStr, 10, 64); err == nil {
			start = v
		}
	}
	end = size - 1
	if eStr != "" {
		if v, err := strconv.ParseInt(eStr, 10, 64); err == nil {
			end = v
		}
	}
	if start < 0 {
		start = 0
	}
	if end >= size {
		end = size - 1
	}
	if start > end {
		return 0, 0, false
	}
	return start, end, true
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

func (o *PlayOrchestrator) resolveFileSize(ctx context.Context, r *http.Request, info *RedirectInfo) int64 {
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

	if info.OriginalURL != "" {
		origPath := info.OriginalURL
		if u, err := url.Parse(info.OriginalURL); err == nil {
			origPath = u.Path
		}
		pathVariants := []string{
			origPath,
			strings.TrimPrefix(origPath, "/dav"),
			"/dav" + strings.TrimPrefix(origPath, "/dav"),
		}
		for _, cachePath := range pathVariants {
			if cachePath == "" {
				continue
			}
			if cached, ok := p.loadFileCache(cachePath); ok && !cached.IsDir && cached.Size > 0 {
				fileSize = cached.Size
				break
			}
		}
	}
	if fileSize > 0 {
		return fileSize
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
		if size := p.fetchWebDAVFileSizeWithPath(webdavURL, info.Headers, info.PasswdInfo.Path); size > 0 {
			fileSize = size
		}
	}
	if fileSize > 0 {
		return fileSize
	}

	probed := p.forceProbeRemoteFileSizeWithPath(info.RedirectURL, r.Header, info.PasswdInfo.Path)
	if probed > 0 {
		fileSize = probed
	}

	return fileSize
}

func (o *PlayOrchestrator) proxyDownloadDecryptWithStrategy(
	w http.ResponseWriter,
	r *http.Request,
	info *RedirectInfo,
	fileSize int64,
	strategy StreamStrategy,
) *StreamOutcome {
	p := o.proxy
	ctx := r.Context()

	if p.shouldFastFailUpstream() {
		_, remain, reason := p.upstreamBackoffState()
		retryAfter := int(remain.Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		return &StreamOutcome{
			Err:           fmt.Errorf("upstream temporarily unavailable: %s", reason),
			FailureReason: "network_error",
			Retryable:     true,
			StatusCode:    http.StatusServiceUnavailable,
		}
	}

	clientRangeHeader := r.Header.Get("Range")
	upstreamRangeHeader := clientRangeHeader
	startPos, endPos, hasRange := parseRange(clientRangeHeader, fileSize)
	meta := LegacyContentMeta(EncryptionType(info.PasswdInfo.EncType), fileSize)
	if info.ContentVersion == ContentVersionV2 && len(info.NonceField) == 16 {
		meta = ContentMeta{
			EncType:        EncryptionType(info.PasswdInfo.EncType),
			Version:        info.ContentVersion,
			HeaderLen:      info.HeaderLen,
			PlainSize:      info.FileSize,
			CiphertextSize: info.CiphertextSize,
			NonceField:     cloneNonceField(info.NonceField),
		}
	}
	if decode := r.URL.Query().Get("decode"); decode != "0" && info.PasswdInfo != nil && (!meta.IsV2() || len(meta.NonceField) != 16) {
		meta = p.inspectEncryptedContentWithFallback(ctx, info.RedirectURL, r.Header, info.PasswdInfo, fileSize, info.EncryptedPath)
		if meta.IsV2() {
			if meta.PlainSize > 0 {
				fileSize = meta.PlainSize
			}
			if hasRange && strategy == StreamStrategyRange {
				upstreamRangeHeader = buildUpstreamRangeHeader(clientRangeHeader, meta)
			}
			log.Infof("V2 redirect meta: url=%s clientRange=%q upstreamRange=%q headerLen=%d cipherSize=%d plainSize=%d",
				info.RedirectURL, clientRangeHeader, upstreamRangeHeader, meta.HeaderLen, meta.CiphertextSize, meta.PlainSize)
		}
	}

	if hasRange {
		if strategy == StreamStrategyChunked || strategy == StreamStrategyFull {
			upstreamRangeHeader = ""
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", info.RedirectURL, nil)
	if err != nil {
		return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: false}
	}
	p.applyRoutingHints(req, info.Provider, info.Driver)

	// Copy headers
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

	if strings.Contains(info.RedirectURL, "baidupcs.com") {
		req.Header.Set("User-Agent", "pan.baidu.com")
	}

	resp, err := p.streamClient.Do(req)
	if err != nil {
		p.markUpstreamFailure(err)
		return &StreamOutcome{
			Err:           err,
			FailureReason: "network_error",
			Retryable:     true,
		}
	}
	defer resp.Body.Close()
	p.markUpstreamSuccess()

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}
	upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
	log.Infof("V2 redirect attempt: url=%s strategy=%s range=%q upstreamStatus=%d contentRange=%q contentLength=%q fileSize=%d",
		info.RedirectURL, strategy, clientRangeHeader, resp.StatusCode, resp.Header.Get("Content-Range"), resp.Header.Get("Content-Length"), fileSize)
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
		log.Infof("V2 redirect normalized size: url=%s contentRange=%q fileSize=%d->%d cipherSize=%d plainSize=%d",
			info.RedirectURL, resp.Header.Get("Content-Range"), originalSize, fileSize, meta.CiphertextSize, meta.PlainSize)
	}
	startPos, endPos, hasRange = parseRange(clientRangeHeader, fileSize)

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
	upstreamShiftedRange := meta.IsV2() && strategy == StreamStrategyRange && buildUpstreamRangeHeader(clientRangeHeader, meta) != clientRangeHeader

	if clientRangeHeader != "" {
		if strategy == StreamStrategyRange {
			if startPos > 0 {
				encryptor.SetPosition(startPos)
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
			if startPos > 0 {
				if _, err := io.CopyN(io.Discard, resp.Body, startPos); err != nil {
					return &StreamOutcome{
						Err:           err,
						FailureReason: "stream_error",
						Retryable:     true,
					}
				}
			}
			encryptor.SetPosition(startPos)
			length := endPos - startPos + 1
			readerToStream = io.LimitReader(resp.Body, length)
			statusCode = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, endPos, fileSize))
			w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		} else if strategy == StreamStrategyFull {
			if startPos > 0 {
				if _, err := io.CopyN(io.Discard, resp.Body, startPos); err != nil {
					return &StreamOutcome{
						Err:           err,
						FailureReason: "stream_error",
						Retryable:     true,
					}
				}
			}
			encryptor.SetPosition(startPos)
			length := fileSize - startPos
			statusCode = http.StatusPartialContent
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, fileSize-1, fileSize))
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

	if meta.IsV2() && !(upstreamShiftedRange && upstreamIsRange) {
		if err := discardBytes(readerToStream, meta.HeaderLen); err != nil {
			return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true}
		}
	}

	decryptReader := NewDecryptReader(readerToStream, encryptor)
	w.WriteHeader(statusCode)

	written, err := copyWithBuffer(w, decryptReader)
	if err != nil {
		log.Warnf("V2 redirect stream copy failed: url=%s strategy=%s written=%d ctxErr=%v err=%v",
			info.RedirectURL, strategy, written, r.Context().Err(), err)
		return &StreamOutcome{Err: err, FailureReason: "stream_error", Retryable: true, ResponseStarted: true}
	}
	log.Infof("V2 redirect stream copy complete: url=%s strategy=%s written=%d status=%d",
		info.RedirectURL, strategy, written, statusCode)

	return &StreamOutcome{StatusCode: statusCode}
}

func (o *PlayOrchestrator) ServeRedirect(w http.ResponseWriter, r *http.Request) {
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

	fileSize := o.resolveFileSize(r.Context(), r, info)
	log.Infof("V2 redirect resolve: key=%s original=%s redirect=%s size=%d range=%q", key, info.OriginalURL, info.RedirectURL, fileSize, r.Header.Get("Range"))
	if fileSize == 0 {
		log.Warnf("V2 play: fileSize is 0, skipping decryption and proxying raw stream")
		req, _ := http.NewRequestWithContext(r.Context(), "GET", info.RedirectURL, nil)
		o.proxy.applyRoutingHints(req, info.Provider, info.Driver)
		for key, values := range r.Header {
			if strings.ToLower(key) != "host" {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}
		resp, err := o.proxy.streamClient.Do(req)
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
		_, _ = copyWithBuffer(w, resp.Body)
		return
	}

	provider := info.Provider
	if provider == "" {
		provider = ProviderKey(info.RedirectURL, "")
	}

	strategies := o.proxy.strategySelector.Select(provider)

	firstFrameHint := isFirstFrameRangeHint(r.Method, r.Header.Get("Range"))

	tryStrategy := func(strategy StreamStrategy) *StreamOutcome {
		outcome := o.proxyDownloadDecryptWithStrategy(w, r, info, fileSize, strategy)
		if outcome != nil && outcome.Err != nil {
			log.Warnf("V2 redirect strategy failed: key=%s strategy=%s reason=%s retryable=%v responseStarted=%v err=%v",
				key, strategy, outcome.FailureReason, outcome.Retryable, outcome.ResponseStarted, outcome.Err)
		}
		if outcome.Err == nil && !outcome.Retryable {
			o.proxy.strategySelector.RecordSuccess(provider, strategy)
			return outcome
		}
		if !outcome.ResponseStarted && outcome.Retryable {
			o.proxy.strategySelector.RecordFailure(provider, strategy, outcome.FailureReason)
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

	if outcome != nil && !outcome.ResponseStarted && o.proxy.config != nil && o.proxy.config.PlayFirstFallback {
		log.Warnf("V2 play: all strategies failed, playing raw stream as final fallback")
		req, _ := http.NewRequestWithContext(r.Context(), "GET", info.RedirectURL, nil)
		o.proxy.applyRoutingHints(req, info.Provider, info.Driver)
		for key, values := range r.Header {
			if strings.ToLower(key) != "host" {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}
		resp, err := o.proxy.streamClient.Do(req)
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
		_, _ = copyWithBuffer(w, resp.Body)
		return
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
