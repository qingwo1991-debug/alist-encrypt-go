package encrypt

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

func parseRangeStart(rangeHeader string) (int64, bool) {
	raw := strings.TrimSpace(rangeHeader)
	if raw == "" || !strings.HasPrefix(raw, "bytes=") {
		return 0, false
	}
	parts := strings.SplitN(strings.TrimPrefix(raw, "bytes="), "-", 2)
	if len(parts) == 0 {
		return 0, false
	}
	startText := strings.TrimSpace(parts[0])
	if startText == "" {
		return 0, false
	}
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start < 0 {
		return 0, false
	}
	return start, true
}

// copyWithAdaptiveBuffer 根据文件大小自适应选择缓冲区
func copyWithAdaptiveBuffer(dst io.Writer, src io.Reader, fileSize int64) (int64, error) {
	if fileSize <= 0 || fileSize > 10*1024*1024 { // 未知大小或大于 10MB
		return copyWithBuffer(dst, src)
	} else if fileSize > 1024*1024 { // 1MB - 10MB
		bufPtr := mediumBufferPool.Get().(*[]byte)
		defer mediumBufferPool.Put(bufPtr)
		return io.CopyBuffer(dst, src, *bufPtr)
	} else { // 小于 1MB
		return copyWithSmallBuffer(dst, src)
	}
}

// handleRedirect 处理重定向下载（V2 orchestrator 入口）
func (p *ProxyServer) handleRedirect(w http.ResponseWriter, r *http.Request) {
	if p != nil && p.streamEngineV2Enabled() {
		newPlayOrchestrator(p).ServePlayback(w, r)
		return
	}
	p.handleRedirectLegacy(w, r)
}

// handleDownload 处理下载请求（V2 orchestrator 入口）
func (p *ProxyServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	if p != nil && p.streamEngineV2Enabled() {
		newPlayOrchestrator(p).ServePlayback(w, r)
		return
	}
	p.handleDownloadLegacy(w, r)
}

// handleDownloadLegacy 保留历史执行链，供 V2 orchestrator 调用
func (p *ProxyServer) handleDownloadLegacy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if p.shouldFastFailUpstream() {
		_, remain, reason := p.upstreamBackoffState()
		retryAfter := int(remain.Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		http.Error(w, "upstream temporarily unavailable: "+reason, http.StatusServiceUnavailable)
		return
	}
	originalPath := r.URL.Path
	filePath := originalPath

	// 移除 /d/ 或 /p/ 前缀
	if strings.HasPrefix(filePath, "/d/") {
		filePath = strings.TrimPrefix(filePath, "/d/")
	} else if strings.HasPrefix(filePath, "/p/") {
		filePath = strings.TrimPrefix(filePath, "/p/")
	}
	filePath = "/" + filePath
	clientRangeHeader := r.Header.Get("Range")

	// 检查是否需要解密
	encPath := p.findEncryptPath(filePath)

	// 构建实际请求的 URL 路径
	actualURLPath := originalPath
	convertedURLPath := false
	noSuffixURLPath := ""
	convertedNoSuffixURLPath := false
	mappedRealPath := ""

	// 如果开启了文件名加密，转换为真实加密名
	if encPath != nil && encPath.EncName {
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			if cachedRealName, ok := GetCachedRealName(path.Dir(filePath), fileName); ok {
				mappedRealPath = path.Join(path.Dir(filePath), cachedRealName)
				p.debugf("playback", "download mapping hit display=%s real=%s", filePath, mappedRealPath)
			}

			newFilePath := mappedRealPath
			if strings.TrimSpace(newFilePath) == "" {
				realName := convertRealNameByRule(encPath, filePath)
				newFilePath = path.Join(path.Dir(filePath), realName)
			}
			if strings.HasPrefix(originalPath, "/d/") {
				actualURLPath = "/d" + newFilePath
			} else {
				actualURLPath = "/p" + newFilePath
			}
			convertedURLPath = actualURLPath != originalPath
			if encPath.EncSuffix != "" {
				noSuffixRealName := ConvertRealNameWithSuffix(encPath.Password, encPath.EncType, filePath, "")
				noSuffixFilePath := path.Join(path.Dir(filePath), noSuffixRealName)
				if strings.HasPrefix(originalPath, "/d/") {
					noSuffixURLPath = "/d" + noSuffixFilePath
				} else {
					noSuffixURLPath = "/p" + noSuffixFilePath
				}
				convertedNoSuffixURLPath = noSuffixURLPath != originalPath && noSuffixURLPath != actualURLPath
			}
		}
	}

	// 获取文件大小 - 首先尝试从缓存获取（使用带 TTL 的缓存方法）
	var fileSize int64 = 0
	cachedRawURL := ""
	if cached, ok := p.loadFileCache(filePath); ok {
		if !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
		}
		cachedRawURL = strings.TrimSpace(cached.RawURL)
		log.Debugf("%s handleDownload: got fileSize from cache: %d for path: %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, filePath)
	}
	if fileSize == 0 && encPath != nil && encPath.EncName {
		encPathFull := mappedRealPath
		if strings.TrimSpace(encPathFull) == "" {
			realName := convertRealNameByRule(encPath, filePath)
			encPathFull = path.Join(path.Dir(filePath), realName)
		}
		if !strings.HasPrefix(encPathFull, "/") {
			encPathFull = "/" + encPathFull
		}
		if cached, ok := p.loadFileCache(encPathFull); ok && !cached.IsDir && cached.Size > 0 {
			fileSize = cached.Size
			log.Debugf("%s handleDownload: got fileSize from enc cache: %d for path: %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, encPathFull)
		}
	}
	if fileSize == 0 {
		if size, ok := p.lookupLocalSize(p.getAlistURL()+actualURLPath, filePath); ok {
			fileSize = size
			log.Debugf("%s handleDownload: got fileSize from local store: %d for path: %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, filePath)
		}
	}

	type downloadAttempt struct {
		urlPath   string
		fullURL   string
		sendRange bool
		stage     string
	}
	buildDownloadRequest := func(urlPath, fullURL string, sendRange bool) (*http.Request, error) {
		targetURL := fullURL
		if strings.TrimSpace(targetURL) == "" {
			targetURL = p.getAlistURL() + urlPath
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, nil)
		if err != nil {
			return nil, err
		}
		for key, values := range r.Header {
			if key != "Host" {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
		}
		if clientRangeHeader != "" {
			if sendRange {
				rangeHeader := clientRangeHeader
				if encPath != nil {
					meta := p.inspectEncryptedContent(r.Context(), targetURL, req.Header, encPath, fileSize)
					rangeHeader = buildUpstreamRangeHeader(clientRangeHeader, meta)
				}
				req.Header.Set("Range", rangeHeader)
			} else {
				req.Header.Del("Range")
			}
		}
		return req, nil
	}
	shouldSendRangeForPath := func(urlPath string) bool {
		if clientRangeHeader == "" {
			return false
		}
		targetURL := p.getAlistURL() + urlPath
		if p.shouldSkipRange(targetURL, filePath) {
			return false
		}
		return true
	}

	attempts := make([]downloadAttempt, 0, 6)
	addAttempt := func(urlPath, fullURL string, sendRange bool, stage string) {
		for _, a := range attempts {
			if a.urlPath == urlPath && a.fullURL == fullURL && a.sendRange == sendRange {
				return
			}
		}
		attempts = append(attempts, downloadAttempt{urlPath: urlPath, fullURL: fullURL, sendRange: sendRange, stage: stage})
	}
	initialURLPath := actualURLPath
	primaryRange := shouldSendRangeForPath(actualURLPath)
	if cachedRawURL != "" {
		addAttempt(actualURLPath, cachedRawURL, false, "cached-raw-url")
	}
	addAttempt(actualURLPath, "", primaryRange, "primary")
	if convertedNoSuffixURLPath && encPath != nil && encPath.EncName {
		addAttempt(noSuffixURLPath, "", shouldSendRangeForPath(noSuffixURLPath), "fallback-encrypted-no-suffix")
	}
	if convertedURLPath && encPath != nil && encPath.EncName {
		addAttempt(originalPath, "", shouldSendRangeForPath(originalPath), "fallback-original-path")
	}
	if clientRangeHeader != "" {
		addAttempt(actualURLPath, "", !primaryRange, "fallback-toggle-range")
		if convertedNoSuffixURLPath && encPath != nil && encPath.EncName {
			addAttempt(noSuffixURLPath, "", !shouldSendRangeForPath(noSuffixURLPath), "fallback-encrypted-no-suffix-toggle-range")
		}
		if convertedURLPath && encPath != nil && encPath.EncName {
			addAttempt(originalPath, "", !shouldSendRangeForPath(originalPath), "fallback-original-toggle-range")
		}
	}
	p.debugf("playback", "download attempts path=%s range=%q count=%d", filePath, clientRangeHeader, len(attempts))

	client := p.httpClient
	if r.Method == http.MethodGet {
		client = p.streamClient
	}
	retryableStatus := map[int]bool{
		http.StatusBadRequest:                   true,
		http.StatusNotFound:                     true,
		http.StatusRequestedRangeNotSatisfiable: true,
	}
	var req *http.Request
	var resp *http.Response
	var err error
	var selectedAttempt downloadAttempt
	for i, attempt := range attempts {
		p.debugf("playback", "download attempt=%d stage=%s path=%s sendRange=%v", i+1, attempt.stage, attempt.urlPath, attempt.sendRange)
		req, err = buildDownloadRequest(attempt.urlPath, attempt.fullURL, attempt.sendRange)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		resp, err = client.Do(req)
		if err != nil {
			if i < len(attempts)-1 {
				p.debugf("download", "request attempt failed stage=%s path=%s err=%v", attempt.stage, attempt.urlPath, err)
				continue
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		selectedAttempt = attempt
		if retryableStatus[resp.StatusCode] && i < len(attempts)-1 {
			p.debugf("download", "retryable download response stage=%s path=%s status=%d", attempt.stage, attempt.urlPath, resp.StatusCode)
			resp.Body.Close()
			resp = nil
			continue
		}
		break
	}
	if resp == nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()
	actualURLPath = selectedAttempt.urlPath
	p.debugf("playback", "download selected stage=%s path=%s status=%d", selectedAttempt.stage, actualURLPath, resp.StatusCode)
	if selectedAttempt.stage == "fallback-original-path" || selectedAttempt.stage == "fallback-original-toggle-range" {
		p.debugf("filename", "download fallback to original path=%s from=%s", originalPath, initialURLPath)
	}

	// 处理 302/303 重定向：对于需要解密的路径，创建代理重定向
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		log.Infof("%s handleDownload backend redirect: path=%s statusCode=%d location=%s",
			internal.LogPrefix(ctx, internal.TagDownload), filePath, resp.StatusCode, location)

		if encPath != nil && encPath.Enable && location != "" {
			driver := p.inferDriverFromPath(ctx, filePath, r.Header)
			p.noteDriverCandidate(driver)
			// 对于需要解密的 GET 请求，创建代理重定向
			// 生成唯一的重定向 key
			redirectKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), path.Base(filePath))

			// 缓存重定向信息
			redirectInfo := &RedirectInfo{
				RedirectURL:   location,
				PasswdInfo:    encPath,
				FileSize:      fileSize,
				OriginalURL:   r.URL.String(),
				EncryptedPath: actualURLPath,
				Headers:       r.Header.Clone(),
				Driver:        driver,
			}
			p.storeRedirectCache(redirectKey, redirectInfo)

			// 构建代理重定向 URL
			proxyLocation := fmt.Sprintf("/redirect/%s?decode=1&lastUrl=%s",
				redirectKey, url.QueryEscape(r.URL.Path))

			log.Infof("%s handleDownload proxy redirect: path=%s, original=%s, proxy=%s, fileSize=%d",
				internal.LogPrefix(ctx, internal.TagDownload), filePath, location, proxyLocation, fileSize)

			// 复制响应头（排除 Location）
			for key, values := range resp.Header {
				if strings.ToLower(key) == "location" {
					continue
				}
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			// 返回修改后的重定向响应
			w.Header().Set("Location", proxyLocation)
			w.WriteHeader(resp.StatusCode)
			copyWithBuffer(w, resp.Body)
			return
		}

		// 对于不需要解密的请求，直接透传重定向
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		copyWithBuffer(w, resp.Body)
		return
	}

	// 如果缓存中没有文件大小，尝试从响应头获取；如果仍然未知，探测远程总大小（HEAD 或 Range=0-0）
	if fileSize == 0 && encPath != nil {
		// Range 请求下 Content-Length 只是分片大小，不能用作总大小
		if clientRangeHeader == "" {
			if cl := resp.Header.Get("Content-Length"); cl != "" {
				if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
					fileSize = size
					log.Infof("%s handleDownload: got fileSize from Content-Length: %d for path: %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, filePath)
				}
			}
		}
		// 尝试从 Content-Range 获取总大小 (格式: bytes start-end/total)
		if fileSize == 0 {
			if cr := resp.Header.Get("Content-Range"); cr != "" {
				// Content-Range: bytes 0-1023/10240
				if idx := strings.LastIndex(cr, "/"); idx != -1 {
					totalStr := cr[idx+1:]
					if totalStr != "*" {
						if total, err := strconv.ParseInt(totalStr, 10, 64); err == nil && total > 0 {
							fileSize = total
							log.Infof("%s handleDownload: got fileSize from Content-Range: %d for path: %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, filePath)
						}
					}
				}
			}
		}
		if fileSize == 0 {
			// 强制探测：加密文件没有 fileSize 无法解密
			probed := p.forceProbeRemoteFileSizeWithPath(p.getAlistURL()+actualURLPath, req.Header, encPath.Path)
			if probed > 0 {
				fileSize = probed
				log.Infof("%s handleDownload: probed remote fileSize=%d for path: %s", internal.LogPrefix(ctx, internal.TagFileSize), fileSize, filePath)
				// re-request resource to ensure fresh stream with streamClient
				resp.Body.Close()
				req2, reqErr := buildDownloadRequest(actualURLPath, selectedAttempt.fullURL, selectedAttempt.sendRange)
				if reqErr != nil {
					http.Error(w, reqErr.Error(), http.StatusInternalServerError)
					return
				}
				resp, err = p.streamClient.Do(req2)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
			}
		}
	}

	statusCode := resp.StatusCode
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Range") != "" {
		statusCode = http.StatusPartialContent
	}
	upstreamIsRange := resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != ""
	if clientRangeHeader != "" && selectedAttempt.sendRange {
		if upstreamIsRange {
			p.markRangeCompatible(p.getAlistURL()+actualURLPath, filePath)
		} else {
			p.markRangeIncompatible(p.getAlistURL()+actualURLPath, filePath)
		}
	}

	observedStrategy := StreamStrategyChunked
	if upstreamIsRange {
		observedStrategy = StreamStrategyRange
	}
	p.recordLocalObservation(p.getAlistURL()+actualURLPath, filePath, fileSize, resp.StatusCode, resp.Header.Get("Content-Type"), observedStrategy)

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// 下载时解密文件名（修改 Content-Disposition，与 alist-encrypt 一致）
	if encPath != nil && encPath.EncName && resp.StatusCode == http.StatusOK {
		fileName := path.Base(filePath)
		if decoded, err := url.PathUnescape(fileName); err == nil {
			fileName = decoded
		}
		ext := path.Ext(fileName)
		baseName := strings.TrimSuffix(fileName, ext)
		decryptedName := DecodeName(encPath.Password, encPath.EncType, baseName)
		if decryptedName != "" {
			// 清除旧的 filename 参数，设置解密后的文件名
			cd := w.Header().Get("Content-Disposition")
			// 移除现有的 filename 和 filename* 参数
			if cd != "" {
				// 简单的正则替换：移除 filename=xxx 或 filename*=xxx
				cd = regexp.MustCompile(`filename\*?=[^;]*;?\s*`).ReplaceAllString(cd, "")
			}
			if cd == "" {
				cd = "attachment; "
			} else if !strings.HasSuffix(cd, "; ") && !strings.HasSuffix(cd, ";") {
				cd += "; "
			}
			w.Header().Set("Content-Disposition", cd+fmt.Sprintf("filename*=UTF-8''%s", url.PathEscape(decryptedName)))
			log.Debugf("%s Decrypted filename in Content-Disposition: %s -> %s", internal.LogPrefix(ctx, internal.TagDecrypt), fileName, decryptedName)
		}
	}

	// 获取 Range 信息
	var startPos int64 = 0
	if parsedStart, ok := parseRangeStart(clientRangeHeader); ok {
		startPos = parsedStart
	}

	// 只有响应状态码是 2xx 时才尝试解密
	// 非 2xx 状态码（如 4xx、5xx 错误）直接透传，不尝试解密
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Debugf("%s handleDownload: non-2xx response: status=%d, skip decryption", internal.LogPrefix(ctx, internal.TagDownload), resp.StatusCode)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
		return
	}

	// 如果需要解密
	if encPath != nil && fileSize > 0 {
		log.Infof("%s handleDownload: decrypting with fileSize=%d for path: %s", internal.LogPrefix(ctx, internal.TagDecrypt), fileSize, filePath)
		targetForMeta := selectedAttempt.fullURL
		if strings.TrimSpace(targetForMeta) == "" {
			targetForMeta = p.getAlistURL() + actualURLPath
		}
		meta := LegacyContentMeta(EncryptionType(encPath.EncType), fileSize)
		if cached, ok := p.loadFileCache(filePath); ok && cached != nil && cached.ContentVersion == ContentVersionV2 && len(cached.NonceField) == 16 {
			meta = ContentMeta{
				EncType:        EncryptionType(encPath.EncType),
				Version:        cached.ContentVersion,
				HeaderLen:      cached.HeaderLen,
				PlainSize:      cached.Size,
				CiphertextSize: cached.CiphertextSize,
				NonceField:     cloneNonceField(cached.NonceField),
			}
		} else {
			encProbePath := actualURLPath
			if strings.HasPrefix(encProbePath, "/d") {
				encProbePath = strings.TrimPrefix(encProbePath, "/d")
			}
			meta = p.inspectEncryptedContentWithFallback(ctx, targetForMeta, req.Header, encPath, fileSize, encProbePath)
		}
		originalSize := fileSize
		fileSize = normalizePlainFileSize(fileSize, &meta, resp.Header.Get("Content-Range"))
		if meta.IsV2() {
			p.storeFileCache(filePath, &FileInfo{
				Name:           path.Base(filePath),
				Size:           meta.PlainSize,
				CiphertextSize: meta.TotalCiphertextSize(),
				ContentVersion: meta.Version,
				HeaderLen:      meta.HeaderLen,
				NonceField:     cloneNonceField(meta.NonceField),
				IsDir:          false,
				Path:           filePath,
				RawURL:         targetForMeta,
			})
			log.Infof("%s handleDownload: v2 meta target=%s clientRange=%q headerLen=%d cipherSize=%d plainSize=%d fileSize=%d->%d",
				internal.LogPrefix(ctx, internal.TagDecrypt), targetForMeta, clientRangeHeader, meta.HeaderLen, meta.CiphertextSize, meta.PlainSize, originalSize, fileSize)
		}

		var encryptor FlowEncryptor
		if meta.IsV2() {
			encryptor, err = NewCipherV2(EncryptionType(encPath.EncType), encPath.Password, fileSize, meta.NonceField)
		} else {
			encryptor, err = NewFlowEncryptor(encPath.Password, encPath.EncType, fileSize)
		}
		if err != nil {
			log.Errorf("%s handleDownload: failed to create encryptor: %v", internal.LogPrefix(ctx, internal.TagDecrypt), err)
			if p.config != nil && p.config.PlayFirstFallback {
				atomic.AddUint64(&p.playFirstCount, 1)
				w.WriteHeader(statusCode)
				copyWithBuffer(w, resp.Body)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if startPos > 0 {
			if upstreamIsRange {
				encryptor.SetPosition(startPos)
			} else {
				if startPos > p.rangeSkipMaxBytes() {
					log.Warnf("%s handleDownload: skip exceeds limit start=%d limit=%d upstreamRange=%v status=%d contentRange=%q path=%s",
						internal.LogPrefix(ctx, internal.TagDecrypt), startPos, p.rangeSkipMaxBytes(), upstreamIsRange, resp.StatusCode, resp.Header.Get("Content-Range"), filePath)
					http.Error(w, "range skip exceeds limit", http.StatusRequestedRangeNotSatisfiable)
					return
				}
				discardLen := startPos
				if meta.IsV2() {
					discardLen += meta.HeaderLen
				}
				if _, err := io.CopyN(io.Discard, resp.Body, discardLen); err != nil {
					log.Warnf("%s handleDownload: skip encrypted prefix failed: %v", internal.LogPrefix(ctx, internal.TagDecrypt), err)
				}
				encryptor.SetPosition(startPos)
			}
		} else if meta.IsV2() && !upstreamIsRange {
			if err := discardBytes(resp.Body, meta.HeaderLen); err != nil {
				log.Warnf("%s handleDownload: discard v2 header failed: %v", internal.LogPrefix(ctx, internal.TagDecrypt), err)
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
		}

		if meta.IsV2() && upstreamIsRange && selectedAttempt.sendRange {
			if clientRangeHeader != "" {
				if _, end, ok := parseRange(clientRangeHeader, fileSize); ok {
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", startPos, end, fileSize))
					w.Header().Set("Content-Length", strconv.FormatInt(end-startPos+1, 10))
				}
			}
		}
		decryptReader := NewDecryptReader(resp.Body, encryptor)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, decryptReader)
	} else if encPath != nil && fileSize == 0 {
		// fileSize 为 0 时无法正确解密（因为 fileSize 参与密钥生成）
		// 直接透传原始数据，让客户端知道这是加密的文件
		log.Warnf("%s handleDownload: cannot decrypt, fileSize is 0 for encrypted path: %s. Passing through raw data.", internal.LogPrefix(ctx, internal.TagDownload), filePath)
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
	} else {
		w.WriteHeader(statusCode)
		copyWithBuffer(w, resp.Body)
	}
}
