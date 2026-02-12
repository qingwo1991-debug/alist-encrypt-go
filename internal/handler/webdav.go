package handler

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/trace"
)

// WebDAVHandler handles WebDAV requests
type WebDAVHandler struct {
	cfg           *config.Config
	streamProxy   *proxy.StreamProxy
	fileDAO       *dao.FileDAO
	passwdDAO     *dao.PasswdDAO
	proxyHandler  *ProxyHandler
	strategyCache *StrategyCache
	sizeResolver  *FileSizeResolver
	strategySel   *StrategySelector
	metaStore     FileMetaStore
	probe         *ProbeScheduler
}

// Stats returns WebDAV handler statistics
func (h *WebDAVHandler) Stats() map[string]interface{} {
	var selectorStats map[string]interface{}
	if h.strategySel != nil {
		selectorStats = h.strategySel.Stats()
	}
	return map[string]interface{}{
		"strategy_cache":    h.strategyCache.Stats(),
		"size_resolver":     h.sizeResolver.Stats(),
		"strategy_selector": selectorStats,
	}
}

// NewWebDAVHandler creates a new WebDAV handler
func NewWebDAVHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO, selector *StrategySelector, metaStore FileMetaStore) *WebDAVHandler {
	return &WebDAVHandler{
		cfg:           cfg,
		streamProxy:   streamProxy,
		fileDAO:       fileDAO,
		passwdDAO:     passwdDAO,
		proxyHandler:  NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, selector, metaStore),
		strategyCache: NewStrategyCache(1000),
		sizeResolver:  NewFileSizeResolver(fileDAO, metaStore, 20, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		strategySel:   selector,
		metaStore:     metaStore,
		probe:         nil,
	}
}

// Handle routes WebDAV requests
func (h *WebDAVHandler) Handle(w http.ResponseWriter, r *http.Request) {
	davPath := strings.TrimPrefix(r.URL.Path, "/dav")
	if davPath == "" {
		davPath = "/"
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		ctx := context.WithValue(r.Context(), "webdav-auth", auth)
		r = r.WithContext(ctx)
	}

	switch r.Method {
	case "GET", "HEAD":
		h.handleGet(w, r, davPath)
	case "PUT":
		h.handlePut(w, r, davPath)
	case "PROPFIND":
		h.handlePropfind(w, r, davPath)
	case "DELETE":
		h.handleDelete(w, r, davPath)
	case "MOVE":
		h.handleMove(w, r, davPath)
	case "COPY":
		h.handleCopy(w, r, davPath)
	case "MKCOL", "PROPPATCH", "LOCK", "UNLOCK", "OPTIONS":
		h.handlePassthrough(w, r)
	default:
		h.handlePassthrough(w, r)
	}
}

func (h *WebDAVHandler) SetProbeScheduler(probe *ProbeScheduler) {
	h.probe = probe
}

// convertToRealPath converts display path to encrypted path for WebDAV
func (h *WebDAVHandler) convertToRealPath(davPath string, passwdInfo *config.PasswdInfo) string {
	if passwdInfo == nil || !passwdInfo.EncName {
		return davPath
	}

	// First try to get cached encrypted path
	if encPath, ok := h.fileDAO.GetEncPath(davPath); ok {
		return encPath
	}

	// Fallback: re-encrypt
	fileName := path.Base(davPath)
	if encryption.IsOriginalFile(fileName) {
		realName := encryption.StripOriginalPrefix(fileName)
		return path.Dir(davPath) + "/" + realName
	}

	converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
	realName := converter.ToRealName(fileName)
	return path.Dir(davPath) + "/" + realName
}

// handleGet handles GET requests with decryption
func (h *WebDAVHandler) handleGet(w http.ResponseWriter, r *http.Request, davPath string) {
	trace.Logf(r.Context(), "webdav-get", "Processing: %s", davPath)

	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found {
		trace.Logf(r.Context(), "webdav-get", "No encryption, passthrough")
		h.handlePassthrough(w, r)
		return
	}

	// Convert display path to real encrypted path
	realPath := h.convertToRealPath(davPath, passwdInfo)
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	trace.Logf(r.Context(), "webdav-get", "Path converted: %s -> %s", davPath, realPath)

	// Look up file info using DISPLAY path (davPath), not realPath
	// PROPFIND caches entries by display path after decrypting filenames
	fileSize, usedStrategy := h.getFileSizeWithStrategy(davPath, realPath, targetURL, r)

	trace.Logf(r.Context(), "webdav-get", "File size: %d, strategy: %s", fileSize, usedStrategy)
	fileItem := FileItem{
		DisplayPath:   davPath,
		EncryptedPath: realPath,
		TargetURL:     targetURL,
		FileName:      path.Base(davPath),
	}
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}
	if fileSize == 0 {
		if h.sizeResolver != nil {
			fresh := h.sizeResolver.ResolveSingleFresh(r.Context(), fileItem, authHeaders)
			if fresh.Error == nil && fresh.Size > 0 {
				fileSize = fresh.Size
			}
		}
	}
	if fileSize == 0 {
		trace.Logf(r.Context(), "webdav-get", "Size unknown, passthrough")
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
			log.Error().Err(err).Str("path", davPath).Msg("WebDAV passthrough failed")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	trace.Logf(r.Context(), "webdav-get", "Proxying with decryption, target=%s", targetURL)
	providerKey := ProviderKey(targetURL, davPath)
	strategies := []proxy.StreamStrategy{proxy.StreamStrategyRange}
	if h.strategySel != nil {
		strategies = h.strategySel.Select(providerKey)
	}

	tryStream := func(size int64) (bool, bool, string, error) {
		var lastErr error
		var lastFailure string
		var responseStarted bool

		for _, strategy := range strategies {
			attemptReq, err := httputil.NewRequest(r.Method, targetURL).
				WithContext(r.Context()).
				WithBodyReader(r.Body).
				CopyHeaders(r).
				Build()
			if err != nil {
				RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
				return false, true, "internal_error", err
			}

			result := h.streamProxy.ProxyDownloadDecryptReqWithStrategy(w, attemptReq, targetURL, passwdInfo, size, strategy)
			if result.Err == nil && !result.Retryable {
				if h.strategySel != nil {
					h.strategySel.RecordSuccess(providerKey, strategy)
				}
				if h.sizeResolver != nil && r.Method == http.MethodGet {
					metaSize := size
					if result.ExpectedBytes > 0 {
						metaSize = result.ExpectedBytes
					}
					h.sizeResolver.RecordPlaybackSuccess(r.Context(), fileItem, metaSize, result.StatusCode, result.ContentType, result.ETag)
				}
				return true, result.ResponseStarted, "", nil
			}

			reason := result.FailureReason
			if reason == "" && result.Err != nil {
				reason = "stream_error"
			}
			if reason == "" {
				reason = "unknown"
			}
			if lastFailure == "" {
				lastFailure = reason
			}

			if h.strategySel != nil {
				if result.Retryable && !result.ResponseStarted {
					if isNonStrategyFailure(reason) {
						trace.Logf(r.Context(), "network-skip", "reason: %s, provider=%s, path=%s", reason, providerKey, davPath)
					} else {
						trace.Logf(r.Context(), "strategy-fallback", "reason: %s, strategy=%s, provider=%s, path=%s", reason, strategy, providerKey, davPath)
					}
				}
				h.strategySel.RecordFailure(providerKey, strategy, reason)
			}

			if result.Err != nil {
				lastErr = result.Err
			} else if result.Retryable {
				lastErr = fmt.Errorf("strategy %s failed", strategy)
			}
			responseStarted = responseStarted || result.ResponseStarted
			if result.ResponseStarted || !result.Retryable {
				if lastErr != nil {
					log.Error().Err(lastErr).Str("path", davPath).Msg("WebDAV GET decryption failed")
				}
				return false, responseStarted, lastFailure, lastErr
			}
		}
		return false, responseStarted, lastFailure, lastErr
	}

	success, responseStarted, lastFailure, lastErr := tryStream(fileSize)
	if success {
		return
	}

	if !responseStarted && h.sizeResolver != nil {
		fresh := h.sizeResolver.ResolveSingleFresh(r.Context(), fileItem, authHeaders)
		if fresh.Error == nil && fresh.Size > 0 {
			if fileSize > 0 && fresh.Size != fileSize {
				h.sizeResolver.RecordMetaConflict(providerKey)
			}
			fileSize = fresh.Size
			success, responseStarted, lastFailure, lastErr = tryStream(fileSize)
			if success {
				return
			}
		}
	}

	if lastFailure == "range_unsatisfiable" {
		RespondHTTPErrorWithStatus(w, "Range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if lastErr != nil {
		log.Error().Err(lastErr).Str("path", davPath).Msg("WebDAV GET decryption failed")
		RespondHTTPErrorWithStatus(w, "Decryption error", http.StatusBadGateway)
	}
}

// handlePut handles PUT requests with encryption and filename encryption
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, davPath string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found {
		h.handlePassthrough(w, r)
		return
	}

	fileSize, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)

	// Convert display path to real encrypted path
	realPath := davPath
	if passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileName := path.Base(davPath)
		ext := passwdInfo.EncSuffix
		if ext == "" {
			ext = path.Ext(fileName)
		}
		encName := converter.EncryptFileName(strings.TrimSuffix(fileName, path.Ext(fileName)))
		realPath = path.Dir(davPath) + "/" + encName + ext

		// Cache file info for subsequent PROPFIND (like alist-encrypt does)
		h.fileDAO.Set(&dao.FileInfo{
			Path:  davPath,
			Name:  fileName,
			Size:  fileSize,
			IsDir: false,
		})
		log.Debug().Str("original", davPath).Str("encrypted", realPath).Msg("WebDAV PUT filename encrypted")
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", davPath).Msg("WebDAV PUT encryption failed")
		RespondHTTPErrorWithStatus(w, "Encryption error", http.StatusBadGateway)
	}
}

// handleDelete handles DELETE requests with filename encryption
func (h *WebDAVHandler) handleDelete(w http.ResponseWriter, r *http.Request, davPath string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found || !passwdInfo.EncName {
		h.handlePassthrough(w, r)
		return
	}

	// Convert display path to real encrypted path
	realPath := h.convertToRealPath(davPath, passwdInfo)
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

	proxyReq, err := httputil.NewRequest("DELETE", targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	client := &http.Client{Timeout: getAlistRequestTimeout(h.cfg)}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV DELETE failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleMove handles MOVE requests with filename encryption
func (h *WebDAVHandler) handleMove(w http.ResponseWriter, r *http.Request, davPath string) {
	h.handleMoveOrCopy(w, r, davPath, "MOVE")
}

// handleCopy handles COPY requests with filename encryption
func (h *WebDAVHandler) handleCopy(w http.ResponseWriter, r *http.Request, davPath string) {
	h.handleMoveOrCopy(w, r, davPath, "COPY")
}

// handleMoveOrCopy handles MOVE/COPY requests with filename encryption
func (h *WebDAVHandler) handleMoveOrCopy(w http.ResponseWriter, r *http.Request, davPath string, method string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)

	// Convert source path
	realSrcPath := davPath
	if found && passwdInfo.EncName {
		realSrcPath = h.convertToRealPath(davPath, passwdInfo)
	}

	// Convert destination path from header
	destination := r.Header.Get("Destination")
	if destination != "" {
		destURL, err := url.Parse(destination)
		if err == nil {
			destPath := strings.TrimPrefix(destURL.Path, "/dav")
			destPasswd, destFound := h.passwdDAO.FindByPath(destPath)
			if destFound && destPasswd.EncName {
				converter := encryption.NewFileNameConverter(destPasswd.Password, destPasswd.EncType, destPasswd.EncSuffix)
				fileName := path.Base(destPath)
				ext := destPasswd.EncSuffix
				if ext == "" {
					ext = path.Ext(fileName)
				}
				encName := converter.EncryptFileName(strings.TrimSuffix(fileName, path.Ext(fileName)))
				realDestPath := path.Dir(destPath) + "/" + encName + ext

				// Rebuild destination URL
				destURL.Path = "/dav" + realDestPath
				destination = destURL.String()
			}
		}
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realSrcPath, r)

	body, _ := io.ReadAll(r.Body)
	proxyReq, err := httputil.NewRequest(method, targetURL).
		WithContext(r.Context()).
		WithBody(body).
		CopyHeadersExcept(r, "Destination").
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if destination != "" {
		proxyReq.Header.Set("Destination", destination)
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msgf("WebDAV %s failed", method)
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handlePropfind handles PROPFIND requests - follows OpenList-Encrypt logic:
// 1. First try without path conversion (for directory listing)
// 2. If 404, retry with encrypted filename (for file metadata)
// 3. Decrypt filenames in response
func (h *WebDAVHandler) handlePropfind(w http.ResponseWriter, r *http.Request, davPath string) {
	trace.Logf(r.Context(), "propfind", "Listing: %s", davPath)

	passwdInfo, found := h.passwdDAO.FindByPath(davPath)

	// Read request body (need to buffer for possible retry)
	body, _ := io.ReadAll(r.Body)

	// Determine the actual path to request from Alist
	// For files with encrypted names, use cached encrypted path
	requestPath := davPath
	if found && passwdInfo.EncName {
		if encPath, ok := h.fileDAO.GetEncPath(davPath); ok {
			requestPath = encPath
			trace.Logf(r.Context(), "propfind", "Using cached enc path: %s -> %s", davPath, requestPath)
		}
	}

	// Step 1: Request Alist with the determined path
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+requestPath, r)

	proxyReq, err := httputil.NewRequest("PROPFIND", targetURL).
		WithContext(r.Context()).
		WithBody(body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV PROPFIND failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}

	trace.Logf(r.Context(), "propfind", "Alist response: status=%d", resp.StatusCode)

	// Step 2: If 404 and encryption enabled, retry with encrypted filename
	if resp.StatusCode == http.StatusNotFound && found && passwdInfo.EncName {
		resp.Body.Close()

		fileName := path.Base(davPath)
		if fileName != "" && fileName != "/" && fileName != "." {
			// Convert to encrypted path and retry
			realPath := h.convertToRealPath(davPath, passwdInfo)
			retryURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+realPath, r)

			trace.Logf(r.Context(), "propfind", "404 retry: %s -> %s", davPath, realPath)

			retryReq, err := httputil.NewRequest("PROPFIND", retryURL).
				WithContext(r.Context()).
				WithBody(body).
				CopyHeaders(r).
				Build()
			if err == nil {
				retryResp, err := client.Do(retryReq)
				if err == nil {
					resp = retryResp
				}
			}
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Step 3: Parse and cache file info from PROPFIND response
	h.parsePropfindResponse(r.Context(), respBody, davPath)

	// Step 4: Decrypt filenames in the XML response if encryption is enabled
	if found && passwdInfo.EncName && resp.StatusCode == http.StatusMultiStatus {
		respBody = h.decryptPropfindResponse(respBody, passwdInfo)
	}

	// Copy response headers (recalculate Content-Length since body may have changed)
	httputil.CopyResponseHeaders(w, resp, "Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handlePassthrough passes requests directly to Alist
func (h *WebDAVHandler) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)

	if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
		log.Error().Err(err).Str("method", r.Method).Msg("WebDAV passthrough failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
	}
}

// parsePropfindResponse parses WebDAV PROPFIND XML response and caches file info
func (h *WebDAVHandler) parsePropfindResponse(ctx context.Context, body []byte, basePath string) {
	type PropfindResponse struct {
		XMLName  xml.Name `xml:"multistatus"`
		Response []struct {
			Href string `xml:"href"`
			Prop struct {
				DisplayName   string `xml:"propstat>prop>displayname"`
				ContentLength int64  `xml:"propstat>prop>getcontentlength"`
				ResourceType  string `xml:"propstat>prop>resourcetype"`
				LastModified  string `xml:"propstat>prop>getlastmodified"`
			} `xml:"propstat>prop"`
		} `xml:"response"`
	}

	var propfind PropfindResponse
	if err := xml.Unmarshal(body, &propfind); err != nil {
		log.Debug().Err(err).Msg("Failed to parse PROPFIND response")
		return
	}

	for _, resp := range propfind.Response {
		// Extract path from href
		filePath := strings.TrimPrefix(resp.Href, "/dav")
		if filePath == "" {
			filePath = "/"
		}

		// URL decode the path
		if decoded, err := url.PathUnescape(filePath); err == nil {
			filePath = decoded
		}

		info := &dao.FileInfo{
			Path:  filePath,
			Name:  resp.Prop.DisplayName,
			Size:  resp.Prop.ContentLength,
			IsDir: strings.Contains(resp.Prop.ResourceType, "collection"),
		}

		h.fileDAO.Set(info)
		if !info.IsDir {
			if info.Size > 0 {
				h.upsertMetaFromListing(ctx, filePath, info.Size)
			}
			h.enqueueProbeFromPropfind(ctx, filePath, info.Size)
		}

		// Also cache without /dav prefix for compatibility
		if strings.HasPrefix(filePath, "/") {
			h.fileDAO.Set(&dao.FileInfo{
				Path:  filePath,
				Name:  info.Name,
				Size:  info.Size,
				IsDir: info.IsDir,
			})
		}
	}
}

func (h *WebDAVHandler) upsertMetaFromListing(ctx context.Context, displayPath string, size int64) {
	if h.metaStore == nil || size <= 0 {
		return
	}
	providerKey := ProviderKey(h.cfg.GetAlistURL(), displayPath)
	_ = h.metaStore.Upsert(ctx, FileMeta{
		ProviderKey:  providerKey,
		OriginalPath: displayPath,
		Size:         size,
		StatusCode:   0,
	})
}

func (h *WebDAVHandler) enqueueProbeFromPropfind(ctx context.Context, displayPath string, reportedSize int64) {
	if h.probe == nil {
		return
	}
	passwdInfo, found := h.passwdDAO.FindByPath(displayPath)
	if !found || passwdInfo == nil {
		return
	}
	realPath := displayPath
	if passwdInfo.EncName {
		realPath = h.convertToRealPath(displayPath, passwdInfo)
	}
	targetURL := h.cfg.GetAlistURL() + "/dav" + realPath
	file := FileItem{
		DisplayPath:   displayPath,
		EncryptedPath: realPath,
		TargetURL:     targetURL,
		FileName:      path.Base(displayPath),
	}
	authHeaders := make(http.Header)
	if auth := ctx.Value("webdav-auth"); auth != nil {
		if value, ok := auth.(string); ok && value != "" {
			authHeaders.Set("Authorization", value)
		}
	}
	h.probe.EnqueueWithSize(file, authHeaders, reportedSize)
}

// decryptPropfindResponse decrypts filenames in WebDAV PROPFIND XML response
func (h *WebDAVHandler) decryptPropfindResponse(body []byte, passwdInfo *config.PasswdInfo) []byte {
	result := string(body)

	// Decrypt displayname elements: <D:displayname>encryptedName.ext</D:displayname>
	// Match both <D:displayname> and <displayname> variants
	displayNamePatterns := []string{
		`<D:displayname>`, `</D:displayname>`,
		`<d:displayname>`, `</d:displayname>`,
		`<displayname>`, `</displayname>`,
	}

	for i := 0; i < len(displayNamePatterns); i += 2 {
		startTag := displayNamePatterns[i]
		endTag := displayNamePatterns[i+1]
		result = h.decryptXMLElements(result, startTag, endTag, passwdInfo)
	}

	// Decrypt href elements: <D:href>/dav/path/encryptedName.ext</D:href>
	hrefPatterns := []string{
		`<D:href>`, `</D:href>`,
		`<d:href>`, `</d:href>`,
		`<href>`, `</href>`,
	}

	for i := 0; i < len(hrefPatterns); i += 2 {
		startTag := hrefPatterns[i]
		endTag := hrefPatterns[i+1]
		result = h.decryptHrefElements(result, startTag, endTag, passwdInfo)
	}

	return []byte(result)
}

// decryptXMLElements decrypts content between XML tags (for displayname)
func (h *WebDAVHandler) decryptXMLElements(xmlStr, startTag, endTag string, passwdInfo *config.PasswdInfo) string {
	result := xmlStr
	searchPos := 0

	for {
		startIdx := strings.Index(result[searchPos:], startTag)
		if startIdx == -1 {
			break
		}
		startIdx += searchPos

		endIdx := strings.Index(result[startIdx:], endTag)
		if endIdx == -1 {
			break
		}
		endIdx += startIdx

		contentStart := startIdx + len(startTag)
		encryptedName := result[contentStart:endIdx]

		if encryptedName != "" && encryptedName != "/" {
			allowLoose := h.cfg != nil && h.cfg.AlistServer.AllowLooseDecode
			decryptedName := encryption.ConvertShowNameWithOptions(passwdInfo.Password, passwdInfo.EncType, encryptedName, allowLoose)
			if decryptedName != "" && decryptedName != encryptedName {
				result = result[:contentStart] + decryptedName + result[endIdx:]
				searchPos = contentStart + len(decryptedName) + len(endTag)
				continue
			}
		}
		searchPos = endIdx + len(endTag)
	}

	return result
}

// decryptHrefElements decrypts filenames in href paths
func (h *WebDAVHandler) decryptHrefElements(xmlStr, startTag, endTag string, passwdInfo *config.PasswdInfo) string {
	result := xmlStr
	searchPos := 0

	for {
		startIdx := strings.Index(result[searchPos:], startTag)
		if startIdx == -1 {
			break
		}
		startIdx += searchPos

		endIdx := strings.Index(result[startIdx:], endTag)
		if endIdx == -1 {
			break
		}
		endIdx += startIdx

		contentStart := startIdx + len(startTag)
		hrefValue := result[contentStart:endIdx]

		// Only process /dav/ paths
		if strings.HasPrefix(hrefValue, "/dav/") {
			davPath := strings.TrimPrefix(hrefValue, "/dav")
			// URL decode the path first (handles spaces, parentheses, etc.)
			decodedPath, err := url.PathUnescape(davPath)
			if err != nil {
				decodedPath = davPath // fallback to original if decode fails
			}
			if decodedPath != "/" && decodedPath != "" {
				// Get the filename from the decoded path
				fileName := path.Base(decodedPath)
				if fileName != "" && fileName != "/" && fileName != "." {
					allowLoose := h.cfg != nil && h.cfg.AlistServer.AllowLooseDecode
					decryptedName := encryption.ConvertShowNameWithOptions(passwdInfo.Password, passwdInfo.EncType, fileName, allowLoose)
					if decryptedName != "" && !encryption.IsOriginalFile(decryptedName) && decryptedName != fileName {
						// Save mapping: display path -> encrypted path (use decoded path)
						displayPath := path.Dir(decodedPath) + "/" + decryptedName
						encryptedPath := decodedPath
						h.fileDAO.SetEncPathMapping(displayPath, encryptedPath)

						// Copy file info from encrypted path to display path cache
						// This fixes cache key mismatch: PROPFIND caches with encrypted path,
						// but GET requests look up with display path
						if fileInfo, ok := h.fileDAO.Get(encryptedPath); ok {
							h.fileDAO.Set(&dao.FileInfo{
								Path:  displayPath,
								Name:  decryptedName,
								Size:  fileInfo.Size,
								IsDir: fileInfo.IsDir,
							})
						}

						// Replace only the filename part in the href
						newHref := "/dav" + path.Dir(decodedPath) + "/" + url.PathEscape(decryptedName)
						// Normalize path (remove double slashes)
						newHref = httputil.CleanPath(newHref)
						result = result[:contentStart] + newHref + result[endIdx:]
						searchPos = contentStart + len(newHref) + len(endTag)
						continue
					}
				}
			}
		}
		searchPos = endIdx + len(endTag)
	}

	return result
}
