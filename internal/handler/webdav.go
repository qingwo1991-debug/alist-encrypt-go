package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	cfg                   *config.Config
	streamProxy           *proxy.StreamProxy
	fileDAO               *dao.FileDAO
	passwdDAO             *dao.PasswdDAO
	proxyHandler          *ProxyHandler
	strategyCache         *StrategyCache
	sizeResolver          *FileSizeResolver
	strategySel           *StrategySelector
	metaStore             FileMetaStore
	probe                 *ProbeScheduler
	negCache              *negativePathCache
	sharedTransport       http.RoundTripper // shared transport for connection pooling
	shortClient           *http.Client      // 10s timeout for HEAD/quick ops
	stdClient             *http.Client      // 30s timeout for PROPFIND/DELETE/MOVE/COPY
	finalPassthroughCount uint64
	sizeConflictCount     uint64
	strategyFallbackCount uint64
	firstFrameCount       uint64
	firstFrameFallbacks   uint64
	warmupEnqueueCount    uint64
}

const propfindPersistentWriteThreshold = 128
const webdavAuthContextKey = "webdav-auth"

type webdavRawURLResolution struct {
	RawURL        string
	Source        string
	StatusCode    int
	FailureReason string
}

// Stats returns WebDAV handler statistics
func (h *WebDAVHandler) Stats() map[string]interface{} {
	var selectorStats map[string]interface{}
	if h.strategySel != nil {
		selectorStats = h.strategySel.Stats()
	}
	return map[string]interface{}{
		"strategy_cache": h.strategyCache.Stats(),
		"size_resolver":  h.sizeResolver.Stats(),
		"stream": map[string]interface{}{
			"final_passthrough_count": atomic.LoadUint64(&h.finalPassthroughCount),
			"size_conflict_count":     atomic.LoadUint64(&h.sizeConflictCount),
			"strategy_fallback_count": atomic.LoadUint64(&h.strategyFallbackCount),
			"first_frame_count":       atomic.LoadUint64(&h.firstFrameCount),
			"first_frame_fallbacks":   atomic.LoadUint64(&h.firstFrameFallbacks),
			"warmup_enqueue_count":    atomic.LoadUint64(&h.warmupEnqueueCount),
		},
		"probe_scheduler": func() map[string]interface{} {
			if h.probe != nil {
				return h.probe.Stats()
			}
			return nil
		}(),
		"strategy_selector": selectorStats,
	}
}

// NewWebDAVHandler creates a new WebDAV handler
func NewWebDAVHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO, selector *StrategySelector, metaStore FileMetaStore) *WebDAVHandler {
	sharedTransport := proxy.NewSharedTransport(cfg)
	h := &WebDAVHandler{
		cfg:             cfg,
		streamProxy:     streamProxy,
		fileDAO:         fileDAO,
		passwdDAO:       passwdDAO,
		proxyHandler:    NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, selector, metaStore),
		strategyCache:   NewStrategyCache(1000),
		sizeResolver:    NewFileSizeResolver(cfg, fileDAO, metaStore, 20, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		strategySel:     selector,
		metaStore:       metaStore,
		probe:           nil,
		negCache:        newNegativePathCache(getNegativeCacheTTL(cfg)),
		sharedTransport: sharedTransport,
		shortClient:     proxy.NewHTTPClientWithTransport(sharedTransport, 10*time.Second),
		stdClient:       proxy.NewHTTPClientWithTransport(sharedTransport, 30*time.Second),
	}
	return h
}

// Handle routes WebDAV requests
func (h *WebDAVHandler) Handle(w http.ResponseWriter, r *http.Request) {
	davPath := strings.TrimPrefix(r.URL.Path, "/dav")
	if davPath == "" {
		davPath = "/"
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		ctx := context.WithValue(r.Context(), webdavAuthContextKey, auth)
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

// Stop terminates background maintenance goroutines owned by the WebDAV handler.
func (h *WebDAVHandler) Stop() {
	if h == nil || h.proxyHandler == nil {
		return
	}
	h.proxyHandler.Stop()
}

// getStdClient returns the shared standard-timeout HTTP client,
// lazily creating one if the handler was constructed without NewWebDAVHandler.
func (h *WebDAVHandler) getStdClient() *http.Client {
	if h.stdClient != nil {
		return h.stdClient
	}
	if h.sharedTransport == nil {
		h.sharedTransport = proxy.NewSharedTransport(h.cfg)
	}
	h.stdClient = proxy.NewHTTPClientWithTransport(h.sharedTransport, 30*time.Second)
	return h.stdClient
}

// getShortClient returns the shared short-timeout HTTP client,
// lazily creating one if the handler was constructed without NewWebDAVHandler.
func (h *WebDAVHandler) getShortClient() *http.Client {
	if h.shortClient != nil {
		return h.shortClient
	}
	if h.sharedTransport == nil {
		h.sharedTransport = proxy.NewSharedTransport(h.cfg)
	}
	h.shortClient = proxy.NewHTTPClientWithTransport(h.sharedTransport, 10*time.Second)
	return h.shortClient
}

func (h *WebDAVHandler) upstreamStalenessThreshold() time.Duration {
	if h.cfg != nil && h.cfg.AlistServer.UpstreamStalenessMinutes > 0 {
		return time.Duration(h.cfg.AlistServer.UpstreamStalenessMinutes) * time.Minute
	}
	return 30 * time.Minute
}

func (h *WebDAVHandler) StartupProbe(ctx context.Context, paths []string) {
	if len(paths) == 0 {
		return
	}
	ctx = h.withProbeAuthContext(ctx)
	ctx = withProbeSource(ctx, probeSourceStartupScan)
	if h.cfg != nil && h.cfg.AlistServer.StartupProbeDeepScan {
		h.deepScan(ctx, paths)
		return
	}
	for _, dirPath := range paths {
		h.probePath(ctx, dirPath)
	}
}

func (h *WebDAVHandler) deepScan(ctx context.Context, paths []string) {
	type scanNode struct {
		path  string
		depth int
	}

	maxDepth := 0
	if h.cfg != nil && h.cfg.AlistServer.ScanMaxDepth > 0 {
		maxDepth = h.cfg.AlistServer.ScanMaxDepth
	}

	visited := make(map[string]struct{}, len(paths))
	queue := make([]scanNode, 0, len(paths))

	for _, dirPath := range paths {
		normalized := normalizeProbeDirPath(dirPath)
		if normalized == "" {
			continue
		}
		if _, ok := visited[normalized]; ok {
			continue
		}
		visited[normalized] = struct{}{}
		queue = append(queue, scanNode{path: normalized, depth: 0})
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		entries := h.probePath(ctx, node.path)
		if len(entries) == 0 {
			continue
		}
		if maxDepth > 0 && node.depth >= maxDepth {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir {
				continue
			}
			nextPath := normalizeProbeDirPath(entry.Path)
			if nextPath == "" || nextPath == node.path {
				continue
			}
			if _, ok := visited[nextPath]; ok {
				continue
			}
			visited[nextPath] = struct{}{}
			queue = append(queue, scanNode{path: nextPath, depth: node.depth + 1})
		}
	}
}

// convertToRealPath converts display path to encrypted path for WebDAV
func (h *WebDAVHandler) convertToRealPath(davPath string, passwdInfo *config.PasswdInfo) string {
	realPath, _ := h.resolveRealPathWithMode(davPath, passwdInfo)
	return realPath
}

func (h *WebDAVHandler) resolveRealPathWithMode(davPath string, passwdInfo *config.PasswdInfo) (string, string) {
	allowLoose := h.cfg != nil && h.cfg.AlistServer.AllowLooseDecode
	return resolveEncryptedRealPath(h.fileDAO, passwdInfo, davPath, allowLoose)
}

// handleGet handles GET requests with decryption
func (h *WebDAVHandler) handleGet(w http.ResponseWriter, r *http.Request, davPath string) {
	trace.Logf(r.Context(), "webdav-get", "Processing: %s", davPath)

	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found {
		if dirPasswd, ok := h.passwdDAO.FindByDir(davPath); ok {
			passwdInfo = dirPasswd
			found = true
		}
	}
	if !found {
		// Fallback: check for X-OpenEncrypt-Rule-* headers from openencrypt-android
		if headerInfo := PasswdInfoFromOpenEncryptHeaders(r); headerInfo != nil {
			passwdInfo = headerInfo
			found = true
			trace.Logf(r.Context(), "webdav-get", "Using encryption config from X-OpenEncrypt-Rule headers")
		}
	}
	if !found {
		trace.Logf(r.Context(), "webdav-get", "No encryption, passthrough")
		h.handlePassthrough(w, r)
		return
	}

	// Convert display path to real encrypted path
	realPath, pathMode := h.resolveRealPathWithMode(davPath, passwdInfo)
	trace.Logf(r.Context(), "webdav-get", "Path converted: %s -> %s mode=%s", davPath, realPath, pathMode)

	// WebDAV clients often start playback without a Range header. Some signed
	// CDN URLs reject that full-file GET, so keep non-range startup on the stable
	// internal /dav path. Range requests can still use a fresh raw_url for fast
	// seeking.
	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+realPath)
	trace.Logf(r.Context(), "webdav-get", "Using internal /dav target for playback, display=%s source=dav_internal", davPath)
	rangeHeader := strings.TrimSpace(r.Header.Get("Range"))
	staleThreshold := h.upstreamStalenessThreshold()
	if rangeHeader != "" {
		if cachedInfo, ok := h.fileDAO.Get(davPath); ok && cachedRawURLFresh(cachedInfo, staleThreshold) && strings.TrimSpace(cachedInfo.RawURL) != "" {
			targetURL = cachedInfo.RawURL
			trace.Logf(r.Context(), "webdav-get", "Using cached raw_url for ranged playback, display=%s source=cache", davPath)
		}
	}
	if resolve := h.resolveRawURLFromAlist(r, davPath, realPath); resolve.RawURL != "" {
		if rangeHeader != "" && !strings.EqualFold(targetURL, resolve.RawURL) {
			targetURL = resolve.RawURL
			trace.Logf(r.Context(), "webdav-get", "Using fresh raw_url for ranged playback, display=%s source=%s", davPath, resolve.Source)
		} else {
			trace.Logf(r.Context(), "webdav-get", "Warmed raw_url from alist, display=%s source=%s", davPath, resolve.Source)
		}
	} else {
		trace.Logf(r.Context(), "webdav-get", "raw_url warmup failed, display=%s real=%s status=%d reason=%s source=%s",
			davPath, realPath, resolve.StatusCode, resolve.FailureReason, resolve.Source)
	}

	// Look up file info using DISPLAY path (davPath), not realPath
	// PROPFIND caches entries by display path after decrypting filenames
	fileSize, usedStrategy := h.getFileSizeWithStrategy(davPath, realPath, targetURL, r)
	if fileSize == 0 {
		if probed := h.fetchWebDAVFileSize(r, davPath, realPath); probed > 0 {
			fileSize = probed
			trace.Logf(r.Context(), "webdav-get", "Resolved size via PROPFIND fallback: %d", fileSize)
		}
	}

	trace.Logf(r.Context(), "webdav-get", "File size: %d, strategy: %s", fileSize, usedStrategy)
	fileItem := FileItem{
		DisplayPath:      davPath,
		EncryptedPath:    realPath,
		TargetURL:        targetURL,
		FileName:         path.Base(davPath),
		CompatStorageKey: buildRangeCompatStorageKey(passwdInfo, davPath),
	}
	trace.Logf(r.Context(), "webdav-get", "Proxying with decryption, target=%s", targetURL)
	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:        w,
		Request:               r,
		Config:                h.cfg,
		Probe:                 h.probe,
		StreamProxy:           h.streamProxy,
		FileDAO:               h.fileDAO,
		SizeResolver:          h.sizeResolver,
		StrategySel:           h.strategySel,
		PasswdInfo:            passwdInfo,
		FileItem:              fileItem,
		TargetURL:             targetURL,
		ProviderKey:           ProviderKey(targetURL, davPath),
		Path:                  davPath,
		InitialSize:           fileSize,
		OverridePath:          davPath,
		CompatKey:             buildRangeCompatStorageKey(passwdInfo, davPath),
		ConsumerScenario:      consumerScenarioWebDAV,
		FailureLogMsg:         "WebDAV GET decryption failed",
		FinalPassthroughCount: &h.finalPassthroughCount,
		SizeConflictCount:     &h.sizeConflictCount,
		FirstFrameCount:       &h.firstFrameCount,
		FirstFrameFallbacks:   &h.firstFrameFallbacks,
		WarmupEnqueueCount:    &h.warmupEnqueueCount,
	})
}

func (h *WebDAVHandler) fetchWebDAVFileSize(r *http.Request, displayPath, realPath string) int64 {
	if h == nil || h.cfg == nil {
		return 0
	}
	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/d"+realPath)
	req, err := httputil.NewRequest("HEAD", targetURL).
		WithContext(r.Context()).
		CopyHeadersExcept(r, "Host", "Content-Length", "Content-Type", "Accept-Encoding").
		Build()
	if err != nil {
		return 0
	}
	resp, err := h.getShortClient().Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
			return size
		}
	}
	return 0
}

// fetchRawURLFromAlist calls alist /api/fs/get to get the signed raw_url,
// caches it, and returns it. PROPFIND XML doesn't include raw_url.
func (h *WebDAVHandler) fetchRawURLFromAlist(r *http.Request, displayPath, realPath string) string {
	return h.resolveRawURLFromAlist(r, displayPath, realPath).RawURL
}

func (h *WebDAVHandler) resolveRawURLFromAlist(r *http.Request, displayPath, realPath string) webdavRawURLResolution {
	stalenessThreshold := 30 * time.Minute
	if h.cfg != nil && h.cfg.AlistServer.UpstreamStalenessMinutes > 0 {
		stalenessThreshold = time.Duration(h.cfg.AlistServer.UpstreamStalenessMinutes) * time.Minute
	}
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}
	result := fetchRawURL(r.Context(), h.cfg.GetAlistURL(), displayPath, realPath, authHeaders, h.fileDAO, stalenessThreshold)
	return webdavRawURLResolution{
		RawURL:        result.RawURL,
		Source:        result.Source,
		StatusCode:    result.StatusCode,
		FailureReason: result.FailureReason,
	}
}

// handlePut handles PUT requests with encryption and filename encryption
func (h *WebDAVHandler) handlePut(w http.ResponseWriter, r *http.Request, davPath string) {
	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	if !found {
		if dirPasswd, ok := h.passwdDAO.FindByDir(davPath); ok {
			passwdInfo = dirPasswd
			found = true
		}
	}
	if !found {
		h.handlePassthrough(w, r)
		return
	}

	fileSize, err := resolveUploadFileSize(r)
	if err != nil {
		log.Warn().
			Err(err).
			Str("path", davPath).
			Str("content_length", r.Header.Get("Content-Length")).
			Str("content_range", r.Header.Get("Content-Range")).
			Msg("Reject encrypted WebDAV upload without deterministic file size")
		RespondHTTPErrorWithStatus(w, "Cannot determine upload file size for encryption", http.StatusBadRequest)
		return
	}
	startOffset, hasRange, err := parseContentRangeStart(r.Header.Get("Content-Range"))
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid Content-Range header", http.StatusBadRequest)
		return
	}
	if hasRange && startOffset >= fileSize {
		RespondHTTPErrorWithStatus(w, "Invalid Content-Range start offset", http.StatusBadRequest)
		return
	}

	// Convert display path to real encrypted path
	realPath := davPath
	if passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileName := path.Base(davPath)
		realPath = path.Dir(davPath) + "/" + converter.ToRealName(fileName)

		// Cache file info for subsequent PROPFIND (like alist-encrypt does)
		h.fileDAO.Set(&dao.FileInfo{
			Path:  davPath,
			Name:  fileName,
			Size:  fileSize,
			IsDir: false,
		})
		log.Debug().Str("original", davPath).Str("encrypted", realPath).Msg("WebDAV PUT filename encrypted")
	}

	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+realPath)

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize, startOffset); err != nil {
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
	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+realPath)

	proxyReq, err := httputil.NewRequest("DELETE", targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.getStdClient().Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV DELETE failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
		return
	}
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
				realDestPath := path.Dir(destPath) + "/" + converter.ToRealName(fileName)

				// Rebuild destination URL
				destURL.Path = "/dav" + realDestPath
				destination = destURL.String()
			}
		}
	}

	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+realSrcPath)

	body, err := readLimitedRequestBody(r)
	if err != nil {
		log.Warn().Err(err).Msg("Request body read failed")
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}
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

	resp, err := h.getStdClient().Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msgf("WebDAV %s failed", method)
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
		return
	}
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
	startAt := time.Now()

	passwdInfo, found := h.passwdDAO.FindByPath(davPath)
	ruleSource := "FindByPath"
	if !found {
		if dirPasswd, ok := h.passwdDAO.FindByDir(davPath); ok {
			passwdInfo = dirPasswd
			found = true
			ruleSource = "FindByDir"
		}
	}
	if !found {
		ruleSource = "none"
	}

	// Read request body (need to buffer for possible retry)
	body, err := readLimitedRequestBody(r)
	if err != nil {
		log.Warn().Err(err).Msg("Request body read failed")
		http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Determine the actual path to request from Alist
	// For files with encrypted names, use cached encrypted path
	requestPath := davPath
	isDirRequest := strings.HasSuffix(davPath, "/")
	if found && passwdInfo.EncName && !isDirRequest {
		if encPath, ok := h.fileDAO.GetEncPath(davPath); ok {
			requestPath = encPath
			trace.Logf(r.Context(), "propfind", "Using cached enc path: %s -> %s rule=%s", davPath, requestPath, ruleSource)
		} else {
			retryPath := h.convertToRealPath(davPath, passwdInfo)
			if retryPath != "" && retryPath != davPath {
				requestPath = retryPath
				trace.Logf(r.Context(), "propfind", "Using derived enc path: %s -> %s rule=%s", davPath, requestPath, ruleSource)
			}
		}
	}
	trace.Logf(r.Context(), "propfind", "Request path=%s rule=%s", requestPath, ruleSource)

	// Step 1: Request Alist with the determined path
	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+requestPath)

	if !isDirRequest && h.negCache != nil && h.negCache.IsBlocked(requestPath) {
		trace.Logf(r.Context(), "propfind", "Negative cache hit: %s", requestPath)
		RespondHTTPErrorWithStatus(w, "Not found", http.StatusNotFound)
		return
	}

	proxyReq, err := httputil.NewRequest("PROPFIND", targetURL).
		WithContext(r.Context()).
		WithBody(body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.getStdClient().Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("WebDAV PROPFIND failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}

	trace.Logf(r.Context(), "propfind", "Alist response: status=%d", resp.StatusCode)
	if !isDirRequest && resp.StatusCode == http.StatusNotFound && h.negCache != nil {
		h.negCache.Block(requestPath)
	}

	// Step 2: If 404 and encryption enabled, retry with encrypted filename
	if resp.StatusCode == http.StatusNotFound && found && passwdInfo.EncName {
		resp.Body.Close()

		fileName := path.Base(davPath)
		if fileName != "" && fileName != "/" && fileName != "." {
			// Convert to encrypted path and retry
			realPath := h.convertToRealPath(davPath, passwdInfo)
			retryURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+realPath)

			trace.Logf(r.Context(), "propfind", "404 retry: request=%s retry=%s rule=%s", requestPath, realPath, ruleSource)

			retryReq, err := httputil.NewRequest("PROPFIND", retryURL).
				WithContext(r.Context()).
				WithBody(body).
				CopyHeaders(r).
				Build()
			if err == nil {
				retryResp, err := h.getStdClient().Do(retryReq)
				if err == nil {
					resp = retryResp
					if retryResp.StatusCode == http.StatusMultiStatus {
						h.fileDAO.SetEncPathMapping(davPath, realPath)
					}
				}
			}
		}
	}
	defer resp.Body.Close()

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
		return
	}
	upstreamCost := time.Since(startAt)

	// Step 3: Parse and cache file info from PROPFIND response
	parseStart := time.Now()
	entries := h.parsePropfindResponse(r.Context(), respBody, davPath)
	parseCost := time.Since(parseStart)

	// Step 4: Decrypt filenames in the XML response if encryption is enabled
	decryptStart := time.Now()
	if found && passwdInfo.EncName && resp.StatusCode == http.StatusMultiStatus {
		respBody = h.decryptPropfindResponse(respBody, passwdInfo)
	}
	decryptCost := time.Since(decryptStart)
	trace.Logf(r.Context(), "propfind", "Timings upstream=%s parse=%s decrypt=%s entries=%d bytes=%d",
		upstreamCost, parseCost, decryptCost, len(entries), len(respBody))

	// Copy response headers (recalculate Content-Length since body may have changed)
	httputil.CopyResponseHeaders(w, resp, "Content-Length")
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (h *WebDAVHandler) probePath(ctx context.Context, dirPath string) []propfindEntry {
	requestPath := normalizeProbeDirPath(dirPath)
	if requestPath == "" {
		return nil
	}

	if h.negCache != nil && h.negCache.IsBlocked(requestPath) {
		return nil
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/dav"+requestPath, nil)
	req, err := httputil.NewRequest("PROPFIND", targetURL).
		WithContext(ctx).
		WithHeader("Depth", "1").
		Build()
	if err != nil {
		return nil
	}
	if auth := h.probeAuthHeader(ctx); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	resp, err := h.getStdClient().Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		return nil
	}
	if resp.StatusCode == http.StatusNotFound && h.negCache != nil {
		h.negCache.Block(requestPath)
		return nil
	}
	if resp.StatusCode != http.StatusMultiStatus {
		return nil
	}

	return h.parsePropfindResponse(ctx, body, requestPath)
}

type negativePathCache struct {
	mu   sync.Mutex
	ttl  time.Duration
	data map[string]time.Time
}

func newNegativePathCache(ttl time.Duration) *negativePathCache {
	if ttl <= 0 {
		return nil
	}
	return &negativePathCache{
		ttl:  ttl,
		data: make(map[string]time.Time),
	}
}

func (c *negativePathCache) IsBlocked(path string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.data[path]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(c.data, path)
		return false
	}
	return true
}

func (c *negativePathCache) Block(path string) {
	if c == nil || path == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[path] = time.Now().Add(c.ttl)
}

// handlePassthrough passes requests directly to Alist
func (h *WebDAVHandler) handlePassthrough(w http.ResponseWriter, r *http.Request) {
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)

	if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
		log.Error().Err(err).Str("method", r.Method).Msg("WebDAV passthrough failed")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
	}
}

type propfindEntry struct {
	Path  string
	Name  string
	Size  int64
	IsDir bool
}

func (h *WebDAVHandler) parsePropfindEntries(body []byte) []propfindEntry {
	type PropfindResponse struct {
		XMLName  xml.Name `xml:"multistatus"`
		Response []struct {
			Href     string `xml:"href"`
			PropStat []struct {
				Prop struct {
					DisplayName   string `xml:"displayname"`
					ContentLength int64  `xml:"getcontentlength"`
					ResourceType  struct {
						Collection *struct{} `xml:"collection"`
						Value      string    `xml:",chardata"`
					} `xml:"resourcetype"`
				} `xml:"prop"`
			} `xml:"propstat"`
		} `xml:"response"`
	}

	var propfind PropfindResponse
	if err := xml.Unmarshal(body, &propfind); err != nil {
		log.Debug().Err(err).Msg("Failed to parse PROPFIND response")
		return nil
	}

	entries := make([]propfindEntry, 0, len(propfind.Response))
	for _, resp := range propfind.Response {
		filePath := strings.TrimPrefix(resp.Href, "/dav")
		if filePath == "" {
			filePath = "/"
		}

		if decoded, err := url.PathUnescape(filePath); err == nil {
			filePath = decoded
		}

		displayName := ""
		contentLength := int64(0)
		hasCollection := false
		resourceTypeText := ""
		for _, propStat := range resp.PropStat {
			if propStat.Prop.DisplayName != "" {
				displayName = propStat.Prop.DisplayName
			}
			if propStat.Prop.ContentLength > 0 {
				contentLength = propStat.Prop.ContentLength
			}
			if propStat.Prop.ResourceType.Collection != nil {
				hasCollection = true
			}
			if propStat.Prop.ResourceType.Value != "" {
				resourceTypeText = propStat.Prop.ResourceType.Value
			}
		}
		isDir := hasCollection || strings.Contains(strings.ToLower(resourceTypeText), "collection")
		if !isDir && strings.HasSuffix(filePath, "/") {
			isDir = true
		}

		entries = append(entries, propfindEntry{
			Path:  filePath,
			Name:  displayName,
			Size:  contentLength,
			IsDir: isDir,
		})
	}
	return entries
}

// parsePropfindResponse parses WebDAV PROPFIND XML response and caches file info
func (h *WebDAVHandler) parsePropfindResponse(ctx context.Context, body []byte, basePath string) []propfindEntry {
	entries := h.parsePropfindEntries(body)
	if len(entries) == 0 {
		return nil
	}

	// For large directories, avoid per-entry BoltDB writes in request path.
	// Keep hot data in pathCache and let background mechanisms persist metadata.
	persistToStore := len(entries) <= propfindPersistentWriteThreshold

	for _, entry := range entries {
		displayPath := entry.Path
		displayName := entry.Name
		encryptedPath := entry.Path

		if h.passwdDAO != nil {
			if passwdInfo, found := h.passwdDAO.FindByPath(entry.Path); found && passwdInfo != nil && passwdInfo.EncName {
				allowLoose := h.cfg != nil && h.cfg.AlistServer.AllowLooseDecode
				if decryptedName := encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, entry.Name, passwdInfo.EncSuffix, allowLoose); decryptedName != "" && decryptedName != entry.Name {
					displayName = decryptedName
					displayPath = path.Join(path.Dir(entry.Path), decryptedName)
				}
			}
		}

		info := &dao.FileInfo{
			Path:  displayPath,
			Name:  displayName,
			Size:  entry.Size,
			IsDir: entry.IsDir,
		}

		if persistToStore {
			_ = h.fileDAO.Set(info)
		} else {
			h.fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, displayName, entry.Size, entry.IsDir)
		}
		if displayPath != encryptedPath {
			h.fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, displayName, entry.Size, entry.IsDir)
		}
		if !info.IsDir {
			if info.Size > 0 {
				h.upsertMetaFromListing(ctx, displayPath, info.Size)
			}
			h.enqueueProbeFromPropfind(ctx, displayPath, info.Size)
		}
	}
	return entries
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
		DisplayPath:      displayPath,
		EncryptedPath:    realPath,
		TargetURL:        targetURL,
		FileName:         path.Base(displayPath),
		CompatStorageKey: buildRangeCompatStorageKey(passwdInfo, displayPath),
	}
	authHeaders := make(http.Header)
	if auth := ctx.Value(webdavAuthContextKey); auth != nil {
		if value, ok := auth.(string); ok && value != "" {
			authHeaders.Set("Authorization", value)
		}
	}
	h.probe.EnqueueWithSource(file, authHeaders, reportedSize, probeSourceFromContext(ctx, probeSourcePropfind))
}

func (h *WebDAVHandler) withProbeAuthContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if auth := h.probeAuthHeader(ctx); auth != "" {
		return context.WithValue(ctx, webdavAuthContextKey, auth)
	}
	return ctx
}

func (h *WebDAVHandler) probeAuthHeader(ctx context.Context) string {
	if ctx != nil {
		if auth := ctx.Value(webdavAuthContextKey); auth != nil {
			if value, ok := auth.(string); ok {
				value = strings.TrimSpace(value)
				if value != "" {
					return value
				}
			}
		}
	}
	if h == nil || h.cfg == nil {
		return ""
	}
	if raw := strings.TrimSpace(h.cfg.AlistServer.ScanAuthHeader); raw != "" {
		return extractAuthorizationValue(raw)
	}
	username := h.cfg.AlistServer.ScanUsername
	password := h.cfg.AlistServer.ScanPassword
	if username == "" && password == "" {
		return ""
	}
	token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return "Basic " + token
}

func extractAuthorizationValue(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "authorization:") {
		value = strings.TrimSpace(value[len("authorization:"):])
	}
	return value
}

func normalizeProbeDirPath(dirPath string) string {
	trimmed := strings.TrimSpace(dirPath)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	clean := path.Clean(trimmed)
	if clean == "." {
		clean = "/"
	}
	if clean != "/" {
		clean = strings.TrimRight(clean, "/") + "/"
	}
	return clean
}

func isStrictWebDAVRawURLFailure(statusCode int) bool {
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	default:
		return false
	}
}

// decryptPropfindResponse decrypts filenames in WebDAV PROPFIND XML response
// and adjusts getcontentlength for V2 encrypted files (subtract 32-byte header).
// Uses a single-pass strings.Builder approach to avoid the original double conversion
// ([]byte -> string -> []byte) and the 7+ intermediate string allocations from
// sequential per-tag-type passes.
func (h *WebDAVHandler) decryptPropfindResponse(body []byte, passwdInfo *config.PasswdInfo) []byte {
	type tagPair struct {
		start, end string
		kind       int // 0=displayname, 1=href, 2=getcontentlength
	}
	tags := []tagPair{
		{`<D:displayname>`, `</D:displayname>`, 0},
		{`<d:displayname>`, `</d:displayname>`, 0},
		{`<displayname>`, `</displayname>`, 0},
		{`<D:href>`, `</D:href>`, 1},
		{`<d:href>`, `</d:href>`, 1},
		{`<href>`, `</href>`, 1},
		{`<D:getcontentlength>`, `</D:getcontentlength>`, 2},
		{`<d:getcontentlength>`, `</d:getcontentlength>`, 2},
		{`<getcontentlength>`, `</getcontentlength>`, 2},
	}

	headerSize := encryption.ContentHeaderSize()
	allowLoose := h.cfg != nil && h.cfg.AlistServer.AllowLooseDecode

	var b bytes.Buffer
	b.Grow(len(body))
	searchPos := 0

	for searchPos < len(body) {
		bestStart := -1
		bestEnd := -1
		bestKind := -1
		var bestStartTag, bestEndTag string

		for _, t := range tags {
			if t.kind == 2 && headerSize <= 0 {
				continue
			}
			idx := bytes.Index(body[searchPos:], []byte(t.start))
			if idx == -1 {
				continue
			}
			absStart := searchPos + idx
			if bestStart != -1 && absStart >= bestStart {
				continue
			}
			endIdx := bytes.Index(body[absStart+len(t.start):], []byte(t.end))
			if endIdx == -1 {
				continue
			}
			bestStart = absStart
			bestEnd = absStart + len(t.start) + endIdx
			bestKind = t.kind
			bestStartTag = t.start
			bestEndTag = t.end
		}

		if bestStart == -1 {
			b.Write(body[searchPos:])
			break
		}

		b.Write(body[searchPos:bestStart])
		b.WriteString(bestStartTag)
		contentStart := bestStart + len(bestStartTag)
		content := string(body[contentStart:bestEnd])

		switch bestKind {
		case 0: // displayname
			if content != "" && content != "/" {
				decryptedName := encryption.ConvertShowNameWithSuffixOptions(
					passwdInfo.Password, passwdInfo.EncType, content, passwdInfo.EncSuffix, allowLoose)
				if decryptedName != "" && decryptedName != content {
					b.WriteString(decryptedName)
					b.WriteString(bestEndTag)
					searchPos = bestEnd + len(bestEndTag)
					continue
				}
			}
			b.WriteString(content)
			b.WriteString(bestEndTag)

		case 1: // href
			if strings.HasPrefix(content, "/dav/") {
				davPath := strings.TrimPrefix(content, "/dav")
				decodedPath, err := url.PathUnescape(davPath)
				if err != nil {
					decodedPath = davPath
				}
				if decodedPath != "/" && decodedPath != "" {
					fileName := path.Base(decodedPath)
					if fileName != "" && fileName != "/" && fileName != "." {
						decryptedName := encryption.ConvertShowNameWithSuffixOptions(
							passwdInfo.Password, passwdInfo.EncType, fileName, passwdInfo.EncSuffix, allowLoose)
						if decryptedName != "" && !encryption.IsOriginalFile(decryptedName) && decryptedName != fileName {
							displayPath := path.Dir(decodedPath) + "/" + decryptedName
							h.fileDAO.SetEncPathMapping(displayPath, decodedPath)
							if fileInfo, ok := h.fileDAO.Get(decodedPath); ok {
								h.fileDAO.SetEncPathMappingWithInfo(
									displayPath, decodedPath, decryptedName, fileInfo.Size, fileInfo.IsDir)
							}
							origName := path.Base(content)
							decHref := strings.TrimSuffix(content, origName) + decryptedName
							b.WriteString(decHref)
							b.WriteString(bestEndTag)
							searchPos = bestEnd + len(bestEndTag)
							continue
						}
					}
				}
			}
			b.WriteString(content)
			b.WriteString(bestEndTag)

		case 2: // getcontentlength
			valStr := strings.TrimSpace(content)
			size, err := strconv.ParseInt(valStr, 10, 64)
			if err == nil && size > headerSize {
				b.WriteString(strconv.FormatInt(size-headerSize, 10))
				b.WriteString(bestEndTag)
				searchPos = bestEnd + len(bestEndTag)
				continue
			}
			b.WriteString(content)
			b.WriteString(bestEndTag)
		}

		searchPos = bestEnd + len(bestEndTag)
	}

	return b.Bytes()
}

// adjustPropfindContentLengthForV2 subtracts the V2 header size from getcontentlength
// in PROPFIND XML response blocks, but only for files confirmed to be V2 format.
// V1 files store plaintext directly, so their content length must not be adjusted.
// A file is confirmed as V2 when the file DAO has cached metadata with ContentVersion == 2.
func (h *WebDAVHandler) adjustPropfindContentLengthForV2(xmlStr string) string {
	headerSize := encryption.ContentHeaderSize()
	if headerSize <= 0 {
		return xmlStr
	}

	contentLengthVariants := [][2]string{
		{`<D:getcontentlength>`, `</D:getcontentlength>`},
		{`<d:getcontentlength>`, `</d:getcontentlength>`},
		{`<getcontentlength>`, `</getcontentlength>`},
	}

	hrefVariants := [][2]string{
		{`<D:href>`, `</D:href>`},
		{`<d:href>`, `</d:href>`},
		{`<href>`, `</href>`},
	}

	result := xmlStr
	searchPos := 0

	for {
		// Find the next <response> or <D:response> block
		respStart := -1
		for _, prefix := range []string{"<D:response>", "<d:response>", "<response>"} {
			idx := strings.Index(result[searchPos:], prefix)
			if idx == -1 {
				continue
			}
			absIdx := searchPos + idx
			if respStart == -1 || absIdx < respStart {
				respStart = absIdx
			}
		}
		if respStart == -1 {
			break
		}

		respEnd := -1
		for _, suffix := range []string{"</D:response>", "</d:response>", "</response>"} {
			idx := strings.Index(result[respStart:], suffix)
			if idx == -1 {
				continue
			}
			absIdx := respStart + idx + len(suffix)
			if respEnd == -1 || absIdx < respEnd {
				respEnd = absIdx
			}
		}
		if respEnd == -1 {
			break
		}

		block := result[respStart:respEnd]

		// Extract href from the block to identify the file
		filePath := ""
		for _, hv := range hrefVariants {
			idx := strings.Index(block, hv[0])
			if idx == -1 {
				continue
			}
			hrefStart := idx + len(hv[0])
			hrefEnd := strings.Index(block[hrefStart:], hv[1])
			if hrefEnd == -1 {
				continue
			}
			href := block[hrefStart : hrefStart+hrefEnd]
			hrefPath := strings.TrimPrefix(href, "/dav")
			if decoded, err := url.PathUnescape(hrefPath); err == nil {
				filePath = decoded
			} else {
				filePath = hrefPath
			}
			break
		}

		// Find and adjust getcontentlength within this block only if file is V2
		for _, variant := range contentLengthVariants {
			idx := strings.Index(block, variant[0])
			if idx == -1 {
				continue
			}
			valStart := idx + len(variant[0])
			valEnd := strings.Index(block[valStart:], variant[1])
			if valEnd == -1 {
				continue
			}
			valEnd += valStart

			valStr := strings.TrimSpace(block[valStart:valEnd])
			size, err := strconv.ParseInt(valStr, 10, 64)
			if err != nil || size <= headerSize {
				continue
			}

			// Only adjust if file is confirmed V2 via cached metadata
			isV2 := false
			if filePath != "" && h.fileDAO != nil {
				if fi, ok := h.fileDAO.Get(filePath); ok && fi != nil && fi.ContentVersion == 2 {
					isV2 = true
				}
			}
			if !isV2 {
				continue
			}

			newSize := size - headerSize
			newValStr := strconv.FormatInt(newSize, 10)
			absValStart := respStart + valStart
			absValEnd := respStart + valEnd
			result = result[:absValStart] + newValStr + result[absValEnd:]
			break
		}

		searchPos = respEnd
	}

	return result
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
			decryptedName := encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, encryptedName, passwdInfo.EncSuffix, allowLoose)
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
					decryptedName := encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, fileName, passwdInfo.EncSuffix, allowLoose)
					if decryptedName != "" && !encryption.IsOriginalFile(decryptedName) && decryptedName != fileName {
						// Save mapping: display path -> encrypted path (use decoded path)
						displayPath := path.Dir(decodedPath) + "/" + decryptedName
						encryptedPath := decodedPath
						h.fileDAO.SetEncPathMapping(displayPath, encryptedPath)

						// Copy file info from encrypted path to display path cache
						// This fixes cache key mismatch: PROPFIND caches with encrypted path,
						// but GET requests look up with display path
						if fileInfo, ok := h.fileDAO.Get(encryptedPath); ok {
							// Keep this mapping hot in memory without forcing a synchronous BoltDB write.
							h.fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, decryptedName, fileInfo.Size, fileInfo.IsDir)
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
