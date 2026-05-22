package handler

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
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

// ProxyHandler handles proxy requests
type ProxyHandler struct {
	cfg                   *config.Config
	streamProxy           *proxy.StreamProxy
	fileDAO               *dao.FileDAO
	passwdDAO             *dao.PasswdDAO
	redirectMap           sync.Map // key -> redirect info
	client                *proxy.Client
	redirectKeys          []string
	keysMu                sync.Mutex
	strategyCache         *StrategyCache
	sizeResolver          *FileSizeResolver
	strategySel           *StrategySelector
	probe                 *ProbeScheduler
	finalPassthroughCount uint64
	sizeConflictCount     uint64
	strategyFallbackCount uint64
	firstFrameCount       uint64
	firstFrameFallbacks   uint64
	warmupEnqueueCount    uint64
	prefetchTotal         uint64
	prefetchSuccess       uint64
	prefetchSkipped       uint64
	prefetchStaleTriggers uint64
	prefetchLastAt        int64 // Unix nano
}

const maxRedirectEntries = 10000

type redirectInfo struct {
	URL         string
	FileSize    int64
	Password    string
	EncType     string
	EncName     bool
	DisplayPath string
	CompatKey   string
	ExpiresAt   time.Time
}

// Stats returns proxy handler statistics
func (h *ProxyHandler) Stats() map[string]interface{} {
	redirectCount := 0
	h.redirectMap.Range(func(_, _ interface{}) bool {
		redirectCount++
		return true
	})

	h.keysMu.Lock()
	keysLen := len(h.redirectKeys)
	h.keysMu.Unlock()

	return map[string]interface{}{
		"redirects": map[string]interface{}{
			"entries": redirectCount,
			"keys":    keysLen,
			"max":     maxRedirectEntries,
		},
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
		"strategy_selector": func() map[string]interface{} {
			if h.strategySel != nil {
				return h.strategySel.Stats()
			}
			return nil
		}(),
		"prefetch": h.prefetchStats(),
	}
}

func (h *ProxyHandler) prefetchStats() map[string]interface{} {
	lastAt := atomic.LoadInt64(&h.prefetchLastAt)
	lastAtStr := ""
	if lastAt > 0 {
		lastAtStr = time.Unix(0, lastAt).Format(time.RFC3339)
	}
	return map[string]interface{}{
		"total":          atomic.LoadUint64(&h.prefetchTotal),
		"success":        atomic.LoadUint64(&h.prefetchSuccess),
		"skipped":        atomic.LoadUint64(&h.prefetchSkipped),
		"stale_triggers": atomic.LoadUint64(&h.prefetchStaleTriggers),
		"last_at":        lastAtStr,
	}
}

// NewProxyHandler creates a new proxy handler
func NewProxyHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO, selector *StrategySelector, metaStore FileMetaStore) *ProxyHandler {
	h := &ProxyHandler{
		cfg:           cfg,
		streamProxy:   streamProxy,
		fileDAO:       fileDAO,
		passwdDAO:     passwdDAO,
		client:        proxy.NewClient(cfg),
		strategyCache: NewStrategyCache(1000),
		sizeResolver:  NewFileSizeResolver(cfg, fileDAO, metaStore, 20, getMinMetaSize(cfg), getRedirectMaxHops(cfg)),
		strategySel:   selector,
	}
	if h.streamProxy != nil {
		h.streamProxy.SetRedirectRewriter(h.rewriteRedirectLocation)
	}
	go h.cleanupRedirects()
	return h
}

func (h *ProxyHandler) SetProbeScheduler(probe *ProbeScheduler) {
	h.probe = probe
}

func (h *ProxyHandler) cleanupRedirects() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		h.redirectMap.Range(func(key, value interface{}) bool {
			info := value.(*redirectInfo)
			if now.After(info.ExpiresAt) {
				h.redirectMap.Delete(key)
			}
			return true
		})

		// Cleanup redirectKeys slice to prevent memory leak
		// Remove entries that no longer exist in the map
		h.cleanupRedirectKeys()
	}
}

// cleanupRedirectKeys removes stale entries from redirectKeys slice
func (h *ProxyHandler) cleanupRedirectKeys() {
	h.keysMu.Lock()
	defer h.keysMu.Unlock()

	validKeys := make([]string, 0, len(h.redirectKeys))
	for _, key := range h.redirectKeys {
		if _, ok := h.redirectMap.Load(key); ok {
			validKeys = append(validKeys, key)
		}
	}
	h.redirectKeys = validKeys
}

// HandleRedirect handles /redirect/:key for 302 redirect decryption
func (h *ProxyHandler) HandleRedirect(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/redirect/")
	if key == "" {
		RespondHTTPErrorWithStatus(w, "Missing key", http.StatusBadRequest)
		return
	}

	value, ok := h.redirectMap.Load(key)
	if !ok {
		RespondHTTPErrorWithStatus(w, "Redirect key not found or expired", http.StatusNotFound)
		return
	}

	info := value.(*redirectInfo)

	decodeParam := r.URL.Query().Get("decode")
	decryptEnabled := decodeParam != "0"

	if strings.Contains(info.URL, "baidupcs.com") {
		r.Header.Set("User-Agent", "pan.baidu.com")
	}
	if !decryptEnabled {
		r.Header.Del("Referer")
		r.Header.Del("Authorization")
		r.Header.Del("Host")
		r.Host = ""
		if err := h.streamProxy.ProxyRequest(w, r, info.URL); err != nil {
			log.Error().Err(err).Str("key", key).Msg("Failed to proxy redirect (passthrough)")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}
	if info.FileSize == 0 {
		// When decryption is explicitly requested (decode=1), we must not
		// silently return encrypted content. SizeUnknownStrict only
		// controls non-decrypt paths.
		log.Warn().Str("key", key).Msg("Decryption requested but file size is unknown, refusing to serve encrypted content")
		RespondHTTPErrorWithStatus(w, "Unable to determine encrypted file size for decryption", http.StatusBadGateway)
		return
	}

	passwdInfo := &config.PasswdInfo{
		Password: info.Password,
		EncType:  info.EncType,
		EncName:  info.EncName,
		Enable:   true,
	}
	proxy.StripWebDAVHeaders(r)
	r.Host = ""

	displayPath := info.DisplayPath
	if displayPath == "" {
		displayPath = resolveRedirectDisplayPath(r)
	}
	if displayPath != "" {
		r = r.WithContext(proxy.WithDisplayName(r.Context(), path.Base(displayPath)))
	}
	fileItem := FileItem{
		DisplayPath:      displayPath,
		EncryptedPath:    displayPath,
		TargetURL:        info.URL,
		FileName:         path.Base(displayPath),
		CompatStorageKey: info.CompatKey,
	}
	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:        w,
		Request:               r,
		Config:                h.cfg,
		Probe:                 h.probe,
		StreamProxy:           h.streamProxy,
		SizeResolver:          h.sizeResolver,
		StrategySel:           h.strategySel,
		PasswdInfo:            passwdInfo,
		FileItem:              fileItem,
		TargetURL:             info.URL,
		ProviderKey:           ProviderKey(info.URL, displayPath),
		Path:                  displayPath,
		InitialSize:           info.FileSize,
		OverridePath:          displayPath,
		CompatKey:             redirectCompatKey(info, passwdInfo, displayPath),
		FailureLogMsg:         "Failed to proxy redirect",
		FinalPassthroughCount: &h.finalPassthroughCount,
		SizeConflictCount:     &h.sizeConflictCount,
		FirstFrameCount:       &h.firstFrameCount,
		FirstFrameFallbacks:   &h.firstFrameFallbacks,
		WarmupEnqueueCount:    &h.warmupEnqueueCount,
	})
}

// RegisterRedirect registers a URL for redirect decryption and returns the key
func (h *ProxyHandler) RegisterRedirect(url string, fileSize int64, passwdInfo *config.PasswdInfo, displayPath string) string {
	password := ""
	encType := ""
	encName := false
	compatKey := "/"
	if passwdInfo != nil {
		password = passwdInfo.Password
		encType = passwdInfo.EncType
		encName = passwdInfo.EncName
		compatKey = buildRangeCompatStorageKey(passwdInfo, displayPath)
	}
	hash := md5.Sum([]byte(fmt.Sprintf("%s:%d:%d", url, fileSize, time.Now().UnixNano())))
	key := hex.EncodeToString(hash[:])

	h.redirectMap.Store(key, &redirectInfo{
		URL:         url,
		FileSize:    fileSize,
		Password:    password,
		EncType:     encType,
		EncName:     encName,
		DisplayPath: displayPath,
		CompatKey:   compatKey,
		ExpiresAt:   time.Now().Add(72 * time.Hour),
	})

	// LRU eviction
	h.keysMu.Lock()
	h.redirectKeys = append(h.redirectKeys, key)
	for len(h.redirectKeys) > maxRedirectEntries {
		oldKey := h.redirectKeys[0]
		h.redirectKeys = h.redirectKeys[1:]
		h.redirectMap.Delete(oldKey)
	}
	h.keysMu.Unlock()

	return key
}

func (h *ProxyHandler) rewriteRedirectLocation(req *http.Request, location string, fileSize int64, passwdInfo *config.PasswdInfo) (string, bool) {
	if passwdInfo == nil || !passwdInfo.Enable {
		return "", false
	}

	displayPath := ""
	if req != nil && req.URL != nil {
		displayPath = redirectDisplayPathFromURLPath(req.URL.Path)
	}
	key := h.RegisterRedirect(location, fileSize, passwdInfo, displayPath)
	lastURL := ""
	if req != nil && req.URL != nil {
		if req.URL.RequestURI() != "" {
			lastURL = req.URL.RequestURI()
		} else {
			lastURL = req.URL.Path
		}
	}

	return buildRedirectPath(key, lastURL, true), true
}

func redirectCompatKey(info *redirectInfo, passwdInfo *config.PasswdInfo, displayPath string) string {
	if info != nil && strings.TrimSpace(info.CompatKey) != "" {
		return info.CompatKey
	}
	return buildRangeCompatStorageKey(passwdInfo, displayPath)
}

func resolveRedirectDisplayPath(r *http.Request) string {
	if r == nil {
		return ""
	}
	if r.URL != nil {
		if lastURL := r.URL.Query().Get("lastUrl"); lastURL != "" {
			if decoded, err := url.QueryUnescape(lastURL); err == nil {
				if parsed, err := url.Parse(decoded); err == nil && parsed.Path != "" {
					if displayPath := redirectDisplayPathFromURLPath(parsed.Path); displayPath != "" {
						return displayPath
					}
				}
			}
		}
		if displayPath := redirectDisplayPathFromURLPath(r.URL.Path); displayPath != "" {
			return displayPath
		}
	}
	return ""
}

func redirectDisplayPathFromURLPath(rawPath string) string {
	if rawPath == "" {
		return ""
	}
	switch {
	case strings.HasPrefix(rawPath, "/d/"):
		return strings.TrimPrefix(rawPath, "/d")
	case strings.HasPrefix(rawPath, "/p/"):
		return strings.TrimPrefix(rawPath, "/p")
	case strings.HasPrefix(rawPath, "/dav/"):
		return strings.TrimPrefix(rawPath, "/dav")
	default:
		return ""
	}
}

// convertDisplayToRealPath converts a display path to encrypted path for downloads
func (h *ProxyHandler) convertDisplayToRealPath(displayPath string, passwdInfo *config.PasswdInfo) string {
	if passwdInfo == nil || !passwdInfo.EncName {
		return displayPath
	}

	// First try to get cached encrypted path
	if encPath, ok := h.fileDAO.GetEncPath(displayPath); ok {
		return encPath
	}

	// Fallback: re-encrypt
	fileName := path.Base(displayPath)
	if encryption.IsOriginalFile(fileName) {
		realName := encryption.StripOriginalPrefix(fileName)
		return path.Dir(displayPath) + "/" + realName
	}

	converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
	realName := converter.ToRealName(fileName)
	return path.Dir(displayPath) + "/" + realName
}

// HandleDownload handles /d/* and /p/* download requests with decryption
func (h *ProxyHandler) HandleDownload(w http.ResponseWriter, r *http.Request) {
	displayPath := strings.TrimPrefix(r.URL.Path, "/d")
	displayPath = strings.TrimPrefix(displayPath, "/p")
	r = r.WithContext(proxy.WithDisplayName(r.Context(), path.Base(displayPath)))

	trace.Logf(r.Context(), "download", "Processing: display=%s", displayPath)

	passwdInfo, found := h.passwdDAO.FindByPath(displayPath)
	if !found {
		// Fallback: check for X-OpenEncrypt-Rule-* headers from openencrypt-android
		if headerInfo := PasswdInfoFromOpenEncryptHeaders(r); headerInfo != nil {
			passwdInfo = headerInfo
			found = true
			trace.Logf(r.Context(), "download", "Using encryption config from X-OpenEncrypt-Rule headers")
		}
	}
	if !found {
		// No encryption - proxy original path
		trace.Logf(r.Context(), "download", "No encryption, proxying directly")

		targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
			log.Error().Err(err).Str("path", displayPath).Msg("Failed to proxy download")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	// Convert display path to encrypted path if filename encryption is enabled
	realPath := displayPath
	if passwdInfo.EncName {
		realPath = h.convertDisplayToRealPath(displayPath, passwdInfo)
		trace.Logf(r.Context(), "download", "Path converted: %s -> %s", displayPath, realPath)
	}

	// Determine URL prefix first (needed for HEAD request)
	urlPrefix := "/d"
	if strings.HasPrefix(r.URL.Path, "/p") {
		urlPrefix = "/p"
	}

	// Fetch fresh upstream metadata if cache is cold or stale.
	cachedInfo, hasCache := h.fileDAO.Get(displayPath)
	stale := hasCache && cachedInfo != nil && cachedInfo.Size > 0 && strings.TrimSpace(cachedInfo.RawURL) != "" &&
		cachedInfo.UpstreamStaleness() > h.upstreamStalenessThreshold()
	if !hasCache || cachedInfo == nil ||
		cachedInfo.Size <= 0 || strings.TrimSpace(cachedInfo.RawURL) == "" || stale {
		h.prefetchDownloadMetadata(r, displayPath, realPath, stale)
	}

	// Look up file info by DISPLAY path (how PROPFIND/fs/list cached it)
	fileInfo, usedStrategy := h.getFileSizeWithStrategy(displayPath, realPath, urlPrefix, r)

	trace.Logf(r.Context(), "download", "File size: %d, strategy: %s", fileInfo.Size, usedStrategy)

	targetURL := ""
	if cachedInfo, ok := h.fileDAO.Get(displayPath); ok && strings.TrimSpace(cachedInfo.RawURL) != "" {
		targetURL = cachedInfo.RawURL
		trace.Logf(r.Context(), "download", "Using cached raw_url for target")
	}
	if targetURL == "" {
		// Build target URL with ENCRYPTED path.
		// IMPORTANT: strip query params because the original request's ?sign=xxx
		// was computed for the display path, not the encrypted path. Including it
		// would cause alist to reject the request with 401.
		targetURL = httputil.BuildTargetURLWithQuery(h.cfg.GetAlistURL(), urlPrefix+realPath, "")
	}

	trace.Logf(r.Context(), "decrypt", "Decrypting with fileSize=%d", fileInfo.Size)
	fileItem := FileItem{
		DisplayPath:      displayPath,
		EncryptedPath:    realPath,
		TargetURL:        targetURL,
		FileName:         path.Base(displayPath),
		CompatStorageKey: buildRangeCompatStorageKey(passwdInfo, displayPath),
	}
	executeDecryptPlayback(decryptPlaybackRequest{
		ResponseWriter:        w,
		Request:               r,
		Config:                h.cfg,
		Probe:                 h.probe,
		StreamProxy:           h.streamProxy,
		SizeResolver:          h.sizeResolver,
		StrategySel:           h.strategySel,
		PasswdInfo:            passwdInfo,
		FileItem:              fileItem,
		TargetURL:             targetURL,
		ProviderKey:           ProviderKey(targetURL, displayPath),
		Path:                  displayPath,
		InitialSize:           fileInfo.Size,
		OverridePath:          displayPath,
		CompatKey:             buildRangeCompatStorageKey(passwdInfo, displayPath),
		FailureLogMsg:         "Failed to decrypt download",
		FinalPassthroughCount: &h.finalPassthroughCount,
		SizeConflictCount:     &h.sizeConflictCount,
		FirstFrameCount:       &h.firstFrameCount,
		FirstFrameFallbacks:   &h.firstFrameFallbacks,
		WarmupEnqueueCount:    &h.warmupEnqueueCount,
	})
}

const (
	metadataPrefetchTimeout       = 5 * time.Second
	maxMetadataBodySize           = 64 * 1024 // 64KB limit for fs/get response
	defaultUpstreamStalenessMins  = 30        // default threshold for refreshing upstream metadata
)

func (h *ProxyHandler) prefetchDownloadMetadata(r *http.Request, displayPath, realPath string, stale bool) {
	atomic.AddUint64(&h.prefetchTotal, 1)
	if stale {
		atomic.AddUint64(&h.prefetchStaleTriggers, 1)
	}

	ctx, cancel := context.WithTimeout(r.Context(), metadataPrefetchTimeout)
	defer cancel()

	reqBody, err := json.Marshal(map[string]string{"path": realPath})
	if err != nil {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: marshal failed: %v", err)
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/get", nil)
	proxyReq, err := httputil.NewRequest(http.MethodPost, targetURL).
		WithContext(ctx).
		WithBody(reqBody).
		CopyHeadersExcept(r, "Content-Length").
		WithForwardedHeaders(r).
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: build request failed: %v", err)
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: upstream request failed: %v", err)
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: upstream returned status %d", resp.StatusCode)
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBodySize))
	if err != nil {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: read response failed: %v", err)
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: invalid JSON response")
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	data, ok := payload["data"].(map[string]interface{})
	if !ok {
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	if err := h.fileDAO.SetFromAlistResponse(displayPath, data); err != nil {
		trace.Logf(r.Context(), "download", "Skip metadata warmup: cache update failed: %v", err)
		atomic.AddUint64(&h.prefetchSkipped, 1)
		return
	}

	atomic.StoreInt64(&h.prefetchLastAt, time.Now().UnixNano())
	atomic.AddUint64(&h.prefetchSuccess, 1)
	trace.Logf(r.Context(), "download", "Metadata warmup cached size/raw_url for %s", displayPath)
}

func (h *ProxyHandler) upstreamStalenessThreshold() time.Duration {
	if h.cfg != nil && h.cfg.AlistServer.UpstreamStalenessMinutes > 0 {
		return time.Duration(h.cfg.AlistServer.UpstreamStalenessMinutes) * time.Minute
	}
	return defaultUpstreamStalenessMins * time.Minute
}

// HandleProxy handles catch-all proxy to Alist
func (h *ProxyHandler) HandleProxy(w http.ResponseWriter, r *http.Request) {
	log.Debug().Str("path", r.URL.Path).Str("method", r.Method).Msg("Proxying request")
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), r.URL.Path, r)
	log.Debug().Str("target", targetURL).Msg("Target URL")

	proxyReq, err := httputil.NewRequest(r.Method, targetURL).
		WithContext(r.Context()).
		WithBodyReader(r.Body).
		CopyHeaders(r).
		WithForwardedHeaders(r).
		Build()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create proxy request")
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Str("target", targetURL).Msg("Failed to proxy request")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	log.Debug().Str("target", targetURL).Int("status", resp.StatusCode).Msg("Proxy response")
	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")

	// Handle redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		httputil.CopyResponseHeaders(w, resp)
		location := resp.Header.Get("Location")
		if location != "" {
			parsedLoc, err := url.Parse(location)
			if err == nil {
				redirectPath := parsedLoc.Path
				// Get original request path (display path) for cache lookup
				// Strip /d or /p prefix to match how paths are cached in fs/get
				originalPath := r.URL.Path
				displayPath := strings.TrimPrefix(originalPath, "/d")
				displayPath = strings.TrimPrefix(displayPath, "/p")

				if passwdInfo, found := h.passwdDAO.FindByPath(redirectPath); found {
					var fileSize int64

					// Strategy 1: Try display path first (without /d or /p prefix)
					if fileInfo, found := h.fileDAO.Get(displayPath); found && fileInfo.Size > 0 {
						fileSize = fileInfo.Size
						trace.Logf(r.Context(), "redirect", "Found size via display path: %d", fileSize)
					}

					// Strategy 2: Try the redirect location path
					if fileSize == 0 {
						if fileInfo, found := h.fileDAO.Get(redirectPath); found && fileInfo.Size > 0 {
							fileSize = fileInfo.Size
							trace.Logf(r.Context(), "redirect", "Found size via redirect path: %d", fileSize)
						}
					}

					// Strategy 3: Use FileSizeResolver for robust resolution
					if fileSize == 0 {
						trace.Logf(r.Context(), "redirect", "Cache miss, using size resolver")
						authHeaders := make(http.Header)
						if auth := r.Header.Get("Authorization"); auth != "" {
							authHeaders.Set("Authorization", auth)
						}
						if cookie := r.Header.Get("Cookie"); cookie != "" {
							authHeaders.Set("Cookie", cookie)
						}

						file := FileItem{
							DisplayPath:   displayPath,
							EncryptedPath: redirectPath,
							TargetURL:     location,
							FileName:      path.Base(displayPath),
						}
						result := h.sizeResolver.ResolveSingle(r.Context(), file, authHeaders)
						if result.Error == nil && result.Size > 0 {
							fileSize = result.Size
							trace.Logf(r.Context(), "redirect", "Resolved size via %s: %d", result.Source, fileSize)
						}
					}

					key := h.RegisterRedirect(location, fileSize, passwdInfo, displayPath)
					lastURL := ""
					if r.URL != nil {
						lastURL = r.URL.RequestURI()
					}
					w.Header().Set("Location", buildRedirectPath(key, lastURL, true))
					w.WriteHeader(resp.StatusCode)
					return
				}
			}

			w.Header().Set("Location", rewriteUpstreamLocation(r, h.cfg.GetAlistURL(), location))
			w.WriteHeader(resp.StatusCode)
			return
		}
	}

	if shouldRewriteTextResponse(contentType) {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read textual proxy response body")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
			return
		}
		body = rewriteUpstreamTextBody(r, h.cfg.GetAlistURL(), body)
		httputil.CopyResponseHeaders(w, resp, "Content-Length")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return
	}

	httputil.CopyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	buf := proxy.GetBuffer()
	defer proxy.PutBuffer(buf)
	io.CopyBuffer(w, resp.Body, *buf)
}
