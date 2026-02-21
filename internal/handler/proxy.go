package handler

import (
	"crypto/md5"
	"encoding/hex"
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
	finalPassthroughCount uint64
	sizeConflictCount     uint64
	strategyFallbackCount uint64
}

const maxRedirectEntries = 10000

type redirectInfo struct {
	URL       string
	FileSize  int64
	Password  string
	EncType   string
	EncName   bool
	ExpiresAt time.Time
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
		},
		"strategy_selector": func() map[string]interface{} {
			if h.strategySel != nil {
				return h.strategySel.Stats()
			}
			return nil
		}(),
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

	lastURL := r.URL.Query().Get("lastUrl")
	if lastURL != "" {
		if decoded, err := url.QueryUnescape(lastURL); err == nil {
			if parsed, err := url.Parse(decoded); err == nil {
				if parsed.Path != "" {
					r.URL.Path = parsed.Path
				}
			}
		}
	}

	decodeParam := r.URL.Query().Get("decode")
	decryptEnabled := decodeParam != "0"

	if strings.Contains(info.URL, "baidupcs.com") {
		r.Header.Set("User-Agent", "pan.baidu.com")
	}
	r.Header.Del("Referer")
	r.Header.Del("Authorization")
	r.Header.Del("Host")
	r.Host = ""
	if !decryptEnabled || info.FileSize == 0 {
		if err := h.streamProxy.ProxyRequest(w, r, info.URL); err != nil {
			log.Error().Err(err).Str("key", key).Msg("Failed to proxy redirect (passthrough)")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	passwdInfo := &config.PasswdInfo{
		Password: info.Password,
		EncType:  info.EncType,
		EncName:  info.EncName,
		Enable:   true,
	}

	if err := h.streamProxy.ProxyDownloadDecrypt(w, r, info.URL, passwdInfo, info.FileSize); err != nil {
		log.Error().Err(err).Str("key", key).Msg("Failed to proxy redirect")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
	}
}

// RegisterRedirect registers a URL for redirect decryption and returns the key
func (h *ProxyHandler) RegisterRedirect(url string, fileSize int64, password, encType string, encName bool) string {
	hash := md5.Sum([]byte(fmt.Sprintf("%s:%d:%d", url, fileSize, time.Now().UnixNano())))
	key := hex.EncodeToString(hash[:])

	h.redirectMap.Store(key, &redirectInfo{
		URL:       url,
		FileSize:  fileSize,
		Password:  password,
		EncType:   encType,
		EncName:   encName,
		ExpiresAt: time.Now().Add(72 * time.Hour),
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

	key := h.RegisterRedirect(location, fileSize, passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncName)
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

	trace.Logf(r.Context(), "download", "Processing: display=%s", displayPath)

	passwdInfo, found := h.passwdDAO.FindByPath(displayPath)
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

	// Look up file info by DISPLAY path (how PROPFIND/fs/list cached it)
	fileInfo, usedStrategy := h.getFileSizeWithStrategy(displayPath, realPath, urlPrefix, r)

	trace.Logf(r.Context(), "download", "File size: %d, strategy: %s", fileInfo.Size, usedStrategy)

	// Build target URL with ENCRYPTED path
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), urlPrefix+realPath, r)

	trace.Logf(r.Context(), "decrypt", "Decrypting with fileSize=%d", fileInfo.Size)
	fileItem := FileItem{
		DisplayPath:   displayPath,
		EncryptedPath: realPath,
		TargetURL:     targetURL,
		FileName:      path.Base(displayPath),
	}
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}
	if fileInfo.Size == 0 {
		if h.sizeResolver != nil {
			fresh := h.sizeResolver.ResolveSingleFresh(r.Context(), fileItem, authHeaders)
			if fresh.Error == nil && fresh.Size > 0 {
				fileInfo.Size = fresh.Size
			}
		}
	}
	if fileInfo.Size == 0 {
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
			log.Error().Err(err).Str("path", displayPath).Msg("Failed to proxy download (size unknown)")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}
	providerKey := ProviderKey(targetURL, displayPath)
	compatStorageKey := buildRangeCompatStorageKey(passwdInfo, displayPath)
	strategies := []proxy.StreamStrategy{proxy.StreamStrategyRange}
	if override, ok := selectStrategyOverride(h.cfg, displayPath); ok {
		strategies = []proxy.StreamStrategy{override}
	} else if h.strategySel != nil {
		strategies = h.strategySel.Select(providerKey)
	}

	tryStream := func(size int64) (bool, bool, string, error) {
		var lastErr error
		var lastFailure string
		var responseStarted bool

		for _, strategy := range strategies {
			result := h.streamProxy.ProxyDownloadDecryptWithStrategyForStorage(w, r, targetURL, passwdInfo, size, strategy, compatStorageKey)
			if result.Err == nil && !result.Retryable {
				if h.strategySel != nil && !result.NoLearning {
					h.strategySel.RecordSuccess(providerKey, strategy)
				}
				if h.sizeResolver != nil && r.Method == http.MethodGet && !result.NoLearning {
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
				if !result.NoLearning {
					if result.Retryable && !result.ResponseStarted {
						if isNonStrategyFailure(reason) {
							trace.Logf(r.Context(), "network-skip", "reason: %s, provider=%s, path=%s", reason, providerKey, displayPath)
						} else {
							trace.Logf(r.Context(), "strategy-fallback", "reason: %s, strategy=%s, provider=%s, path=%s", reason, strategy, providerKey, displayPath)
							atomic.AddUint64(&h.strategyFallbackCount, 1)
						}
					}
					h.strategySel.RecordFailure(providerKey, strategy, reason)
				}
			}

			if result.Err != nil {
				lastErr = result.Err
			} else if result.Retryable {
				lastErr = fmt.Errorf("strategy %s failed", strategy)
			}
			responseStarted = responseStarted || result.ResponseStarted
			if result.ResponseStarted || !result.Retryable {
				if lastErr != nil {
					log.Error().Err(lastErr).Str("path", displayPath).Msg("Failed to decrypt download")
				}
				return false, responseStarted, lastFailure, lastErr
			}
		}

		if lastFailure == "range_unsatisfiable" && !responseStarted {
			fallback := h.streamProxy.ProxyDownloadDecryptWithStrategyForStorage(w, r, targetURL, passwdInfo, size, proxy.StreamStrategyFull, compatStorageKey)
			if fallback.Err == nil && !fallback.Retryable {
				if h.strategySel != nil && !fallback.NoLearning {
					h.strategySel.RecordSuccess(providerKey, proxy.StreamStrategyFull)
				}
				if h.sizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
					metaSize := size
					if fallback.ExpectedBytes > 0 {
						metaSize = fallback.ExpectedBytes
					}
					h.sizeResolver.RecordPlaybackSuccess(r.Context(), fileItem, metaSize, fallback.StatusCode, fallback.ContentType, fallback.ETag)
				}
				return true, fallback.ResponseStarted, "", nil
			}
			lastErr = fallback.Err
			lastFailure = "range_unsatisfiable"
			responseStarted = responseStarted || fallback.ResponseStarted
		}
		return false, responseStarted, lastFailure, lastErr
	}

	success, responseStarted, lastFailure, lastErr := tryStream(fileInfo.Size)
	if success {
		return
	}

	if !responseStarted && h.sizeResolver != nil {
		fresh := h.sizeResolver.ResolveSingleFresh(r.Context(), fileItem, authHeaders)
		if fresh.Error == nil && fresh.Size > 0 {
			if fileInfo.Size > 0 && fresh.Size != fileInfo.Size {
				h.sizeResolver.RecordMetaConflict(providerKey)
				atomic.AddUint64(&h.sizeConflictCount, 1)
			}
			fileInfo.Size = fresh.Size
			success, responseStarted, lastFailure, lastErr = tryStream(fileInfo.Size)
			if success {
				return
			}
		}
	}

	if !responseStarted && lastFailure != "range_unsatisfiable" && h.cfg != nil && h.cfg.AlistServer.PlayFirstFallback {
		trace.Logf(r.Context(), "play-first-fallback", "Proxying without decrypt as final fallback")
		atomic.AddUint64(&h.finalPassthroughCount, 1)
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err == nil {
			return
		} else {
			lastErr = err
		}
	}

	if lastFailure == "range_unsatisfiable" {
		RespondHTTPErrorWithStatus(w, "Range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if lastErr != nil {
		log.Error().Err(lastErr).Str("path", displayPath).Msg("Failed to decrypt download")
		RespondHTTPErrorWithStatus(w, "Decryption error", http.StatusBadGateway)
	}
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
	httputil.CopyResponseHeaders(w, resp)

	// Handle redirects
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
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

					key := h.RegisterRedirect(location, fileSize, passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncName)
					lastURL := ""
					if r.URL != nil {
						lastURL = r.URL.RequestURI()
					}
					w.Header().Set("Location", buildRedirectPath(key, lastURL, true))
					w.WriteHeader(resp.StatusCode)
					return
				}
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Inject version for HTML
	if strings.Contains(contentType, "text/html") {
		const maxHTMLSize = 10 * 1024 * 1024
		limitedReader := io.LimitReader(resp.Body, maxHTMLSize)
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read response body")
			return
		}
		modified := strings.Replace(string(body), "</head>", "<!-- alist-encrypt-go --></head>", 1)
		w.Write([]byte(modified))
		return
	}

	buf := proxy.GetBuffer()
	defer proxy.PutBuffer(buf)
	io.CopyBuffer(w, resp.Body, *buf)
}
