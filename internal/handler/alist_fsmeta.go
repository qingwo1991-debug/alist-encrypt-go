package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/trace"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

// HandleFsGet intercepts /api/fs/get to modify raw_url and handle filename encryption
func (h *AlistHandler) HandleFsGet(w http.ResponseWriter, r *http.Request) {
	h.handleFsGetOrLink(w, r, "/api/fs/get")
}

// HandleFsLink intercepts /api/fs/link for newer OpenList clients.
func (h *AlistHandler) HandleFsLink(w http.ResponseWriter, r *http.Request) {
	h.handleFsGetOrLink(w, r, "/api/fs/link")
}

func (h *AlistHandler) handleFsGetOrLink(w http.ResponseWriter, r *http.Request, apiPath string) {
	body, err := readLimitedRequestBody(r)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	filePath, _ := reqData["path"].(string)
	originalPath := filePath
	trace.Logf(r.Context(), "get", "Processing %s path: %s", apiPath, filePath)

	// Single-file reads signal the parent directory is in use: record it for
	// snapshot prewarming so browsing back into that directory stays warm.
	if h.dirSyncStore != nil {
		if parent := path.Dir(filePath); parent != "" && parent != "." && parent != "/" && h.snapshotScopeEnabled(parent) {
			reqHeaders := h.requestAuthHeaders(r)
			h.rememberRecentList(parent, buildDirScopeKey(parent, h.requestScopeHash(reqHeaders)), reqHeaders)
		}
	}

	// Check if filename encryption is needed
	passwdInfo, found := h.passwdDAO.PathFindPasswd(filePath)
	if !found {
		// Fallback: check for X-OpenEncrypt-Rule-* headers from openencrypt-android
		if headerInfo := PasswdInfoFromOpenEncryptHeaders(r); headerInfo != nil {
			passwdInfo = headerInfo
			found = true
			trace.Logf(r.Context(), "get", "Using encryption config from X-OpenEncrypt-Rule headers")
		}
	}
	if found && passwdInfo.EncName {
		if !h.isEncryptedDirRoot(filePath) {
			// Check if it's a directory first
			fileInfo, exists := h.fileDAO.Get(url.QueryEscape(filePath))
			if !exists || !fileInfo.IsDir {
				// First try to get cached encrypted path
				if encPath, ok := h.fileDAO.GetEncPath(filePath); ok {
					filePath = encPath
					reqData["path"] = filePath
					trace.Logf(r.Context(), "get", "Using cached enc path: %s -> %s", originalPath, filePath)
				} else {
					// Fallback: re-encrypt (for backwards compatibility)
					converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
					fileName := path.Base(filePath)
					realName := converter.ToRealName(fileName)
					filePath = path.Dir(filePath) + "/" + realName
					reqData["path"] = filePath
					trace.Logf(r.Context(), "get", "Fallback enc: %s -> %s", originalPath, filePath)
				}
			}
		}
	}

	// Marshal updated request
	modifiedBody, _ := json.Marshal(reqData)

	// Forward to Alist
	trace.Logf(r.Context(), "get", "Alist URL: %s", h.cfg.GetAlistURL())
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), apiPath, nil)
	trace.Logf(r.Context(), "get", "Target for %s: %s", apiPath, targetURL)
	cacheAllowed := true
	if refresh, ok := reqData["refresh"].(bool); ok && refresh {
		cacheAllowed = false
		if h.cfg.AlistServerSnapshot().PlaybackProfile == config.PlaybackProfileTrustedLocal && h.fileDAO != nil {
			h.fileDAO.InvalidateDisplayPath(originalPath)
		}
	}
	upstream, cacheHit, shared, err := h.fetchFSMetaUpstream(r, apiPath, targetURL, modifiedBody, cacheAllowed)
	if err != nil {
		log.Error().Err(err).Str("api_path", apiPath).Msg("Failed to proxy fs/get-or-link")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	if cacheHit {
		trace.Logf(r.Context(), "get", "%s metadata hot cache hit shared=%v failure_fast=%v", apiPath, shared, upstream.FailureFast)
	}
	respBody := upstream.Body

	// Log Alist response (truncate to 500 chars)
	respPreview := string(respBody)
	if len(respPreview) > 500 {
		respPreview = respPreview[:500]
	}
	trace.Logf(r.Context(), "get", "Alist response status=%d body=%s", upstream.StatusCode, respPreview)

	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		RespondRaw(w, upstream.StatusCode, upstream.Header.Get("Content-Type"), respBody)
		return
	}

	// Process response
	if found {
		if data, ok := respData["data"].(map[string]interface{}); ok {
			// Decrypt filename for display
			if passwdInfo.EncName {
				if name, ok := data["name"].(string); ok {
					showName := h.convertShowName(passwdInfo, name)
					data["name"] = showName
					normalizeDecryptedListItem(data, showName)
				}
			}

			// Modify raw_url for encrypted files
			if rawURL, ok := data["raw_url"].(string); ok && rawURL != "" {
				ciphertextSize := int64(0)
				if size, ok := data["size"].(float64); ok {
					ciphertextSize = int64(size)
				}
				meta := h.contentMetaOrProbe(r, rawURL, originalPath, filePath, ciphertextSize, passwdInfo)
				fileSize := ciphertextSize
				if (meta.IsV2() || meta.IsV3()) && meta.PlainSize >= 0 {
					fileSize = meta.PlainSize
					data["size"] = float64(fileSize)
				}
				if fileSize > 0 {
					h.upsertMetaFromListing(r.Context(), originalPath, fileSize)
				}
				h.enqueueProbeFromList(r, originalPath, fileSize)
				_ = h.fileDAO.Set(&dao.FileInfo{
					Path:            originalPath,
					EncryptedPath:   filePath,
					Name:            path.Base(originalPath),
					Size:            fileSize,
					CiphertextSize:  ciphertextSize,
					ContentVersion:  meta.Version,
					HeaderLen:       meta.HeaderLen,
					NonceField:      append([]byte(nil), meta.NonceField...),
					ChunkSize:       meta.ChunkSize,
					KDFIterations:   meta.KDFIterations,
					IsDir:           false,
					RawURL:          rawURL,
					RawURLAuthScope: rawURLAuthScope(r.Header),
					Sign:            func() string { v, _ := data["sign"].(string); return v }(),
				})

				// Register redirect and update URL
				key := h.proxyHandler.RegisterRedirect(rawURL, fileSize, passwdInfo, originalPath)
				redirectPath := buildRedirectPath(key, originalPath, true)
				data["raw_url"] = buildRedirectURL(r, redirectPath)
			} else {
				h.fileDAO.SetFromAlistResponse(originalPath, data, rawURLAuthScope(r.Header))
			}

			if provider, ok := data["provider"].(string); ok && provider == "AliyundriveOpen" {
				data["provider"] = "Local"
			}
		}
	} else {
		// Still cache file info even without encryption
		if data, ok := respData["data"].(map[string]interface{}); ok {
			h.fileDAO.SetFromAlistResponse(filePath, data, rawURLAuthScope(r.Header))
		}
	}

	RespondJSON(w, upstream.StatusCode, respData)
}

func (h *AlistHandler) fetchFSMetaUpstream(r *http.Request, apiPath, targetURL string, body []byte, cacheAllowed bool) (*fsMetaUpstreamResponse, bool, bool, error) {
	atomic.AddUint64(&h.fsMetaRequests, 1)
	if !cacheAllowed {
		atomic.AddUint64(&h.fsMetaRefreshBypass, 1)
	}
	cacheKey := fsMetaCacheKey(apiPath, targetURL, body, r.Header)
	if cacheAllowed {
		if cached, ok := h.getFSMetaCache(cacheKey); ok {
			atomic.AddUint64(&h.fsMetaCacheHits, 1)
			if cached.FailureFast {
				atomic.AddUint64(&h.fsMetaFailureFastHits, 1)
			}
			return cached, true, false, nil
		}
	}

	result, err, shared := h.fsMetaGroup.Do(cacheKey, func() (interface{}, error) {
		if cacheAllowed {
			if cached, ok := h.getFSMetaCache(cacheKey); ok {
				return fsMetaFetchResult{Response: cached, CacheHit: true}, nil
			}
		}
		upstream, err := h.fetchFSMetaFromAlist(r, apiPath, targetURL, body)
		if err != nil {
			return nil, err
		}
		if cacheAllowed {
			h.setFSMetaCache(cacheKey, upstream)
		}
		return fsMetaFetchResult{Response: upstream}, nil
	})
	if err != nil {
		return nil, false, shared, err
	}
	fetched, ok := result.(fsMetaFetchResult)
	if !ok || fetched.Response == nil {
		return nil, false, shared, fmt.Errorf("unexpected fs metadata response type")
	}
	if shared {
		atomic.AddUint64(&h.fsMetaSingleflightHits, 1)
	}
	if fetched.CacheHit {
		atomic.AddUint64(&h.fsMetaCacheHits, 1)
		if fetched.Response.FailureFast {
			atomic.AddUint64(&h.fsMetaFailureFastHits, 1)
		}
	}
	return cloneFSMetaResponse(fetched.Response), fetched.CacheHit, shared, nil
}

func (h *AlistHandler) fetchFSMetaFromAlist(r *http.Request, apiPath, targetURL string, body []byte) (*fsMetaUpstreamResponse, error) {
	atomic.AddUint64(&h.fsMetaUpstreamFetches, 1)
	ctx := context.Background()
	cancel := func() {}
	if timeout := getAlistRequestTimeout(h.cfg); timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	proxyReq, err := httputil.NewRequest("POST", targetURL).
		WithContext(ctx).
		WithBody(body).
		CopyHeadersExcept(r, "Content-Length").
		WithForwardedHeaders(r).
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		return nil, err
	}
	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		return nil, err
	}
	return &fsMetaUpstreamResponse{
		StatusCode: resp.StatusCode,
		Header:     cloneHeader(resp.Header),
		Body:       append([]byte(nil), respBody...),
	}, nil
}

func fsMetaCacheKey(apiPath, targetURL string, body []byte, headers http.Header) string {
	bodyHash := sha256.Sum256(body)
	authHash := sha256.Sum256([]byte(headers.Get("Authorization") + "\x00" + headers.Get("Cookie")))
	return fmt.Sprintf("%s|%s|%x|%x", apiPath, targetURL, bodyHash[:8], authHash[:8])
}

func (h *AlistHandler) getFSMetaCache(key string) (*fsMetaUpstreamResponse, bool) {
	if h == nil || key == "" {
		return nil, false
	}
	h.fsMetaMu.Lock()
	defer h.fsMetaMu.Unlock()
	if h.fsMetaCache == nil {
		return nil, false
	}
	entry, ok := h.fsMetaCache[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(h.fsMetaCache, key)
		return nil, false
	}
	return &fsMetaUpstreamResponse{
		StatusCode:  entry.StatusCode,
		Header:      cloneHeader(entry.Header),
		Body:        append([]byte(nil), entry.Body...),
		FailureFast: entry.FailureFast,
	}, true
}

func (h *AlistHandler) setFSMetaCache(key string, upstream *fsMetaUpstreamResponse) {
	if h == nil || key == "" || upstream == nil {
		return
	}
	ttl := fsMetaHotCacheTTL
	failureFast := false
	if upstream.StatusCode >= http.StatusBadRequest {
		ttl = fsMetaFailureCacheTTL
		failureFast = true
		atomic.AddUint64(&h.fsMetaFailureStores, 1)
	}
	h.fsMetaMu.Lock()
	defer h.fsMetaMu.Unlock()
	if h.fsMetaCache == nil {
		h.fsMetaCache = make(map[string]fsMetaCacheEntry)
	}
	now := time.Now()
	if len(h.fsMetaCache) >= maxFSMetaCacheEntries {
		for cacheKey, entry := range h.fsMetaCache {
			if now.After(entry.ExpiresAt) {
				delete(h.fsMetaCache, cacheKey)
			}
		}
	}
	if len(h.fsMetaCache) >= maxFSMetaCacheEntries {
		for cacheKey := range h.fsMetaCache {
			delete(h.fsMetaCache, cacheKey)
			break
		}
	}
	h.fsMetaCache[key] = fsMetaCacheEntry{
		StatusCode:  upstream.StatusCode,
		Header:      cloneHeader(upstream.Header),
		Body:        append([]byte(nil), upstream.Body...),
		ExpiresAt:   now.Add(ttl),
		FailureFast: failureFast,
	}
}

func cloneFSMetaResponse(src *fsMetaUpstreamResponse) *fsMetaUpstreamResponse {
	if src == nil {
		return nil
	}
	return &fsMetaUpstreamResponse{
		StatusCode:  src.StatusCode,
		Header:      cloneHeader(src.Header),
		Body:        append([]byte(nil), src.Body...),
		FailureFast: src.FailureFast,
	}
}

// contentMetaOrProbe returns the content metadata for an encrypted file.
// When the fileDAO already holds a previously probed ContentMeta (from an
// earlier fs/get or playback) whose ciphertext size still matches the current
// listing, that stable content metadata is reused directly — no upstream
// header probe on every fs/get (fires only on cache miss or size change).
// displayPath is the FileInfo cache key (how fs/get persists the record);
// encryptedPath is used to build the fallback probe candidate URLs.
func (h *AlistHandler) contentMetaOrProbe(r *http.Request, rawURL, displayPath, encryptedPath string, ciphertextSize int64, passwdInfo *config.PasswdInfo) encryption.ContentMeta {
	if h != nil && h.fileDAO != nil && passwdInfo != nil {
		if info, ok := h.fileDAO.Get(displayPath); ok && info != nil && info.ContentVersion > 0 {
			if (info.ContentVersion != encryption.ContentVersionV2 || len(info.NonceField) == 16) &&
				(info.ContentVersion != encryption.ContentVersionV3 || (len(info.NonceField) == 16 && info.ChunkSize > 0 && info.KDFIterations > 0)) &&
				(ciphertextSize <= 0 || info.CiphertextSize <= 0 || info.CiphertextSize == ciphertextSize) {
				log.Info().
					Str("category", "fsget").
					Str("path", displayPath).
					Int("content_version", info.ContentVersion).
					Int64("header_len", info.HeaderLen).
					Int64("cached_size", info.CiphertextSize).
					Int64("listing_size", ciphertextSize).
					Msg("fs/get content meta cache hit")
				return encryption.ContentMeta{
					EncType:        encryption.EncType(passwdInfo.EncType),
					Version:        info.ContentVersion,
					HeaderLen:      info.HeaderLen,
					PlainSize:      info.Size,
					CiphertextSize: info.CiphertextSize,
					NonceField:     append([]byte(nil), info.NonceField...),
					ChunkSize:      info.ChunkSize,
					KDFIterations:  info.KDFIterations,
				}
			}
		}
	}
	trace.Logf(r.Context(), "get", "fs/get content meta MISS display=%s cipher=%d", displayPath, ciphertextSize)
	return h.inspectContentMetaWithFallback(r, rawURL, encryptedPath, ciphertextSize, passwdInfo)
}

func (h *AlistHandler) inspectContentMetaWithFallback(r *http.Request, rawURL, encryptedPath string, ciphertextSize int64, passwdInfo *config.PasswdInfo) encryption.ContentMeta {
	authVariants := buildProbeAuthVariants(h.cfg, r.Header)
	meta := encryption.LegacyContentMeta(encryption.EncType(passwdInfo.EncType), ciphertextSize)
	candidates := []string{rawURL}
	if h != nil && h.cfg != nil && strings.TrimSpace(encryptedPath) != "" {
		alistURL := strings.TrimSpace(h.cfg.GetAlistURL())
		if alistURL != "" {
			candidates = append(candidates,
				httputil.BuildTargetURLWithQuery(alistURL, "/dav"+encryptedPath, ""),
				httputil.BuildTargetURLWithQuery(alistURL, "/d"+encryptedPath, ""),
			)
		}
	}
	result, confirmedCandidate := probeCandidateCandidatesContext(r.Context(), h.cfg, candidates, authVariants, func(ctx context.Context, candidate string, headers http.Header) proxy.ContentInspectionResult {
		return h.streamProxy.InspectEncryptedContentResult(ctx, candidate, headers, passwdInfo, ciphertextSize)
	})
	if result.Confirmed {
		if result.Meta.IsV2() && result.Meta.PlainSize > 0 {
			trace.Logf(r.Context(), "get", "Detected V%s content via probe target=%s plain=%d cipher=%d", contentVersionLabel(result.Meta), confirmedCandidate, result.Meta.PlainSize, result.Meta.CiphertextSize)
		}
		return result.Meta
	}
	return meta
}

func contentVersionLabel(meta encryption.ContentMeta) string {
	if meta.IsV3() {
		return "V3"
	}
	if meta.IsV2() {
		return "V2"
	}
	return "V1"
}
