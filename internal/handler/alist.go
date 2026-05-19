package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/trace"
)

// AlistHandler handles Alist API interception
type AlistHandler struct {
	cfg          *config.Config
	streamProxy  *proxy.StreamProxy
	httpClient   *http.Client
	fileDAO      *dao.FileDAO
	passwdDAO    *dao.PasswdDAO
	proxyHandler *ProxyHandler
	metaStore    FileMetaStore
	probe        *ProbeScheduler
}

// NewAlistHandler creates a new Alist handler
// proxyHandler must be the same instance used for /redirect routes
func NewAlistHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO, proxyHandler *ProxyHandler, metaStore FileMetaStore, probe *ProbeScheduler) *AlistHandler {
	return &AlistHandler{
		cfg:          cfg,
		streamProxy:  streamProxy,
		httpClient:   proxy.NewHTTPClient(cfg, getAlistRequestTimeout(cfg)),
		fileDAO:      fileDAO,
		passwdDAO:    passwdDAO,
		proxyHandler: proxyHandler,
		metaStore:    metaStore,
		probe:        probe,
	}
}

// decryptResult holds the result of parallel filename decryption
type decryptResult struct {
	index    int
	showName string
}

const (
	parallelDecryptThreshold = 5
	maxParallelDecryptLimit  = 32
)

var mediaTypeByExt = map[string]float64{
	// video
	".mp4": 2, ".mkv": 2, ".avi": 2, ".mov": 2,
	".wmv": 2, ".flv": 2, ".webm": 2, ".m4v": 2,
	".ts": 2, ".rmvb": 2, ".rm": 2, ".3gp": 2,
	// image
	".jpg": 5, ".jpeg": 5, ".png": 5, ".gif": 5,
	".bmp": 5, ".webp": 5, ".svg": 5, ".avif": 5,
}

func (h *AlistHandler) parallelDecryptEnabled() bool {
	return h.cfg != nil && h.cfg.AlistServer.EnableParallelDecrypt
}

func (h *AlistHandler) parallelDecryptLimit() int {
	limit := 4
	if h.cfg != nil && h.cfg.AlistServer.ParallelDecryptConcurrency > 0 {
		limit = h.cfg.AlistServer.ParallelDecryptConcurrency
	}
	if limit < 1 {
		limit = 1
	}
	if limit > maxParallelDecryptLimit {
		limit = maxParallelDecryptLimit
	}
	return limit
}

func (h *AlistHandler) convertShowName(passwdInfo *config.PasswdInfo, name string) string {
	allowLoose := h.cfg != nil && h.cfg.AlistServer.AllowLooseDecode
	return encryption.ConvertShowNameWithSuffixOptions(passwdInfo.Password, passwdInfo.EncType, name, passwdInfo.EncSuffix, allowLoose)
}

// normalizeDecryptedListItem keeps display fields aligned with decrypted filename,
// so frontend preview strategy won't be stuck on encrypted suffix/type (e.g. ".bin").
func normalizeDecryptedListItem(fileData map[string]interface{}, showName string) {
	if fileData == nil || showName == "" {
		return
	}

	if pathText, ok := fileData["path"].(string); ok && pathText != "" {
		fileData["path"] = path.Join(path.Dir(pathText), showName)
	}

	ext := strings.ToLower(path.Ext(showName))
	if fileType, ok := mediaTypeByExt[ext]; ok {
		fileData["type"] = fileType
	}
}

type fsSearchRequest struct {
	Parent   string `json:"parent"`
	Path     string `json:"path"`
	Keywords string `json:"keywords"`
	Scope    int    `json:"scope"`
	Page     int    `json:"page"`
	PerPage  int    `json:"per_page"`
	Refresh  bool   `json:"refresh"`
}

func containsSearchTerm(value, keyword string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	keyword = strings.TrimSpace(strings.ToLower(keyword))
	if value == "" || keyword == "" {
		return false
	}
	return strings.Contains(value, keyword)
}

func cloneStringMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return nil
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func resolveSearchRootPath(reqData fsSearchRequest) string {
	candidates := []string{
		strings.TrimSpace(reqData.Path),
		strings.TrimSpace(reqData.Parent),
	}
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return "/"
}

func extractSearchRootFromPattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return ""
	}

	var b strings.Builder
	for _, r := range pattern {
		switch r {
		case '*', '+', '?', '[', ']', '(', ')', '{', '}', '|', '^', '$', '.', '\\':
			return strings.TrimRight(b.String(), "/")
		default:
			b.WriteRune(r)
		}
	}

	return strings.TrimRight(b.String(), "/")
}

func (h *AlistHandler) collectEncryptedSearchRoots() []string {
	seen := make(map[string]struct{})
	roots := make([]string, 0)

	if h.cfg == nil {
		return roots
	}

	for i := range h.cfg.AlistServer.PasswdList {
		passwdInfo := &h.cfg.AlistServer.PasswdList[i]
		if !passwdInfo.Enable {
			continue
		}
		for _, pattern := range passwdInfo.EncPath {
			root := extractSearchRootFromPattern(pattern)
			if root == "" {
				continue
			}
			if _, ok := seen[root]; ok {
				continue
			}
			seen[root] = struct{}{}
			roots = append(roots, root)
		}
	}

	return roots
}

func (h *AlistHandler) resolveRemoveName(dirPath, name string, passwdInfo *config.PasswdInfo) string {
	displayPath := path.Join(dirPath, name)

	if encPath, ok := h.fileDAO.GetEncPath(displayPath); ok {
		return path.Base(encPath)
	}

	if fileInfo, ok := h.fileDAO.Get(url.QueryEscape(displayPath)); ok && fileInfo != nil && fileInfo.Path != "" {
		if base := path.Base(fileInfo.Path); base != "" {
			return base
		}
	}

	if passwdInfo != nil && passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileName := path.Base(name)
		encBase := strings.TrimSuffix(fileName, path.Ext(fileName))
		if converter.DecryptFileName(encBase) != "" {
			return name
		}
		if strings.HasPrefix(fileName, encryption.OrigPrefix) {
			return strings.TrimPrefix(fileName, encryption.OrigPrefix)
		}
		return converter.ToRealName(name)
	}

	return name
}

func (h *AlistHandler) resolveRemoveNames(dirPath string, names []string, passwdInfo *config.PasswdInfo) []string {
	if len(names) == 0 {
		return nil
	}

	resolved := make([]string, 0, len(names))
	for _, name := range names {
		resolved = append(resolved, h.resolveRemoveName(dirPath, name, passwdInfo))
	}
	return resolved
}

func (h *AlistHandler) fetchFsListContent(r *http.Request, realPath string) ([]interface{}, error) {
	const perPage = 1000

	var all []interface{}
	for page := 1; ; page++ {
		reqData := map[string]interface{}{
			"path":     realPath,
			"page":     page,
			"per_page": perPage,
			"refresh":  false,
		}
		body, _ := json.Marshal(reqData)
		resp, err := h.proxyToAlist(nil, "POST", "/api/fs/list", body, r)
		if err != nil {
			return nil, err
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var respData map[string]interface{}
		if err := json.Unmarshal(respBody, &respData); err != nil {
			return nil, err
		}
		code, _ := respData["code"].(float64)
		if code != 200 {
			return nil, fmt.Errorf("list failed with code %.0f", code)
		}
		data, _ := respData["data"].(map[string]interface{})
		if data == nil {
			return nil, nil
		}
		content, _ := data["content"].([]interface{})
		if len(content) == 0 {
			break
		}
		all = append(all, content...)
		if len(content) < perPage {
			break
		}
	}

	return all, nil
}

func (h *AlistHandler) searchEncryptedTree(r *http.Request, rootPath, keyword string, scope int, passwdInfo *config.PasswdInfo) ([]interface{}, int, error) {
	type node struct {
		displayPath string
		realPath    string
	}

	recursive := scope != 0
	queue := []node{{
		displayPath: rootPath,
		realPath:    rootPath,
	}}
	visited := make(map[string]struct{})
	var matches []interface{}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := visited[current.realPath]; ok {
			continue
		}
		visited[current.realPath] = struct{}{}

		currentPasswd, found := h.passwdDAO.PathFindPasswd(current.displayPath)
		if !found || currentPasswd == nil {
			currentPasswd = passwdInfo
		}

		content, err := h.fetchFsListContent(r, current.realPath)
		if err != nil {
			return nil, 0, err
		}

		for _, item := range content {
			fileData, ok := item.(map[string]interface{})
			if !ok {
				continue
			}

			rawName, _ := fileData["name"].(string)
			isDir, _ := fileData["is_dir"].(bool)
			if rawName == "" {
				continue
			}

			childDisplayName := rawName
			if currentPasswd != nil && currentPasswd.EncName {
				childDisplayName = h.convertShowName(currentPasswd, rawName)
			}
			if childDisplayName == "" {
				childDisplayName = rawName
			}

			childDisplayPath := path.Join(current.displayPath, childDisplayName)
			childRealPath := path.Join(current.realPath, rawName)

			matchTarget := strings.ToLower(childDisplayName + " " + childDisplayPath + " " + rawName)
			if containsSearchTerm(matchTarget, keyword) {
				normalized := cloneStringMap(fileData)
				normalized["name"] = childDisplayName
				normalized["path"] = childDisplayPath
				if currentPasswd != nil && currentPasswd.EncName {
					normalizeDecryptedListItem(normalized, childDisplayName)
					h.fileDAO.SetEncPathMapping(childDisplayPath, childRealPath)
				}
				matches = append(matches, normalized)
			}

			if recursive && isDir {
				queue = append(queue, node{
					displayPath: childDisplayPath,
					realPath:    childRealPath,
				})
			}
		}
	}

	return matches, len(matches), nil
}

func (h *AlistHandler) searchAllEncryptedRoots(r *http.Request, keyword string, scope int) ([]interface{}, int, error) {
	roots := h.collectEncryptedSearchRoots()
	if len(roots) == 0 {
		return nil, 0, nil
	}

	var matches []interface{}
	for _, root := range roots {
		passwdInfo, found := h.passwdDAO.PathFindPasswd(root)
		if !found || passwdInfo == nil {
			if dirPasswd, ok := h.passwdDAO.FindByDir(root); ok {
				passwdInfo = dirPasswd
				found = true
			}
		}
		if !found || passwdInfo == nil || !passwdInfo.EncName {
			continue
		}

		rootMatches, _, err := h.searchEncryptedTree(r, root, keyword, scope, passwdInfo)
		if err != nil {
			return nil, 0, err
		}
		matches = append(matches, rootMatches...)
	}

	return matches, len(matches), nil
}

// HandleFsSearch intercepts /api/fs/search to search by display names for encrypted paths.
func (h *AlistHandler) HandleFsSearch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData fsSearchRequest
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	rootPath := resolveSearchRootPath(reqData)

	keyword := strings.TrimSpace(reqData.Keywords)
	passwdInfo, found := h.passwdDAO.PathFindPasswd(rootPath)
	if !found {
		if dirPasswd, ok := h.passwdDAO.FindByDir(rootPath); ok {
			passwdInfo = dirPasswd
			found = true
		}
	}
	if keyword == "" || !found || passwdInfo == nil || !passwdInfo.EncName {
		if keyword != "" {
			if matches, total, err := h.searchAllEncryptedRoots(r, keyword, reqData.Scope); err == nil && (total > 0 || rootPath == "/" || found) {
				page := reqData.Page
				if page <= 0 {
					page = 1
				}
				perPage := reqData.PerPage
				if perPage <= 0 {
					perPage = 20
				}

				start := (page - 1) * perPage
				if start > total {
					start = total
				}
				end := start + perPage
				if end > total {
					end = total
				}

				content := make([]interface{}, 0, end-start)
				if start < end {
					content = append(content, matches[start:end]...)
				}

				RespondJSON(w, http.StatusOK, map[string]interface{}{
					"code":    200,
					"message": "success",
					"data": map[string]interface{}{
						"content": content,
						"total":   total,
					},
				})
				return
			}
		}

		resp, err := h.proxyToAlist(nil, "POST", "/api/fs/search", body, r)
		if err != nil {
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		RespondRaw(w, resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return
	}

	matches, total, err := h.searchEncryptedTree(r, rootPath, keyword, reqData.Scope, passwdInfo)
	if err != nil {
		log.Warn().Err(err).Str("path", rootPath).Msg("Encrypted search failed, falling back to upstream search")
		resp, proxyErr := h.proxyToAlist(nil, "POST", "/api/fs/search", body, r)
		if proxyErr != nil {
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		respBody, _ := io.ReadAll(resp.Body)
		RespondRaw(w, resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return
	}

	page := reqData.Page
	if page <= 0 {
		page = 1
	}
	perPage := reqData.PerPage
	if perPage <= 0 {
		perPage = 20
	}

	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}

	content := make([]interface{}, 0, end-start)
	if start < end {
		content = append(content, matches[start:end]...)
	}

	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"code":    200,
		"message": "success",
		"data": map[string]interface{}{
			"content": content,
			"total":   total,
		},
	})
}

// proxyToAlist creates and executes a proxy request to Alist backend
func (h *AlistHandler) proxyToAlist(ctx interface{}, method, endpoint string, body []byte, srcReq *http.Request) (*http.Response, error) {
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), endpoint, nil)

	req, err := httputil.NewRequest(method, targetURL).
		WithContext(srcReq.Context()).
		WithBody(body).
		CopyHeadersExcept(srcReq, "Content-Length", "Authorization", "Authorizetoken", "X-User-Token").
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		return nil, err
	}

	return h.httpClient.Do(req)
}

// HandleFsList intercepts /api/fs/list to handle filename decryption
func (h *AlistHandler) HandleFsList(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	dirPath, _ := reqData["path"].(string)
	trace.Logf(r.Context(), "list", "Handling fs list for path: %s", dirPath)
	allowDecrypt := h.passwdDAO.MatchDir(dirPath)
	var dirPasswd *config.PasswdInfo
	if allowDecrypt {
		if passwdInfo, ok := h.passwdDAO.FindByDir(dirPath); ok {
			dirPasswd = passwdInfo
		}
	}
	if dirPasswd == nil {
		allowDecrypt = false
	}

	// Forward to Alist
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/list", nil)
	proxyReq, err := httputil.NewRequest("POST", targetURL).
		WithContext(r.Context()).
		WithBody(body).
		CopyHeaders(r).
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy fs/list")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read response", http.StatusBadGateway)
		return
	}

	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		RespondRaw(w, resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return
	}

	// Process file list - decrypt filenames if needed
	if code, ok := respData["code"].(float64); ok && code == 200 {
		if data, ok := respData["data"].(map[string]interface{}); ok {
			if content, ok := data["content"].([]interface{}); ok {
				coverNameMap := make(map[string]string)
				var omitNames []string

				// Collect files that need decryption
				type decryptTask struct {
					index      int
					name       string
					passwdInfo *config.PasswdInfo
				}
				var tasks []decryptTask

				for i, item := range content {
					if fileData, ok := item.(map[string]interface{}); ok {
						name, _ := fileData["name"].(string)
						isDir, _ := fileData["is_dir"].(bool)

						if name == "" {
							continue
						}

						// Get file path
						filePath := path.Join(dirPath, name)
						fileData["path"] = filePath

						// Cache file info
						h.fileDAO.SetFromAlistResponse(filePath, fileData)

						if !isDir && allowDecrypt {
							if sizeVal, ok := fileData["size"].(float64); ok {
								size := int64(sizeVal)
								if size > 0 {
									h.upsertMetaFromListing(r.Context(), filePath, size)
								}
								h.enqueueProbeFromList(r, filePath, size)
							}
						}

						// Skip directories for filename decryption
						if isDir || !allowDecrypt {
							continue
						}

						// Use directory password info for fast path
						if dirPasswd != nil && dirPasswd.EncName {
							tasks = append(tasks, decryptTask{
								index:      i,
								name:       name,
								passwdInfo: dirPasswd,
							})
						}

						// Handle cover images (type 5 = image)
						if fileType, ok := fileData["type"].(float64); ok && fileType == 5 {
							baseName := strings.Split(name, ".")[0]
							coverNameMap[baseName] = name
						}
					}
				}

				// Parallel filename decryption using goroutines
				if len(tasks) > 0 {
					applyResult := func(result decryptResult) {
						if fileData, ok := content[result.index].(map[string]interface{}); ok {
							encName := fileData["name"].(string)
							fileData["name"] = result.showName
							normalizeDecryptedListItem(fileData, result.showName)
							content[result.index] = fileData
							trace.Logf(r.Context(), "decrypt", "Decrypt filename: %s -> %s", encName, result.showName)

							// Save mapping: display path -> encrypted path
							displayPath := path.Join(dirPath, result.showName)
							encryptedPath := path.Join(dirPath, encName)
							h.fileDAO.SetEncPathMapping(displayPath, encryptedPath)
						}
					}

					useParallel := h.parallelDecryptEnabled() && len(tasks) >= parallelDecryptThreshold
					if useParallel {
						results := make(chan decryptResult, len(tasks))
						semaphore := make(chan struct{}, h.parallelDecryptLimit())

						for _, task := range tasks {
							semaphore <- struct{}{} // Acquire
							go func(t decryptTask) {
								defer func() { <-semaphore }() // Release
								showName := h.convertShowName(t.passwdInfo, t.name)
								results <- decryptResult{index: t.index, showName: showName}
							}(task)
						}

						// Collect results
						for range tasks {
							applyResult(<-results)
						}
						close(results)
					} else {
						for _, task := range tasks {
							showName := h.convertShowName(task.passwdInfo, task.name)
							applyResult(decryptResult{index: task.index, showName: showName})
						}
					}
				}

				// Associate video files with cover images
				for i, item := range content {
					if fileData, ok := item.(map[string]interface{}); ok {
						name, _ := fileData["name"].(string)
						isDir, _ := fileData["is_dir"].(bool)
						fileType, _ := fileData["type"].(float64)

						if isDir {
							continue
						}

						baseName := strings.Split(name, ".")[0]
						if coverName, exists := coverNameMap[baseName]; exists && fileType == 2 {
							omitNames = append(omitNames, coverName)
							fileData["thumb"] = "/d" + dirPath + "/" + coverName
							content[i] = fileData
						}
					}
				}

				// Filter out cover files
				if len(omitNames) > 0 {
					var filtered []interface{}
					for _, item := range content {
						if fileData, ok := item.(map[string]interface{}); ok {
							name, _ := fileData["name"].(string)
							shouldOmit := false
							for _, omit := range omitNames {
								if name == omit {
									shouldOmit = true
									break
								}
							}
							if !shouldOmit {
								filtered = append(filtered, item)
							}
						}
					}
					data["content"] = filtered
				}
			}
		}
	}

	RespondJSON(w, resp.StatusCode, respData)
}

// HandleFsGet intercepts /api/fs/get to modify raw_url and handle filename encryption
func (h *AlistHandler) HandleFsGet(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
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
	trace.Logf(r.Context(), "get", "Processing path: %s", filePath)

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

	// Marshal updated request
	modifiedBody, _ := json.Marshal(reqData)

	// Forward to Alist
	trace.Logf(r.Context(), "get", "Alist URL: %s", h.cfg.GetAlistURL())
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/get", nil)
	trace.Logf(r.Context(), "get", "Target: %s", targetURL)
	proxyReq, err := httputil.NewRequest("POST", targetURL).
		WithContext(r.Context()).
		WithBody(modifiedBody).
		CopyHeadersExcept(r, "Content-Length").
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy fs/get")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read response", http.StatusBadGateway)
		return
	}

	// Log Alist response (truncate to 500 chars)
	respPreview := string(respBody)
	if len(respPreview) > 500 {
		respPreview = respPreview[:500]
	}
	trace.Logf(r.Context(), "get", "Alist response status=%d body=%s", resp.StatusCode, respPreview)

	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		RespondRaw(w, resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		return
	}

	// Process response
	if found {
		if data, ok := respData["data"].(map[string]interface{}); ok {
			// Cache file info
			h.fileDAO.SetFromAlistResponse(originalPath, data)

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
				fileSize := int64(0)
				if size, ok := data["size"].(float64); ok {
					fileSize = int64(size)
				}
				if fileSize > 0 {
					h.upsertMetaFromListing(r.Context(), originalPath, fileSize)
				}
				h.enqueueProbeFromList(r, originalPath, fileSize)

				// Register redirect and update URL
				key := h.proxyHandler.RegisterRedirect(rawURL, fileSize, passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncName)
				redirectPath := buildRedirectPath(key, originalPath, true)
				data["raw_url"] = buildRedirectURL(r, redirectPath)
			}

			if provider, ok := data["provider"].(string); ok && provider == "AliyundriveOpen" {
				data["provider"] = "Local"
			}
		}
	} else {
		// Still cache file info even without encryption
		if data, ok := respData["data"].(map[string]interface{}); ok {
			h.fileDAO.SetFromAlistResponse(filePath, data)
		}
	}

	RespondJSON(w, resp.StatusCode, respData)
}

func (h *AlistHandler) upsertMetaFromListing(ctx context.Context, displayPath string, size int64) {
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

func (h *AlistHandler) enqueueProbeFromList(r *http.Request, displayPath string, reportedSize int64) {
	if h.probe == nil {
		return
	}
	passwdInfo, found := h.passwdDAO.PathFindPasswd(displayPath)
	if !found || passwdInfo == nil {
		return
	}
	realPath := displayPath
	if passwdInfo.EncName {
		realPath = h.proxyHandler.convertDisplayToRealPath(displayPath, passwdInfo)
	}
	targetURL := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/d"+realPath)
	file := FileItem{
		DisplayPath:      displayPath,
		EncryptedPath:    realPath,
		TargetURL:        targetURL,
		FileName:         path.Base(displayPath),
		CompatStorageKey: buildRangeCompatStorageKey(passwdInfo, displayPath),
	}
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}
	h.probe.EnqueueWithSize(file, authHeaders, reportedSize)
}

// HandleFsPut handles /api/fs/put for encrypted uploads with filename encryption
func (h *AlistHandler) HandleFsPut(w http.ResponseWriter, r *http.Request) {
	uploadPath := r.Header.Get("File-Path")
	if uploadPath != "" {
		uploadPath, _ = url.QueryUnescape(uploadPath)
	} else {
		uploadPath = "/-"
	}

	passwdInfo, found := h.passwdDAO.PathFindPasswd(uploadPath)
	if !found {
		// No encryption, proxy directly
		targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/put", r)
		if err := h.streamProxy.ProxyRequest(w, r, targetURL); err != nil {
			log.Error().Err(err).Msg("Failed to proxy upload")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	fileSize, err := resolveUploadFileSize(r)
	if err != nil {
		log.Warn().
			Err(err).
			Str("path", uploadPath).
			Str("content_length", r.Header.Get("Content-Length")).
			Str("content_range", r.Header.Get("Content-Range")).
			Msg("Reject encrypted upload without deterministic file size")
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

	// Handle filename encryption
	var encryptedPath string
	if passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileName := path.Base(uploadPath)
		ext := passwdInfo.EncSuffix
		if ext == "" {
			ext = path.Ext(fileName)
		}
		encName := converter.EncryptFileName(fileName)
		encryptedPath = path.Dir(uploadPath) + "/" + encName + ext
		r.Header.Set("File-Path", url.QueryEscape(encryptedPath))
		log.Debug().Str("original", uploadPath).Str("encrypted", encryptedPath).Msg("Encrypted filename for upload")
	}

	// Encrypt and upload
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/put", r)

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize, startOffset); err != nil {
		log.Error().Err(err).Str("path", uploadPath).Msg("Failed to encrypt upload")
		RespondHTTPErrorWithStatus(w, "Encryption error", http.StatusBadGateway)
		return
	}

	// Update cache mapping after successful upload
	if passwdInfo.EncName && encryptedPath != "" {
		h.fileDAO.SetEncPathMapping(uploadPath, encryptedPath)
		log.Debug().Str("display", uploadPath).Str("encrypted", encryptedPath).Msg("Cached upload path mapping")
	}
}

// HandleFsRemove handles /api/fs/remove with filename encryption
func (h *AlistHandler) HandleFsRemove(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData struct {
		Dir   string   `json:"dir"`
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	passwdInfo, found := h.passwdDAO.PathFindPasswd(reqData.Dir)
	if !found {
		if dirPasswd, ok := h.passwdDAO.FindByDir(reqData.Dir); ok {
			passwdInfo = dirPasswd
			found = true
		}
	}

	// Resolve each name to a single upstream target.
	fileNames := reqData.Names
	if found && passwdInfo.EncName {
		fileNames = h.resolveRemoveNames(reqData.Dir, reqData.Names, passwdInfo)
	}

	// Forward modified request
	modifiedReq := map[string]interface{}{
		"dir":   reqData.Dir,
		"names": fileNames,
	}
	modifiedBody, _ := json.Marshal(modifiedReq)

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/remove", nil)
	proxyReq, err := httputil.NewRequest("POST", targetURL).
		WithContext(r.Context()).
		WithBody(modifiedBody).
		CopyHeadersExcept(r, "Content-Length").
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy fs/remove")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Clear cache for deleted items on success
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if code, ok := respData["code"].(float64); ok && code == 200 {
			for _, name := range reqData.Names {
				displayPath := path.Join(reqData.Dir, name)
				h.fileDAO.DeleteEncPathMapping(displayPath)
				h.fileDAO.Delete(url.QueryEscape(displayPath))
				log.Debug().Str("path", displayPath).Msg("Cleared cache for deleted file")
			}
		}
	}

	RespondRaw(w, resp.StatusCode, "application/json", respBody)
}

// HandleFsRename handles /api/fs/rename with filename encryption
func (h *AlistHandler) HandleFsRename(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	passwdInfo, found := h.passwdDAO.PathFindPasswd(reqData.Path)
	modifiedReq := map[string]interface{}{
		"path": reqData.Path,
		"name": reqData.Name,
	}

	if found && passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)

		// Check if it's a file (not directory)
		fileInfo, exists := h.fileDAO.Get(url.QueryEscape(reqData.Path))
		if !exists {
			// Try with encrypted name
			realName := converter.ToRealName(reqData.Path)
			realPath := path.Dir(reqData.Path) + "/" + realName
			fileInfo, exists = h.fileDAO.Get(url.QueryEscape(realPath))
		}

		if !exists || !fileInfo.IsDir {
			ext := passwdInfo.EncSuffix
			if ext == "" {
				ext = path.Ext(reqData.Name)
			}

			realOldName := converter.ToRealName(reqData.Path)
			newEncName := converter.EncryptFileName(reqData.Name)

			modifiedReq["path"] = path.Dir(reqData.Path) + "/" + realOldName
			modifiedReq["name"] = newEncName + ext
		}
	}

	modifiedBody, _ := json.Marshal(modifiedReq)

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/rename", nil)
	proxyReq, err := httputil.NewRequest("POST", targetURL).
		WithContext(r.Context()).
		WithBody(modifiedBody).
		CopyHeadersExcept(r, "Content-Length").
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy fs/rename")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Update cache on successful rename
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if code, ok := respData["code"].(float64); ok && code == 200 {
			// Delete old path mapping
			h.fileDAO.DeleteEncPathMapping(reqData.Path)
			h.fileDAO.Delete(url.QueryEscape(reqData.Path))

			// Add new path mapping if filename encryption is enabled
			if found && passwdInfo.EncName {
				newDisplayPath := path.Dir(reqData.Path) + "/" + reqData.Name
				newEncPath := modifiedReq["path"].(string)[:len(path.Dir(reqData.Path))+1] + modifiedReq["name"].(string)
				h.fileDAO.SetEncPathMapping(newDisplayPath, newEncPath)
				log.Debug().Str("old", reqData.Path).Str("new", newDisplayPath).Msg("Updated cache for renamed file")
			}
		}
	}

	RespondRaw(w, resp.StatusCode, "application/json", respBody)
}

// HandleFsMove handles /api/fs/move with filename encryption
func (h *AlistHandler) HandleFsMove(w http.ResponseWriter, r *http.Request) {
	h.handleCopyOrMove(w, r, "/api/fs/move")
}

// HandleFsCopy handles /api/fs/copy with filename encryption
func (h *AlistHandler) HandleFsCopy(w http.ResponseWriter, r *http.Request) {
	h.handleCopyOrMove(w, r, "/api/fs/copy")
}

func (h *AlistHandler) handleCopyOrMove(w http.ResponseWriter, r *http.Request, endpoint string) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	var reqData struct {
		SrcDir string   `json:"src_dir"`
		DstDir string   `json:"dst_dir"`
		Names  []string `json:"names"`
	}
	if err := json.Unmarshal(body, &reqData); err != nil {
		RespondHTTPErrorWithStatus(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	passwdInfo, found := h.passwdDAO.PathFindPasswd(reqData.SrcDir)
	fileNames := reqData.Names

	if found && passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileNames = make([]string, 0, len(reqData.Names))
		for _, name := range reqData.Names {
			if encryption.IsOriginalFile(name) {
				fileNames = append(fileNames, encryption.StripOriginalPrefix(name))
			} else {
				ext := passwdInfo.EncSuffix
				if ext == "" {
					ext = path.Ext(name)
				}
				encName := converter.EncryptFileName(path.Base(name))
				fileNames = append(fileNames, encName+ext)
			}
		}
	}

	modifiedReq := map[string]interface{}{
		"src_dir": reqData.SrcDir,
		"dst_dir": reqData.DstDir,
		"names":   fileNames,
	}
	modifiedBody, _ := json.Marshal(modifiedReq)

	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), endpoint, nil)
	proxyReq, err := httputil.NewRequest("POST", targetURL).
		WithContext(r.Context()).
		WithBody(modifiedBody).
		CopyHeadersExcept(r, "Content-Length").
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		RespondHTTPErrorWithStatus(w, "Internal error", http.StatusInternalServerError)
		return
	}

	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy " + endpoint)
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Update cache on successful move/copy
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if code, ok := respData["code"].(float64); ok && code == 200 {
			isMove := endpoint == "/api/fs/move"
			for i, name := range reqData.Names {
				srcDisplayPath := path.Join(reqData.SrcDir, name)
				dstDisplayPath := path.Join(reqData.DstDir, name)

				// For move operations, delete the source cache entry
				if isMove {
					h.fileDAO.DeleteEncPathMapping(srcDisplayPath)
					h.fileDAO.Delete(url.QueryEscape(srcDisplayPath))
				}

				// Add destination path mapping if filename encryption is enabled
				if found && passwdInfo.EncName && i < len(fileNames) {
					dstEncPath := path.Join(reqData.DstDir, fileNames[i])
					h.fileDAO.SetEncPathMapping(dstDisplayPath, dstEncPath)
				}
			}
			log.Debug().Str("endpoint", endpoint).Int("count", len(reqData.Names)).Msg("Updated cache for moved/copied files")
		}
	}

	RespondRaw(w, resp.StatusCode, "application/json", respBody)
}
