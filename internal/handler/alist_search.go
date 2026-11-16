package handler

import (
	"encoding/json"
	"net/http"
	"path"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
)

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

func (h *AlistHandler) isEncryptedDirRoot(dirPath string) bool {
	if h == nil || h.passwdDAO == nil {
		return false
	}
	dirPath = strings.TrimSpace(dirPath)
	if dirPath == "" {
		return false
	}
	for _, prefix := range h.passwdDAO.GetEncPathPrefixes() {
		if strings.TrimRight(prefix, "/") == strings.TrimRight(dirPath, "/") {
			return true
		}
	}
	return false
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

	passwdList := h.cfg.PasswdListSnapshot()
	for i := range passwdList {
		passwdInfo := &passwdList[i]
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

func (h *AlistHandler) searchEncryptedTree(r *http.Request, rootPath, keyword string, scope int, passwdInfo *config.PasswdInfo) ([]interface{}, int, error) {
	const (
		maxSearchDepth = 20   // Maximum directory nesting depth
		maxSearchItems = 5000 // Maximum total items to process
	)

	type node struct {
		displayPath string
		realPath    string
		depth       int
	}

	recursive := scope != 0
	queue := []node{{
		displayPath: rootPath,
		realPath:    rootPath,
		depth:       0,
	}}
	visited := make(map[string]struct{})
	var matches []interface{}
	itemsProcessed := 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := visited[current.realPath]; ok {
			continue
		}
		visited[current.realPath] = struct{}{}

		if current.depth > maxSearchDepth {
			log.Warn().Int("max_depth", maxSearchDepth).Str("path", current.realPath).Msg("searchEncryptedTree reached depth limit, skipping directory")
			continue
		}

		currentPasswd, found := h.passwdDAO.PathFindPasswd(current.displayPath)
		if !found || currentPasswd == nil {
			currentPasswd = passwdInfo
		}

		content, err := h.fetchFsListContent(r, current.realPath)
		if err != nil {
			return nil, 0, err
		}

		for _, item := range content {
			itemsProcessed++
			if itemsProcessed > maxSearchItems {
				log.Warn().Int("max_items", maxSearchItems).Msg("searchEncryptedTree reached item limit, stopping search")
				return matches, len(matches), nil
			}

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
				childDisplayName = h.convertEntryShowName(currentPasswd, rawName, isDir)
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
					depth:       current.depth + 1,
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
	body, err := readLimitedRequestBody(r)
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

		respBody, err := readLimitedBody(resp, maxProxyResponseBody)
		if err != nil {
			log.Warn().Err(err).Msg("Upstream response body read failed")
			http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
			return
		}
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

		respBody, err := readLimitedBody(resp, maxProxyResponseBody)
		if err != nil {
			log.Warn().Err(err).Msg("Upstream response body read failed")
			http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
			return
		}
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
