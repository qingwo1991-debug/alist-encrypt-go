package handler

import (
	"encoding/json"
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
)

// AlistHandler handles Alist API interception
type AlistHandler struct {
	cfg          *config.Config
	streamProxy  *proxy.StreamProxy
	fileDAO      *dao.FileDAO
	passwdDAO    *dao.PasswdDAO
	proxyHandler *ProxyHandler
}

// NewAlistHandler creates a new Alist handler
// proxyHandler must be the same instance used for /redirect routes
func NewAlistHandler(cfg *config.Config, streamProxy *proxy.StreamProxy, fileDAO *dao.FileDAO, passwdDAO *dao.PasswdDAO, proxyHandler *ProxyHandler) *AlistHandler {
	return &AlistHandler{
		cfg:          cfg,
		streamProxy:  streamProxy,
		fileDAO:      fileDAO,
		passwdDAO:    passwdDAO,
		proxyHandler: proxyHandler,
	}
}

// decryptResult holds the result of parallel filename decryption
type decryptResult struct {
	index    int
	showName string
}

// proxyToAlist creates and executes a proxy request to Alist backend
func (h *AlistHandler) proxyToAlist(ctx interface{}, method, endpoint string, body []byte, srcReq *http.Request) (*http.Response, error) {
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), endpoint, nil)

	req, err := httputil.NewRequest(method, targetURL).
		WithContext(srcReq.Context()).
		WithBody(body).
		CopyHeadersExcept(srcReq, "Content-Length").
		WithHeader("Content-Type", "application/json").
		Build()
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	return client.Do(req)
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

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
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

						// Skip directories for filename decryption
						if isDir {
							continue
						}

						// Check if filename encryption is enabled for this path
						passwdInfo, found := h.passwdDAO.PathFindPasswd(filePath)
						if found && passwdInfo.EncName {
							tasks = append(tasks, decryptTask{
								index:      i,
								name:       name,
								passwdInfo: passwdInfo,
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
					results := make(chan decryptResult, len(tasks))

					// Use worker pool for parallel decryption (limit concurrency)
					const maxWorkers = 32
					semaphore := make(chan struct{}, maxWorkers)

					for _, task := range tasks {
						semaphore <- struct{}{} // Acquire
						go func(t decryptTask) {
							defer func() { <-semaphore }() // Release
							showName := encryption.ConvertShowName(t.passwdInfo.Password, t.passwdInfo.EncType, t.name)
							results <- decryptResult{index: t.index, showName: showName}
						}(task)
					}

					// Collect results
					for range tasks {
						result := <-results
						if fileData, ok := content[result.index].(map[string]interface{}); ok {
							fileData["name"] = result.showName
							content[result.index] = fileData
						}
					}
					close(results)
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

	// Check if filename encryption is needed
	passwdInfo, found := h.passwdDAO.PathFindPasswd(filePath)
	if found && passwdInfo.EncName {
		// Check if it's a directory first
		fileInfo, exists := h.fileDAO.Get(url.QueryEscape(filePath))
		if !exists || !fileInfo.IsDir {
			// Convert display name to real encrypted name
			converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
			fileName := path.Base(filePath)
			realName := converter.ToRealName(fileName)
			filePath = path.Dir(filePath) + "/" + realName
			reqData["path"] = filePath
		}
	}

	// Marshal updated request
	modifiedBody, _ := json.Marshal(reqData)

	// Forward to Alist
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/get", nil)
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

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
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
					showName := encryption.ConvertShowName(passwdInfo.Password, passwdInfo.EncType, name)
					data["name"] = showName
				}
			}

			// Modify raw_url for encrypted files
			if rawURL, ok := data["raw_url"].(string); ok && rawURL != "" {
				fileSize := int64(0)
				if size, ok := data["size"].(float64); ok {
					fileSize = int64(size)
				}

				// Register redirect and update URL
				key := h.proxyHandler.RegisterRedirect(rawURL, fileSize, passwdInfo.Password, passwdInfo.EncType)
				data["raw_url"] = "/redirect/" + key
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

// HandleFsPut handles /api/fs/put for encrypted uploads with filename encryption
func (h *AlistHandler) HandleFsPut(w http.ResponseWriter, r *http.Request) {
	uploadPath := r.Header.Get("File-Path")
	if uploadPath != "" {
		uploadPath, _ = url.QueryUnescape(uploadPath)
	} else {
		uploadPath = "/-"
	}

	fileSize, _ := strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)

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

	// Handle filename encryption
	if passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		fileName := path.Base(uploadPath)
		ext := passwdInfo.EncSuffix
		if ext == "" {
			ext = path.Ext(fileName)
		}
		encName := converter.EncryptFileName(fileName)
		newPath := path.Dir(uploadPath) + "/" + encName + ext
		r.Header.Set("File-Path", url.QueryEscape(newPath))
		log.Debug().Str("original", uploadPath).Str("encrypted", newPath).Msg("Encrypted filename for upload")
	}

	// Encrypt and upload
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/put", r)

	if err := h.streamProxy.ProxyUploadEncrypt(w, r, targetURL, passwdInfo, fileSize); err != nil {
		log.Error().Err(err).Str("path", uploadPath).Msg("Failed to encrypt upload")
		RespondHTTPErrorWithStatus(w, "Encryption error", http.StatusBadGateway)
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

	// Build file names list
	fileNames := make([]string, 0, len(reqData.Names)*2)
	fileNames = append(fileNames, reqData.Names...)

	if found && passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)
		for _, name := range reqData.Names {
			realName := converter.ToRealName(name)
			fileNames = append(fileNames, realName)
		}
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

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy fs/remove")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
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

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy fs/rename")
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
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

	client := &http.Client{}
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Error().Err(err).Msg("Failed to proxy " + endpoint)
		RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	RespondRaw(w, resp.StatusCode, "application/json", respBody)
}
