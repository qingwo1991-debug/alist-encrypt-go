package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

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
	startOffset, hasRange, err := validateUploadContentRange(r.Header.Get("Content-Range"), fileSize, r.ContentLength)
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

	// Match OpenList's existing exact header-value contract, without rewriting it.
	asyncUpload := r.Header.Get("As-Task") == "true"
	if asyncUpload && passwdInfo.EncName && protectedFilenameLimit(h.cfg, uploadPath) > 0 {
		if _, ok := h.fileDAO.(filenameUploadTaskRepository); !ok {
			respondFilenameWriteError(w, newFilenameWriteError("filename_store_unavailable", http.StatusServiceUnavailable, nil))
			return
		}
	}
	protected, safePath, err := prepareFilenameWrite(h.cfg, h.fileDAO, r, passwdInfo, uploadPath, encryptedPath, fileSize, hasRange, h.httpClient)
	if err != nil {
		respondFilenameWriteError(w, err)
		return
	}
	var buffered *filenameWriteResponse
	var uploadResponse http.ResponseWriter = w
	if protected != nil {
		encryptedPath = safePath
		r.Header.Set("File-Path", url.QueryEscape(encryptedPath))
		r = r.WithContext(proxy.WithSynchronousUploadVerification(r.Context()))
		buffered = newFilenameWriteResponse()
		uploadResponse = buffered
	}
	// Encrypt and upload
	targetURL := httputil.BuildTargetURL(h.cfg.GetAlistURL(), "/api/fs/put", r)

	if err := h.streamProxy.ProxyUploadEncrypt(uploadResponse, r, targetURL, passwdInfo, fileSize, startOffset); err != nil {
		if protected != nil && !asyncUpload {
			// Synchronous (non-task) protected uploads: any proxy failure means the
			// remote write did not complete, so retain the FAILED audit exactly as
			// before. Async uploads are handled below because acceptance may be
			// unknown there.
			_ = protected.finish(storage.FilenameFailed)
		} else if protected != nil {
			// Only a definite upstream rejection (non-2xx before any body committed)
			// proves no task was accepted. Transport or mid-stream failures leave
			// acceptance unknown: a task may already be running, so keep the claim
			// pending to preserve the exclusive reservation rather than allow a
			// risky maintenance release.
			var rejected *proxy.UpstreamRejectedUploadError
			if errors.As(err, &rejected) {
				_ = protected.finish(storage.FilenameFailed)
			}
		}
		log.Error().Err(err).Str("path", uploadPath).Msg("Failed to encrypt upload")
		RespondHTTPErrorWithStatus(w, "Encryption error", http.StatusBadGateway)
		return
	}

	if protected != nil {
		if buffered.overflow || buffered.status >= 300 {
			// A committed non-2xx upstream status is a definite rejection. An
			// oversized/malformed response is acceptance-unknown, so for async keep
			// the claim pending rather than allow a risky maintenance release.
			if !asyncUpload || buffered.status >= 300 {
				_ = protected.finish(storage.FilenameFailed)
			}
			RespondHTTPErrorWithStatus(w, "Protected upload failed", http.StatusBadGateway)
			return
		}
		if asyncUpload {
			taskID, err := filenameAcceptedTaskID(buffered.body.Bytes())
			if err != nil {
				// Malformed/unknown result: an upstream task may already be running,
				// so keep the claim pending rather than guessing success or failure.
				RespondHTTPErrorWithStatus(w, "Invalid protected upload response", http.StatusBadGateway)
				return
			}
			if taskID != "" {
				taskRepo, ok := h.fileDAO.(filenameUploadTaskRepository)
				if !ok {
					RespondHTTPErrorWithStatus(w, "Protected upload task store unavailable", http.StatusServiceUnavailable)
					return
				}
				receipt := storage.FilenameUploadTask{Origin: protected.record.Origin, TaskID: taskID, EncryptedPath: protected.record.EncryptedPath, Token: protected.record.Token, AuthScope: protected.record.AuthScope, RuleFingerprint: protected.record.RuleFingerprint}
				if err := taskRepo.BindFilenameUploadTask(receipt); err != nil {
					RespondHTTPErrorWithStatus(w, "Cannot persist protected upload task", http.StatusServiceUnavailable)
					return
				}
				buffered.publish(w)
				h.pollFilenameUploadTask(receipt, filenameTaskCredentials(r.Header))
				return // Accepted is not completed: no mapping or immediate verification.
			}
		}
		if err := protected.verify(r, h.httpClient); err != nil {
			RespondHTTPErrorWithStatus(w, err.Error(), http.StatusBadGateway)
			return
		}
		buffered.publish(w)
	}
	// Update cache mapping after successful upload
	if passwdInfo.EncName && encryptedPath != "" {
		h.fileDAO.SetEncPathMapping(uploadPath, encryptedPath)
		log.Debug().Str("display", uploadPath).Str("encrypted", encryptedPath).Msg("Cached upload path mapping")
	}
}

// HandleFsRemove handles /api/fs/remove with filename encryption
func (h *AlistHandler) HandleFsRemove(w http.ResponseWriter, r *http.Request) {
	body, err := readLimitedRequestBody(r)
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
		fileNames = h.resolveUpstreamNames(r, reqData.Dir, reqData.Names, passwdInfo)
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

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
		return
	}

	// Clear cache for deleted items on success
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if code, ok := respData["code"].(float64); ok && code == 200 {
			for i, name := range reqData.Names {
				displayPath := h.displayPathForUpstreamName(reqData.Dir, name, fileNames, i)
				// Directories take their whole subtree with them; invalidating
				// only the exact path would leave descendant mappings until TTL.
				h.fileDAO.InvalidateDisplaySubtree(displayPath)
				h.fileDAO.DeleteEncPathMapping(displayPath)
				h.fileDAO.InvalidateDisplayPath(displayPath)
				h.fileDAO.Delete(url.QueryEscape(displayPath))
				if h.probe != nil {
					h.probe.InvalidateWarm(displayPath, "fs_remove")
				}
				log.Debug().Str("path", displayPath).Msg("Cleared cache for deleted file")
				if h.statsRecorder != nil {
					h.statsRecorder.RecordDeletion(displayPath)
				}
			}
		}
	}

	RespondRaw(w, resp.StatusCode, "application/json", respBody)
}

// HandleFsRename handles /api/fs/rename with filename encryption
func (h *AlistHandler) HandleFsRename(w http.ResponseWriter, r *http.Request) {
	body, err := readLimitedRequestBody(r)
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

	if err := guardProtectedRename(h.cfg, reqData.Path, reqData.Name); err != nil {
		respondProtectedMutationError(w, err)
		return
	}

	passwdInfo, found := h.passwdDAO.PathFindPasswd(reqData.Path)
	modifiedReq := map[string]interface{}{
		"path": reqData.Path,
		"name": reqData.Name,
	}

	if found && passwdInfo.EncName {
		converter := encryption.NewFileNameConverter(passwdInfo.Password, passwdInfo.EncType, passwdInfo.EncSuffix)

		realOldPath, sourceIsDir := h.resolveRenameSource(r, reqData.Path, passwdInfo)
		if mutationProtectionEnabled(h.cfg) {
			if _, err := mutationNameVariants(path.Base(realOldPath)); err != nil {
				respondProtectedMutationError(w, invalidMutation("rename"))
				return
			}
		}
		modifiedReq["path"] = realOldPath
		if sourceIsDir {
			// Directory display names are never filename-encrypted.
			modifiedReq["name"] = reqData.Name
		} else {
			ext := passwdInfo.EncSuffix
			if ext == "" {
				ext = path.Ext(reqData.Name)
			}
			newEncName := converter.EncryptFileName(reqData.Name)
			modifiedReq["name"] = newEncName + ext
			if limit := protectedFilenameLimit(h.cfg, path.Join(path.Dir(reqData.Path), reqData.Name)); limit > 0 && len(newEncName+ext) > limit {
				RespondHTTPErrorWithStatus(w, "Encrypted rename destination exceeds configured filename limit; use a shorter name", http.StatusBadRequest)
				return
			}
		}
	}

	// Display aliases and orig_ spellings can resolve to another physical
	// subtree. Check the actual outbound paths as well as the display request.
	if err := guardProtectedRename(h.cfg, modifiedReq["path"].(string), modifiedReq["name"].(string)); err != nil {
		respondProtectedMutationError(w, err)
		return
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

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
		return
	}

	// Update cache on successful rename
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if code, ok := respData["code"].(float64); ok && code == 200 {
			// Delete old path mapping; a renamed directory takes its subtree.
			h.fileDAO.InvalidateDisplaySubtree(reqData.Path)
			h.fileDAO.DeleteEncPathMapping(reqData.Path)
			h.fileDAO.InvalidateDisplayPath(reqData.Path)
			h.fileDAO.Delete(url.QueryEscape(reqData.Path))
			if h.probe != nil {
				h.probe.InvalidateWarm(reqData.Path, "fs_rename_source")
			}

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

// HandleFsMkdir handles /api/fs/mkdir. Directory names are never
// filename-encrypted, so the request forwards unchanged after syntax checks;
// refusing it under filenameWriteLimits would break plain directory creation
// even though no encrypted-name mapping is involved.
func (h *AlistHandler) HandleFsMkdir(w http.ResponseWriter, r *http.Request) {
	body, err := readLimitedRequestBody(r)
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
	if _, err := mutationPathVariants(reqData.Path); err != nil {
		respondProtectedMutationError(w, invalidMutation("mkdir"))
		return
	}
	if _, err := mutationNameVariants(reqData.Name); err != nil {
		respondProtectedMutationError(w, invalidMutation("mkdir"))
		return
	}

	resp, err := h.proxyToAlist(nil, "POST", "/api/fs/mkdir", body, r)
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
	body, err := readLimitedRequestBody(r)
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

	if err := guardProtectedBatchMutation(h.cfg, path.Base(endpoint), reqData.SrcDir, reqData.DstDir, reqData.Names); err != nil {
		respondProtectedMutationError(w, err)
		return
	}

	passwdInfo, found := h.passwdDAO.PathFindPasswd(reqData.SrcDir)
	fileNames := reqData.Names

	if found && passwdInfo.EncName {
		// names are basenames shared by src_dir and dst_dir; resolve each to
		// the single upstream spelling (dirs/plaintext keep their name).
		fileNames = h.resolveUpstreamNames(r, reqData.SrcDir, reqData.Names, passwdInfo)
	}

	// orig_ names may strip into a protected directory even when their display
	// spelling was outside it. Always guard the final outbound batch too.
	if err := guardProtectedBatchMutation(h.cfg, path.Base(endpoint), reqData.SrcDir, reqData.DstDir, fileNames); err != nil {
		respondProtectedMutationError(w, err)
		return
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

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		log.Warn().Err(err).Msg("Upstream response body read failed")
		http.Error(w, "Bad gateway: upstream response too large", http.StatusBadGateway)
		return
	}

	// Update cache on successful move/copy
	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err == nil {
		if code, ok := respData["code"].(float64); ok && code == 200 {
			isMove := endpoint == "/api/fs/move"
			for i, name := range reqData.Names {
				srcDisplayPath := path.Join(reqData.SrcDir, name)
				dstDisplayPath := path.Join(reqData.DstDir, name)
				// MOVE/COPY 覆盖 = 目标文件被删除。目标此前在缓存里（被列出/
				// 播放过）才记：避免把"新建到不存在的路径"误记为删除。
				if h.statsRecorder != nil {
					if _, destExisted := h.fileDAO.Get(url.QueryEscape(dstDisplayPath)); destExisted {
						h.statsRecorder.RecordDeletion(dstDisplayPath)
					}
				}

				// For move operations, delete the source cache entry; a moved
				// directory takes its whole subtree with it.
				if isMove {
					moveSrcDisplayPath := h.displayPathForUpstreamName(reqData.SrcDir, name, fileNames, i)
					h.fileDAO.InvalidateDisplaySubtree(moveSrcDisplayPath)
					h.fileDAO.DeleteEncPathMapping(moveSrcDisplayPath)
					h.fileDAO.InvalidateDisplayPath(moveSrcDisplayPath)
					h.fileDAO.Delete(url.QueryEscape(moveSrcDisplayPath))
					if h.probe != nil {
						h.probe.InvalidateWarm(moveSrcDisplayPath, "fs_move_source")
					}
				}

				// Add destination path mapping if filename encryption is enabled
				if found && passwdInfo.EncName && i < len(fileNames) {
					dstEncPath := path.Join(reqData.DstDir, fileNames[i])
					h.fileDAO.SetEncPathMapping(dstDisplayPath, dstEncPath)
				}

				// 目标被覆盖 = 一次删除。仅当缓存中确实见过目标（避免"目标
				// 原本不存在"的假阳性）；dst == src 时是自己动自己，不算删除。
				if h.statsRecorder != nil && dstDisplayPath != srcDisplayPath {
					if _, ok := h.fileDAO.Get(dstDisplayPath); ok {
						h.statsRecorder.RecordDeletion(dstDisplayPath)
					}
				}
			}
			log.Debug().Str("endpoint", endpoint).Int("count", len(reqData.Names)).Msg("Updated cache for moved/copied files")
		}
	}

	RespondRaw(w, resp.StatusCode, "application/json", respBody)
}
