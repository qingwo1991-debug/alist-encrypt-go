package handler

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/rs/zerolog/log"
)

const (
	dirSyncRequestTTL = 2 * time.Minute
	dirSyncScanTTL    = 10 * time.Minute
	dirSyncScanEvery  = 15 * time.Minute
	dirSyncPageRoute  = "/api/encrypt/dir-sync/page"
	dirSyncModeMixed  = "mixed"
	dirSyncModeReq    = "request_fill"
	dirSyncModeScan   = "background_scan"
	dirSyncScopeScan  = "scan"
)

func (h *AlistHandler) ensureDirSyncLoop() {
	if h == nil || h.dirSyncStore == nil || !h.scanConfigured() {
		return
	}
	h.dirSyncStart.Do(func() {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("Directory sync scheduler panicked")
				}
			}()
			h.runDirSyncScheduler()
		}()
	})
}

func (h *AlistHandler) StartDirSyncLoop() {
	h.ensureDirSyncLoop()
}

func (h *AlistHandler) scanConfigured() bool {
	if h == nil || h.cfg == nil {
		return false
	}
	return strings.TrimSpace(h.cfg.AlistServer.ScanAuthHeader) != "" ||
		strings.TrimSpace(h.cfg.AlistServer.ScanUsername) != "" ||
		strings.TrimSpace(h.cfg.AlistServer.ScanPassword) != ""
}

func (h *AlistHandler) requestAuthHeaders(r *http.Request) http.Header {
	headers := make(http.Header)
	if r == nil {
		return headers
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		headers.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		headers.Set("Cookie", cookie)
	}
	return headers
}

func (h *AlistHandler) scanAuthHeaders() http.Header {
	headers := make(http.Header)
	if h == nil || h.cfg == nil {
		return headers
	}
	if raw := strings.TrimSpace(h.cfg.AlistServer.ScanAuthHeader); raw != "" {
		headers.Set("Authorization", raw)
		return headers
	}
	username := strings.TrimSpace(h.cfg.AlistServer.ScanUsername)
	password := strings.TrimSpace(h.cfg.AlistServer.ScanPassword)
	if username != "" && password != "" {
		// Try JWT token first — alist /api/fs/list needs token, not Basic auth.
		if token := h.fetchAlistJWT(username, password); token != "" {
			headers.Set("Authorization", token)
			return headers
		}
		// Fallback to Basic auth (works for WebDAV but not /api/fs/list).
		req, _ := http.NewRequest(http.MethodGet, "http://local/", nil)
		req.SetBasicAuth(username, password)
		if auth := req.Header.Get("Authorization"); auth != "" {
			headers.Set("Authorization", auth)
		}
	}
	return headers
}

func (h *AlistHandler) fetchAlistJWT(username, password string) string {
	return fetchAlistJWT(h.cfg.GetAlistURL(), username, password)
}

func authScopeHash(headers http.Header) string {
	if headers == nil {
		return "anon"
	}
	raw := strings.TrimSpace(headers.Get("Authorization")) + "\n" + strings.TrimSpace(headers.Get("Cookie"))
	if raw == "" {
		return "anon"
	}
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func buildDirScopeKey(dirPath, authHash string) string {
	dirPath = strings.TrimSpace(dirPath)
	if dirPath == "" {
		dirPath = "/"
	}
	if authHash == "" {
		authHash = "anon"
	}
	return dirPath + "::" + authHash
}

func listResponseTTL(sourceMode string) time.Duration {
	if sourceMode == dirSyncModeScan {
		return dirSyncScanTTL
	}
	return dirSyncRequestTTL
}

func (h *AlistHandler) markSnapshotServingMode(payload []byte, stale bool, syncing bool, cacheMode string, snap *DirListSnapshot) []byte {
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		return payload
	}
	body["stale"] = stale
	body["syncing"] = syncing
	body["cache_hit"] = true
	body["cache_mode"] = cacheMode
	if snap != nil {
		if !snap.LastSyncAt.IsZero() {
			body["last_sync_at"] = snap.LastSyncAt.Format(time.RFC3339)
		}
		if !snap.NextRefreshAt.IsZero() {
			body["next_refresh_at"] = snap.NextRefreshAt.Format(time.RFC3339)
		}
		if snap.LastError != "" {
			body["degraded_reason"] = snap.LastError
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return payload
	}
	return encoded
}

func payloadResponseCode(payload []byte) int {
	if len(payload) == 0 {
		return 0
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		return 0
	}
	switch code := body["code"].(type) {
	case float64:
		return int(code)
	case int:
		return code
	default:
		return 0
	}
}

func isSuccessfulListPayload(payload []byte) bool {
	return payloadResponseCode(payload) == 200
}

func (h *AlistHandler) serveSnapshot(w http.ResponseWriter, snap *DirListSnapshot, cacheMode string) {
	if snap == nil {
		RespondHTTPErrorWithStatus(w, "snapshot not found", http.StatusNotFound)
		return
	}
	now := time.Now()
	stale := snap.Stale || (!snap.NextRefreshAt.IsZero() && now.After(snap.NextRefreshAt))
	syncing := snap.SyncState == "syncing"
	RespondRaw(w, http.StatusOK, "application/json", h.markSnapshotServingMode(snap.PayloadJSON, stale, syncing, cacheMode, snap))
}

func (h *AlistHandler) persistSnapshot(ctx context.Context, dirPath, scopeKey, authHash string, payload []byte, itemCount int, sourceMode string, lastErr string) {
	if h == nil || h.dirSyncStore == nil {
		return
	}
	now := time.Now()
	snap := DirListSnapshot{
		ScopeKey:      scopeKey,
		ProviderHost:  h.cfg.GetAlistURL(),
		DisplayPath:   dirPath,
		AuthScopeHash: authHash,
		RuleVersion:   "v1",
		ItemCount:     itemCount,
		Stale:         false,
		SyncState:     "fresh",
		LastSyncAt:    now,
		LastSuccessAt: now,
		NextRefreshAt: now.Add(listResponseTTL(sourceMode)),
		LastError:     lastErr,
		SourceMode:    sourceMode,
		PayloadJSON:   payload,
		UpdatedAt:     now,
		LastAccessed:  now,
	}
	_ = h.dirSyncStore.UpsertSnapshot(ctx, snap)
}

func (h *AlistHandler) updateSnapshotSyncing(ctx context.Context, scopeKey string, syncing bool, lastErr string) {
	if h == nil || h.dirSyncStore == nil {
		return
	}
	snap, ok, err := h.dirSyncStore.GetSnapshot(ctx, scopeKey)
	if err != nil || !ok || snap == nil {
		return
	}
	if syncing {
		snap.SyncState = "syncing"
		snap.Stale = true
	} else {
		if lastErr != "" {
			snap.LastError = lastErr
			snap.Stale = true
			snap.SyncState = "stale"
			snap.NextRefreshAt = time.Now().Add(30 * time.Second)
		} else {
			snap.SyncState = "fresh"
			snap.Stale = false
		}
	}
	snap.UpdatedAt = time.Now()
	snap.LastAccessed = snap.UpdatedAt
	_ = h.dirSyncStore.UpsertSnapshot(ctx, *snap)
}

func (h *AlistHandler) liveFsListResponse(r *http.Request, body []byte, dirPath string, enableProbe bool) (int, map[string]interface{}, []byte, int, error) {
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

	targetURL := h.cfg.GetAlistURL() + "/api/fs/list"
	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, 0, err
	}
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}
	resp, err := h.httpClient.Do(proxyReq)
	if err != nil {
		return 0, nil, nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, 0, err
	}

	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		return resp.StatusCode, nil, respBody, 0, nil
	}

	itemCount := 0
	if code, ok := respData["code"].(float64); ok && code == 200 {
		if data, ok := respData["data"].(map[string]interface{}); ok {
			if content, ok := data["content"].([]interface{}); ok {
				itemCount = len(content)
				coverNameMap := make(map[string]string)
				var omitNames []string

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
						filePath := path.Join(dirPath, name)
						h.fileDAO.SetFromAlistResponse(filePath, fileData)
						if !isDir && allowDecrypt && enableProbe {
							if sizeVal, ok := fileData["size"].(float64); ok {
								size := int64(sizeVal)
								if size > 0 {
									h.upsertMetaFromListing(r.Context(), filePath, size)
								}
								h.enqueueProbeFromList(r, filePath, size)
							}
						}
						if isDir || !allowDecrypt {
							continue
						}
						if dirPasswd != nil && dirPasswd.EncName {
							tasks = append(tasks, decryptTask{index: i, name: name, passwdInfo: dirPasswd})
						}
						if fileType, ok := fileData["type"].(float64); ok && fileType == 5 {
							baseName := strings.Split(name, ".")[0]
							coverNameMap[baseName] = name
						}
					}
				}

				if len(tasks) > 0 {
					applyResult := func(result decryptResult) {
						if fileData, ok := content[result.index].(map[string]interface{}); ok {
							encName := fileData["name"].(string)
							fileData["name"] = result.showName
							normalizeDecryptedListItem(fileData, result.showName)
							content[result.index] = fileData
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
							semaphore <- struct{}{}
							go func(t decryptTask) {
								defer func() { <-semaphore }()
								showName := h.convertShowName(t.passwdInfo, t.name)
								results <- decryptResult{index: t.index, showName: showName}
							}(task)
						}
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

	encoded, err := json.Marshal(respData)
	if err != nil {
		return resp.StatusCode, respData, respBody, itemCount, nil
	}
	return resp.StatusCode, respData, encoded, itemCount, nil
}

func (h *AlistHandler) refreshDirSnapshotAsync(dirPath string, body []byte, headers http.Header, scopeKey string, sourceMode string) {
	if h == nil || h.dirSyncStore == nil {
		return
	}
	h.ensureDirSyncLoop()
	h.updateSnapshotSyncing(context.Background(), scopeKey, true, "")
	go func() {
		_, err, _ := h.dirSyncGroup.Do(scopeKey, func() (interface{}, error) {
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://dirsync.local/api/fs/list", bytes.NewReader(body))
			req.Header = headers.Clone()
			status, _, payload, itemCount, liveErr := h.liveFsListResponse(req, body, dirPath, true)
			if liveErr != nil {
				h.updateSnapshotSyncing(context.Background(), scopeKey, false, liveErr.Error())
				return nil, liveErr
			}
			if status >= 200 && status < 300 && isSuccessfulListPayload(payload) {
				h.persistSnapshot(context.Background(), dirPath, scopeKey, authScopeHash(headers), payload, itemCount, sourceMode, "")
				return nil, nil
			}
			errText := "upstream list refresh failed"
			if code := payloadResponseCode(payload); code != 0 {
				errText = "upstream list returned code " + strconv.Itoa(code)
			}
			h.updateSnapshotSyncing(context.Background(), scopeKey, false, errText)
			return nil, nil
		})
		if err != nil {
			log.Warn().Err(err).Str("path", dirPath).Msg("dir snapshot refresh failed")
		}
	}()
}

func (h *AlistHandler) runDirSyncScheduler() {
	h.runDirSyncScan("bootstrap_scan")
	ticker := time.NewTicker(dirSyncScanEvery)
	defer ticker.Stop()
	for range ticker.C {
		h.runDirSyncScan("scheduled_scan")
	}
}

func (h *AlistHandler) runDirSyncScan(jobType string) {
	if h == nil || h.dirSyncStore == nil || !h.scanConfigured() {
		return
	}
	roots := h.collectEncryptedSearchRoots()
	status := DirSyncStatus{
		Name:              dirSyncPrimaryStatusName,
		JobID:             time.Now().Format("20060102150405"),
		JobType:           jobType,
		Status:            "running",
		Mode:              dirSyncModeMixed,
		ScanConfigured:    true,
		TotalDirsEstimate: len(roots),
		StartedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		NextRunAt:         time.Now().Add(dirSyncScanEvery),
	}
	_ = h.dirSyncStore.UpsertStatus(context.Background(), status)
	if len(roots) == 0 {
		status.Status = "done"
		status.FinishedAt = time.Now()
		status.LastSuccessAt = status.FinishedAt
		_ = h.dirSyncStore.UpsertStatus(context.Background(), status)
		return
	}

	type scanNode struct {
		path  string
		depth int
	}
	maxDepth := h.cfg.AlistServer.ScanMaxDepth
	if maxDepth <= 0 {
		maxDepth = math.MaxInt // unlimited (consistent with WebDAV deepScan)
	}
	queue := make([]scanNode, 0, len(roots))
	seen := map[string]struct{}{}
	for _, root := range roots {
		if root == "" {
			continue
		}
		queue = append(queue, scanNode{path: root, depth: 0})
		seen[root] = struct{}{}
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		status.TotalDirsDiscovered = len(seen)
		scopeKey := buildDirScopeKey(node.path, dirSyncScopeScan)
		headers := h.scanAuthHeaders()
		if snap, ok, _ := h.dirSyncStore.GetSnapshot(context.Background(), scopeKey); ok && snap != nil && !snap.NextRefreshAt.IsZero() && time.Now().Before(snap.NextRefreshAt) {
			status.DirsSkipped++
			status.DirsScanned++
			if node.depth < maxDepth {
				for _, child := range h.extractDirChildrenFromPayload(node.path, snap.PayloadJSON) {
					if _, exists := seen[child]; exists {
						continue
					}
					seen[child] = struct{}{}
					queue = append(queue, scanNode{path: child, depth: node.depth + 1})
				}
			}
			status.UpdatedAt = time.Now()
			_ = h.dirSyncStore.UpsertStatus(context.Background(), status)
			continue
		}

		reqBody, _ := json.Marshal(map[string]interface{}{
			"path":     node.path,
			"page":     1,
			"per_page": 1000,
			"refresh":  false,
		})
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://dirsync.local/api/fs/list", bytes.NewReader(reqBody))
		req.Header = headers
		req.Header.Set("Content-Type", "application/json")
		respStatus, respData, payload, itemCount, err := h.liveFsListResponse(req, reqBody, node.path, true)
		status.DirsScanned++
		if err != nil || respStatus < 200 || respStatus >= 300 || !isSuccessfulListPayload(payload) {
			status.DirsFailed++
			if err != nil {
				status.LastError = err.Error()
			} else if code := payloadResponseCode(payload); code != 0 {
				status.LastError = "upstream list returned code " + strconv.Itoa(code)
			}
			status.UpdatedAt = time.Now()
			_ = h.dirSyncStore.UpsertStatus(context.Background(), status)
			continue
		}
		status.DirsSucceeded++
		status.ItemsSynced += itemCount
		status.LastError = ""
		h.persistSnapshot(context.Background(), node.path, scopeKey, dirSyncScopeScan, payload, itemCount, dirSyncModeScan, "")
		if node.depth < maxDepth {
			for _, child := range h.extractDirChildrenFromResponse(node.path, respData) {
				if _, exists := seen[child]; exists {
					continue
				}
				seen[child] = struct{}{}
				queue = append(queue, scanNode{path: child, depth: node.depth + 1})
			}
		}
		status.UpdatedAt = time.Now()
		_ = h.dirSyncStore.UpsertStatus(context.Background(), status)
	}
	status.Status = "done"
	status.FinishedAt = time.Now()
	status.LastSuccessAt = status.FinishedAt
	status.UpdatedAt = status.FinishedAt
	_ = h.dirSyncStore.UpsertStatus(context.Background(), status)
}

func (h *AlistHandler) extractDirChildrenFromPayload(parentPath string, payload []byte) []string {
	var resp map[string]interface{}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return nil
	}
	return h.extractDirChildrenFromResponse(parentPath, resp)
}

func (h *AlistHandler) extractDirChildrenFromResponse(parentPath string, resp map[string]interface{}) []string {
	data, _ := resp["data"].(map[string]interface{})
	content, _ := data["content"].([]interface{})
	out := make([]string, 0)
	for _, item := range content {
		fileData, _ := item.(map[string]interface{})
		if fileData == nil {
			continue
		}
		isDir, _ := fileData["is_dir"].(bool)
		if !isDir {
			continue
		}
		if childPath, ok := fileData["path"].(string); ok && childPath != "" {
			out = append(out, childPath)
			continue
		}
		name, _ := fileData["name"].(string)
		if name != "" {
			out = append(out, path.Join(parentPath, name))
		}
	}
	return out
}

func (h *AlistHandler) HandleDirSyncOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		RespondHTTPErrorWithStatus(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := &DirSyncStatus{Name: dirSyncPrimaryStatusName, Status: "idle", Mode: dirSyncModeReq}
	if h.dirSyncStore != nil {
		if stored, ok, _ := h.dirSyncStore.GetStatus(r.Context(), dirSyncPrimaryStatusName); ok && stored != nil {
			status = stored
		}
	}
	total, fresh, stale, syncing, _ := int64(0), int64(0), int64(0), int64(0), error(nil)
	if h.dirSyncStore != nil {
		total, fresh, stale, syncing, _ = h.dirSyncStore.CountSnapshots(r.Context())
	}
	progress := 0
	if status.TotalDirsEstimate > 0 {
		progress = status.DirsScanned * 100 / status.TotalDirsEstimate
	}
	RespondSuccess(w, map[string]interface{}{
		"enabled":         h.dirSyncStore != nil,
		"scan_configured": h.scanConfigured(),
		"mode": func() string {
			if h.scanConfigured() {
				return dirSyncModeMixed
			}
			return dirSyncModeReq
		}(),
		"current_job": map[string]interface{}{
			"job_id":                status.JobID,
			"job_type":              status.JobType,
			"status":                status.Status,
			"progress_percent":      progress,
			"total_dirs_estimate":   status.TotalDirsEstimate,
			"total_dirs_discovered": status.TotalDirsDiscovered,
			"dirs_scanned":          status.DirsScanned,
			"dirs_succeeded":        status.DirsSucceeded,
			"dirs_failed":           status.DirsFailed,
			"dirs_skipped":          status.DirsSkipped,
			"items_synced":          status.ItemsSynced,
			"started_at":            formatRFC3339(status.StartedAt),
			"updated_at":            formatRFC3339(status.UpdatedAt),
			"finished_at":           formatRFC3339(status.FinishedAt),
			"next_run_at":           formatRFC3339(status.NextRunAt),
			"last_success_at":       formatRFC3339(status.LastSuccessAt),
			"last_error":            status.LastError,
		},
		"snapshot_stats": map[string]interface{}{
			"total_snapshots":   total,
			"fresh_snapshots":   fresh,
			"stale_snapshots":   stale,
			"syncing_snapshots": syncing,
		},
	})
}

func (h *AlistHandler) HandleDirSyncRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		RespondHTTPErrorWithStatus(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.scanConfigured() {
		RespondHTTPErrorWithStatus(w, "scan config not set", http.StatusBadRequest)
		return
	}
	go h.runDirSyncScan("manual_scan")
	RespondSuccess(w, map[string]interface{}{"accepted": true})
}

func (h *AlistHandler) HandleDirSyncPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		RespondHTTPErrorWithStatus(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	page := `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>目录同步状态</title>
<style>
body{margin:0;background:#f5f7fb;color:#1d2433;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:18px}
.hero,.card{background:#fff;border:1px solid #dce3f0;border-radius:18px}
.hero{padding:18px 20px;margin-bottom:14px}
.title{font-size:22px;font-weight:700}
.sub{margin-top:6px;color:#5f6b7a}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.card{padding:14px}
.k{font-size:12px;color:#6f7c8d}.v{margin-top:8px;font-size:28px;font-weight:700}
.row{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid #edf1f7}
.row:last-child{border-bottom:0}.ok{color:#138a52}.warn{color:#c66a00}.bad{color:#c23645}
button{border:0;background:#1f6feb;color:#fff;border-radius:999px;padding:10px 16px;font-weight:600;cursor:pointer}
</style></head>
<body><div class="wrap">
<div class="hero"><div class="title">主动探测 / 目录同步状态</div><div class="sub">同一套数据同时供后台管理与移动端查看</div><div style="margin-top:14px"><button id="refresh">刷新</button></div></div>
<div class="grid">
<div class="card"><div class="k">状态</div><div class="v" id="status">-</div></div>
<div class="card"><div class="k">进度</div><div class="v" id="progress">0%</div></div>
<div class="card"><div class="k">总目录</div><div class="v" id="total">0</div></div>
<div class="card"><div class="k">已探测</div><div class="v" id="scanned">0</div></div>
<div class="card"><div class="k">成功</div><div class="v" id="success">0</div></div>
<div class="card"><div class="k">失败</div><div class="v" id="failed">0</div></div>
</div>
<div class="card" style="margin-top:14px">
<div class="row"><span>最近更新时间</span><strong id="updated">-</strong></div>
<div class="row"><span>上次成功</span><strong id="lastSuccess">-</strong></div>
<div class="row"><span>下次计划时间</span><strong id="nextRun">-</strong></div>
<div class="row"><span>快照统计</span><strong id="snapshots">-</strong></div>
<div class="row"><span>最近错误</span><strong id="lastError">无</strong></div>
</div>
</div>
<script>
async function load(){const res=await fetch('/api/encrypt/dir-sync/overview',{cache:'no-store'});const root=await res.json();const d=root.data||{};const j=d.current_job||{};const s=d.snapshot_stats||{};
document.getElementById('status').textContent=(j.status||'idle').toUpperCase();
document.getElementById('progress').textContent=String(j.progress_percent||0)+'%';
document.getElementById('total').textContent=String(j.total_dirs_estimate||0);
document.getElementById('scanned').textContent=String(j.dirs_scanned||0);
document.getElementById('success').textContent=String(j.dirs_succeeded||0);
document.getElementById('failed').textContent=String(j.dirs_failed||0);
document.getElementById('updated').textContent=j.updated_at||'-';
document.getElementById('lastSuccess').textContent=j.last_success_at||'-';
document.getElementById('nextRun').textContent=j.next_run_at||'-';
document.getElementById('snapshots').textContent='总 '+String(s.total_snapshots||0)+' / 新鲜 '+String(s.fresh_snapshots||0)+' / 陈旧 '+String(s.stale_snapshots||0)+' / 同步中 '+String(s.syncing_snapshots||0);
document.getElementById('lastError').textContent=j.last_error||'无';}
document.getElementById('refresh').addEventListener('click',()=>load().catch(console.error));load().catch(console.error);setInterval(()=>load().catch(console.error),5000);
</script></body></html>`
	RespondRaw(w, http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func formatRFC3339(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Format(time.RFC3339)
}
