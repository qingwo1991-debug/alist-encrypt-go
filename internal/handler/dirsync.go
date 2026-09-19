package handler

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/rs/zerolog/log"
)

const (
	dirSyncRequestTTL = 2 * time.Minute
	dirSyncScanTTL    = 30 * time.Minute
	dirSyncScanEvery  = 15 * time.Minute
	dirSyncPageRoute  = "/api/encrypt/dir-sync/page"
	dirSyncModeMixed  = "mixed"
	dirSyncModeReq    = "request_fill"
	dirSyncModeScan   = "background_scan"
	dirSyncScopeScan  = "scan"
	// dirSyncSnapshotMaxPerPage is used when a snapshot is fetched for cache
	// persistence: a single full page is requested so the stored payload holds
	// the entire directory, not just the caller's page window.
	dirSyncSnapshotMaxPerPage = 5000
	// dirSyncRefreshMaxConcurrent caps request-driven async snapshot refreshes
	// running at once. Refreshes are pure optimization (they pre-warm cache);
	// under sustained miss load dropping the excess is safe and prevents
	// unbounded goroutine/DB-write growth.
	dirSyncRefreshMaxConcurrent = 8
)

func (h *AlistHandler) ensureDirSyncLoop() {
	if h == nil || h.dirSyncStore == nil || !h.scanConfigured() {
		return
	}
	h.dirSyncStart.Do(func() {
		h.startDirSyncWork(func(ctx context.Context) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("Directory sync scheduler panicked")
				}
			}()
			h.runDirSyncScheduler(ctx)
		})
	})
}

func (h *AlistHandler) StartDirSyncLoop() {
	h.ensureDirSyncLoop()
}

func (h *AlistHandler) scanConfigured() bool {
	if h == nil || h.cfg == nil {
		return false
	}
	alist := h.cfg.AlistServerSnapshot()
	return strings.TrimSpace(alist.ScanAuthHeader) != "" ||
		strings.TrimSpace(alist.ScanUsername) != "" ||
		strings.TrimSpace(alist.ScanPassword) != ""
}

// snapshotScopeEnabled reports whether the given directory is eligible for
// snapshot read/write caching. Only directories matched by the user's configured
// encryption path whitelist (via MatchDir, which honors * / [..] patterns and
// even "/") are cached; every other path is served live with no snapshot.
// This keeps the cache strictly bounded to the paths the admin opted into, and
// makes a "poisoned" root listing under a subdirectory scope impossible — a
// root that the admin configured is a legitimate snapshot of its own.
func (h *AlistHandler) snapshotScopeEnabled(dirPath string) bool {
	if h == nil || h.passwdDAO == nil {
		return false
	}
	return h.passwdDAO.MatchDir(dirPath)
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
	alist := h.cfg.AlistServerSnapshot()
	if raw := strings.TrimSpace(alist.ScanAuthHeader); raw != "" {
		headers.Set("Authorization", raw)
		return headers
	}
	username := strings.TrimSpace(alist.ScanUsername)
	password := strings.TrimSpace(alist.ScanPassword)
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
			body["degraded_reason"] = publicDirSyncError(snap.LastError)
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

func normalizeDirPath(dirPath string) string {
	dirPath = strings.TrimSpace(dirPath)
	if dirPath == "" {
		return "/"
	}
	cleaned := path.Clean(dirPath)
	if cleaned == "." {
		return "/"
	}
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

func listItemBelongsToDir(dirPath, childPath, name string) bool {
	dirPath = normalizeDirPath(dirPath)
	childPath = normalizeDirPath(childPath)
	if dirPath == "/" {
		trimmed := strings.TrimPrefix(childPath, "/")
		if trimmed == "" {
			return false
		}
		if strings.Contains(trimmed, "/") {
			return false
		}
		return name == "" || path.Base(childPath) == name
	}
	if childPath == dirPath {
		return name == "" || path.Base(childPath) == name
	}
	if !strings.HasPrefix(childPath, dirPath+"/") {
		return false
	}
	return name == "" || path.Base(childPath) == name
}

// snapshotScopeMatches asserts a cached snapshot belongs to the caller's auth
// scope and to the currently-configured upstream host. The listing scope key
// already carries the credential hash, but a snapshot can outlive a config
// switch (provider URL change or credential rotation), so the caller double
// checks before serving. This is the access-scope part of the listing key:
// provider ID + normalized path + scope hash (rule version is validated
// separately, see validateSnapshotForDir).
func (h *AlistHandler) snapshotScopeMatches(snap *DirListSnapshot, authHash string) bool {
	if snap == nil || h == nil || h.cfg == nil {
		return false
	}
	if authHash != "" && snap.AuthScopeHash != "" && snap.AuthScopeHash != authHash {
		return false
	}
	if snap.ProviderHost != "" && snap.ProviderHost != h.cfg.GetAlistURL() {
		return false
	}
	return true
}

func validateSnapshotForDir(dirPath string, snap *DirListSnapshot) (bool, string) {
	if snap == nil {
		return false, "snapshot missing"
	}
	expected := normalizeDirPath(dirPath)
	if got := normalizeDirPath(snap.DisplayPath); got != expected {
		return false, fmt.Sprintf("snapshot display path mismatch: got=%s want=%s", got, expected)
	}
	if len(snap.PayloadJSON) == 0 {
		return false, "snapshot payload empty"
	}

	var body map[string]interface{}
	if err := json.Unmarshal(snap.PayloadJSON, &body); err != nil {
		return false, "snapshot payload invalid json"
	}
	data, _ := body["data"].(map[string]interface{})
	content, _ := data["content"].([]interface{})
	for _, item := range content {
		fileData, _ := item.(map[string]interface{})
		if fileData == nil {
			continue
		}
		name, _ := fileData["name"].(string)
		childPath, hasPath := fileData["path"].(string)
		if hasPath && strings.TrimSpace(childPath) != "" {
			if !listItemBelongsToDir(expected, childPath, name) {
				return false, fmt.Sprintf("item path %s not under %s", childPath, expected)
			}
			continue
		}
		if expected != "/" {
			return false, "snapshot item missing path for non-root dir"
		}
		if snap.SourceMode == dirSyncModeScan {
			return false, "background snapshot item missing path"
		}
	}
	return true, ""
}

func isSuccessfulListPayload(payload []byte) bool {
	return payloadResponseCode(payload) == 200
}

// knownRootMounts returns the set of top-level drive mount directory names
// (e.g. "移动云盘156", "omv", "豆包云"). They are derived from the configured
// encryption path whitelist's first path segment, plus any directory names
// observed in a successful "/" listing learned at runtime. The set is used to
// distinguish a genuine all-directory payload (e.g. a cover-index dir whose
// every item is a subdirectory) from a root-listing masquerade, whose item
// names are exactly these drive mount names.
func (h *AlistHandler) knownRootMounts() map[string]struct{} {
	out := make(map[string]struct{})
	if h != nil && h.cfg != nil {
		for _, p := range h.collectEncryptedSearchRoots() {
			seg := strings.Trim(p, "/")
			if seg == "" {
				continue
			}
			first := seg
			if i := strings.IndexByte(seg, '/'); i > 0 {
				first = seg[:i]
			}
			out[first] = struct{}{}
		}
	}
	if h != nil {
		h.rootMountsMu.RLock()
		for k := range h.rootMountsSet {
			out[k] = struct{}{}
		}
		h.rootMountsMu.RUnlock()
	}
	return out
}

// rememberRootMounts records drive mount directory names observed in a root
// listing so later probes classify root-listings correctly.
func (h *AlistHandler) rememberRootMounts(payload []byte) {
	if h == nil || len(payload) == 0 {
		return
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		return
	}
	data, _ := body["data"].(map[string]interface{})
	content, _ := data["content"].([]interface{})
	h.rootMountsMu.Lock()
	if h.rootMountsSet == nil {
		h.rootMountsSet = make(map[string]struct{})
	}
	for _, item := range content {
		fd, _ := item.(map[string]interface{})
		if fd == nil {
			continue
		}
		if isDir, _ := fd["is_dir"].(bool); !isDir {
			continue
		}
		if name, _ := fd["name"].(string); name != "" {
			h.rootMountsSet[name] = struct{}{}
		}
	}
	h.rootMountsMu.Unlock()
}

// snapshotPayloadRootPoisoned reports whether a list payload for a non-root
// directory is actually a root-listing masquerade: every entry is a directory
// (no files at all) and every entry name matches a known top-level drive
// mount. Real directories that legitimately contain only subdirectories keep
// caching because their child names are content names, not drive mounts.
func (h *AlistHandler) snapshotPayloadRootPoisoned(dirPath string, payload []byte) bool {
	if dirPath == "" || dirPath == "/" || dirPath == "//" || len(payload) == 0 {
		return false
	}
	var body map[string]interface{}
	if err := json.Unmarshal(payload, &body); err != nil {
		return false
	}
	data, _ := body["data"].(map[string]interface{})
	content, _ := data["content"].([]interface{})
	if len(content) == 0 {
		return false
	}
	dirs := 0
	files := 0
	var names []string
	for _, item := range content {
		fd, _ := item.(map[string]interface{})
		if fd == nil {
			return false
		}
		if isDir, _ := fd["is_dir"].(bool); isDir {
			dirs++
		} else {
			files++
		}
		if name, _ := fd["name"].(string); name != "" {
			names = append(names, name)
		}
	}
	// A payload that contains any file is never a root listing (drives are dirs).
	if files > 0 {
		return false
	}
	// All directories: only suspicious when the names overlap heavily with the
	// known root mounts, i.e. this really is the drive-root view.
	if dirs == 0 || dirs != len(content) {
		return false
	}
	roots := h.knownRootMounts()
	if len(roots) == 0 {
		// Without any known top-level mounts we cannot tell a drive-root
		// masquerade from a genuine all-directory folder, so never mislabel
		// a real directory — allow it (the live full listing still wins).
		return false
	}
	overlap := 0
	for _, n := range names {
		if _, ok := roots[n]; ok {
			overlap++
		}
	}
	// Root listing is poisoned when the large majority of its entries are known
	// top-level mounts (≥60% and at least 6). Config-uncovered drives can still
	// appear in the real mount set, so require a heavy majority, not all.
	if overlap < 6 || overlap*5 < len(names)*3 {
		return false
	}
	return dirs >= 3
}

func (h *AlistHandler) serveSnapshot(w http.ResponseWriter, snap *DirListSnapshot, cacheMode string, page, perPage int) {
	if snap == nil {
		RespondHTTPErrorWithStatus(w, "snapshot not found", http.StatusNotFound)
		return
	}
	now := time.Now()
	stale := snap.Stale || (!snap.NextRefreshAt.IsZero() && now.After(snap.NextRefreshAt))
	syncing := snap.SyncState == "syncing"
	respond := h.markSnapshotServingMode(snap.PayloadJSON, stale, syncing, cacheMode, snap)
	if page > 0 && perPage > 0 {
		if sliced, ok := paginateSnapshotJSON(respond, page, perPage); ok {
			respond = sliced
		}
	}
	RespondRaw(w, http.StatusOK, "application/json", respond)
}

// listPaginationFromBody extracts the page/per_page window a client requested.
// Defaults match the upstream Alist contract (page=1, per_page=0 meaning all,
// and the Web UI sending per_page=N per page view).
func listPaginationFromBody(reqBody map[string]interface{}) (int, int) {
	page, perPage := 1, 0
	if v, ok := reqBody["page"].(float64); ok {
		page = int(v)
		if page < 1 {
			page = 1
		}
	}
	if v, ok := reqBody["per_page"].(float64); ok {
		perPage = int(v)
	}
	return page, perPage
}

// paginateSnapshotJSON trims a snapshot list payload to the requested window
// so a served snapshot keeps the same pagination contract as a live listing.
// Returns the original payload when pagination cannot be applied.
func paginateSnapshotJSON(payload []byte, page, perPage int) ([]byte, bool) {
	if page <= 0 || perPage <= 0 {
		return payload, false
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return payload, false
	}
	data, ok := doc["data"].(map[string]interface{})
	if !ok {
		return payload, false
	}
	content, ok := data["content"].([]interface{})
	if !ok {
		return payload, false
	}
	total := len(content)
	start := (page - 1) * perPage
	if start >= total {
		content = []interface{}{}
	} else {
		end := start + perPage
		if end > total {
			end = total
		}
		content = content[start:end]
	}
	data["content"] = content
	if _, ok := data["total"].(float64); !ok {
		data["total"] = float64(total)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return payload, false
	}
	return encoded, true
}

func (h *AlistHandler) persistSnapshot(ctx context.Context, dirPath, scopeKey, authHash string, payload []byte, itemCount int, sourceMode string, lastErr string) {
	if h == nil || h.dirSyncStore == nil {
		return
	}
	if sourceMode != dirSyncModeScan && !h.snapshotScopeEnabled(dirPath) {
		return
	}
	if h.snapshotPayloadRootPoisoned(dirPath, payload) {
		log.Error().
			Str("mode", sourceMode).
			Str("dir_path", dirPath).
			Int("item_count", itemCount).
			Str("scope", scopeKey).
			Msg("Rejecting root-poisoned snapshot payload; refusing to persist")
		return
	}
	now := time.Now()
	// Last-writer-wins on a shared scope key is unsafe under concurrency: a
	// stale page-windowed listing (small item_count) can arrive after a full
	// scan snapshot for the same directory and overwrite it. Guard by refusing
	// to downgrade a strictly-newer-and-fuller row. Only request-driven
	// persists are gated — scan writes may be smaller/fresher by design.
	existing, exists, _ := h.dirSyncStore.GetSnapshot(ctx, scopeKey)
	if exists && existing != nil && existing.ItemCount > itemCount &&
		existing.UpdatedAt.After(now.Add(-30*time.Second)) &&
		sourceMode == dirSyncModeReq {
		log.Debug().
			Str("dir_path", dirPath).
			Str("scope", scopeKey).
			Int("existing_count", existing.ItemCount).
			Int("new_count", itemCount).
			Msg("Skipping snapshot persist: refusing to downgrade a fuller recent snapshot")
		return
	}
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

// fullListRequestBody rewrites a caller-supplied /api/fs/list body so the
// snapshot fetch pulls the full directory listing in a single page instead of
// echoing the caller's pagination (e.g. per_page:5 from the Web UI), which
// would otherwise persist a truncated snapshot. page=1 and a large per_page
// capture the whole folder in one upstream round-trip.
func fullListRequestBody(body []byte) []byte {
	if len(bytes.TrimSpace(body)) == 0 {
		return body
	}
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	req["page"] = 1
	req["per_page"] = dirSyncSnapshotMaxPerPage
	encoded, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return encoded
}

// withRefreshTrue returns a copy of body with refresh set to true, forcing the
// upstream to bypass its own cache. Used to recover from transient root-poison
// responses where openalist returns a drive-root masquerade instead of the real
// directory listing.
func withRefreshTrue(body []byte) []byte {
	if len(bytes.TrimSpace(body)) == 0 {
		return body
	}
	var req map[string]interface{}
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	req["refresh"] = true
	encoded, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return encoded
}

func (h *AlistHandler) updateSnapshotSyncing(ctx context.Context, scopeKey string, syncing bool, lastErr string) {
	if h == nil || h.dirSyncStore == nil {
		return
	}
	if _, err := h.dirSyncStore.SetSnapshotSyncing(ctx, scopeKey, syncing, lastErr); err != nil {
		logDirSyncFailure("snapshot_state", scopeKey, 0, 0, err)
	}
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

	respBody, err := readLimitedBody(resp, maxProxyResponseBody)
	if err != nil {
		return 0, nil, nil, 0, err
	}

	var respData map[string]interface{}
	if err := json.Unmarshal(respBody, &respData); err != nil {
		return resp.StatusCode, nil, respBody, 0, nil
	}

	if h.snapshotPayloadRootPoisoned(dirPath, respBody) {
		var reqData struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(body, &reqData)
		log.Warn().
			Str("dir_path", dirPath).
			Str("req_body_path", reqData.Path).
			Str("endpoint", "/api/fs/list").
			Int("status", resp.StatusCode).
			Int("resp_len", len(respBody)).
			Msg("LIVE_RETURNED_ROOT_POISON")
	}

	itemCount := 0
	if code, ok := respData["code"].(float64); ok && code == 200 {
		if data, ok := respData["data"].(map[string]interface{}); ok {
			if content, ok := data["content"].([]interface{}); ok {
				itemCount = len(content)
				if dirPath == "/" {
					// Learn top-level mount names so root-listing masquerades for
					// deeper dirs can be recognized without mislabeling genuine
					// all-directory subdirs.
					h.rememberRootMounts(respBody)
				}
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
						h.fileDAO.SetFromAlistResponse(filePath, fileData, rawURLAuthScope(r.Header))
						if cached, ok := h.fileDAO.Get(filePath); ok && cached != nil && cached.ContentVersion == encryption.ContentVersionV2 && cached.Size > 0 {
							fileData["size"] = float64(cached.Size)
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
						if name == "" {
							continue
						}
						displayPath := path.Join(dirPath, name)
						// OpenList commonly omits item.path. Background snapshots require a
						// canonical child path and were otherwise guaranteed to fail their
						// own validation on the next read.
						fileData["path"] = displayPath
						content[i] = fileData

						if allowDecrypt {
							size := int64(0)
							if sizeVal, ok := fileData["size"].(float64); ok {
								size = int64(sizeVal)
							}
							encryptedPath := displayPath
							if mapped, ok := h.fileDAO.GetEncPath(displayPath); ok && mapped != "" {
								encryptedPath = mapped
							}
							h.fileDAO.SetEncPathMappingWithInfo(displayPath, encryptedPath, name, size, isDir)
							if !isDir && enableProbe {
								if size > 0 {
									h.upsertMetaFromListing(r.Context(), displayPath, size)
								}
								h.enqueueProbeFromList(r, displayPath, size)
							}
						}
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
	// Bound the number of concurrently running request-driven refreshes. A
	// refresh is a pure optimization (pre-warming the snapshot cache); if the cap
	// is already reached, dropping this one is safe — the next request or the
	// periodic scan will repopulate the row, and we'd rather shed load than
	// spawn an unbounded number of full upstream fetches. The semaphore is
	// acquired INSIDE the goroutine and held for its whole lifetime so the cap
	// bounds actual concurrent work, not just scheduling.
	ctx := h.dirSyncCtx
	if ctx == nil {
		ctx = context.Background()
	}
	h.startDirSyncWork(func(ctx context.Context) {
		select {
		case h.dirSyncRefreshSem <- struct{}{}:
			defer func() { <-h.dirSyncRefreshSem }()
		default:
			log.Debug().Str("path", dirPath).Msg("Dir-sync refresh cap reached; dropping refresh")
			return
		}
		h.updateSnapshotSyncing(ctx, scopeKey, true, "")
		_, _, _ = h.dirSyncGroup.Do(scopeKey, func() (interface{}, error) {
			upstreamBody := fullListRequestBody(body)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://dirsync.local/api/fs/list", bytes.NewReader(upstreamBody))
			req.Header = headers.Clone()
			status, _, payload, itemCount, liveErr := h.liveFsListResponse(req, upstreamBody, dirPath, true)
			if liveErr != nil {
				logDirSyncFailure("snapshot_refresh", dirPath, status, 0, liveErr)
				h.updateSnapshotSyncing(ctx, scopeKey, false, publicDirSyncError(liveErr.Error()))
				return nil, liveErr
			}
			if status >= 200 && status < 300 && isSuccessfulListPayload(payload) {
				h.persistSnapshot(ctx, dirPath, scopeKey, authScopeHash(headers), payload, itemCount, sourceMode, "")
				return nil, nil
			}
			errText := "upstream list refresh failed"
			if code := payloadResponseCode(payload); code != 0 {
				errText = "upstream list returned code " + strconv.Itoa(code)
			}
			logDirSyncFailure("snapshot_refresh", dirPath, status, payloadResponseCode(payload), nil)
			h.updateSnapshotSyncing(ctx, scopeKey, false, errText)
			return nil, nil
		})
	})
}

// learnRootMountsOnce fetches the drive root listing once (using the scan
// account) so the top-level mount names are known. Without the full mount set
// a drive-root masquerade that includes unmounted/config-uncovered drives
// (e.g. "老婆的", "谷歌云盘1991") would slip past the poison classifier.
func (h *AlistHandler) learnRootMountsOnce(ctx context.Context) {
	h.rootMountsOnce.Do(func() {
		if h == nil || h.cfg == nil {
			return
		}
		headers := h.scanAuthHeaders()
		if len(headers) == 0 {
			return
		}
		reqBody, _ := json.Marshal(map[string]interface{}{
			"path":     "/",
			"page":     1,
			"per_page": dirSyncSnapshotMaxPerPage,
			"refresh":  false,
		})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://dirsync.local/api/fs/list", bytes.NewReader(reqBody))
		req.Header = headers.Clone()
		req.Header.Set("Content-Type", "application/json")
		status, _, payload, _, err := h.liveFsListResponse(req, reqBody, "/", true)
		if err != nil || status < 200 || status >= 300 || !isSuccessfulListPayload(payload) {
			logDirSyncFailure("learn_root_mounts", "/", status, payloadResponseCode(payload), err)
			return
		}
		h.rememberRootMounts(payload)
		log.Info().Msg("Learned top-level drive mounts from '/")
	})
}

func (h *AlistHandler) runDirSyncScheduler(ctx context.Context) {
	h.learnRootMountsOnce(ctx)
	h.runDirSyncScan(ctx, "bootstrap_scan")
	ticker := time.NewTicker(dirSyncScanEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.runDirSyncScan(ctx, "scheduled_scan")
		}
	}
}

func (h *AlistHandler) runDirSyncScan(ctx context.Context, jobType string) {
	if h == nil || h.dirSyncStore == nil || !h.scanConfigured() {
		return
	}
	if !h.dirSyncRunning.CompareAndSwap(false, true) {
		log.Info().Str("job_type", jobType).Msg("Directory sync scan already running; coalescing trigger")
		return
	}
	defer h.dirSyncRunning.Store(false)
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
	_ = h.dirSyncStore.UpsertStatus(ctx, status)
	if len(roots) == 0 {
		status.Status = "done"
		status.FinishedAt = time.Now()
		status.LastSuccessAt = status.FinishedAt
		_ = h.dirSyncStore.UpsertStatus(ctx, status)
		return
	}

	type scanNode struct {
		path  string
		depth int
	}
	maxDepth := h.cfg.AlistServerSnapshot().ScanMaxDepth
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

	// Persisting the full status row on every scanned node is O(dirs) DB writes
	// per scan cycle (fresh dirs included). Throttle flush to at most once per
	// second or per 256 nodes; the final flush below always persists.
	var statusDirty bool
	lastStatusFlush := time.Now()
	flushStatus := func(force bool) {
		if !statusDirty {
			return
		}
		if !force && time.Since(lastStatusFlush) < time.Second && status.DirsScanned%64 != 0 {
			return
		}
		status.UpdatedAt = time.Now()
		_ = h.dirSyncStore.UpsertStatus(ctx, status)
		lastStatusFlush = time.Now()
		statusDirty = false
	}

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			flushStatus(true)
			return
		default:
		}
		node := queue[0]
		queue = queue[1:]
		status.TotalDirsDiscovered = len(seen)
		scopeKey := buildDirScopeKey(node.path, dirSyncScopeScan)
		headers := h.scanAuthHeaders()
		if snap, ok, _ := h.dirSyncStore.GetSnapshot(ctx, scopeKey); ok && snap != nil && !snap.NextRefreshAt.IsZero() && time.Now().Before(snap.NextRefreshAt) {
			status.DirsSkipped++
			status.DirsScanned++
			statusDirty = true
			if node.depth < maxDepth {
				for _, child := range h.extractDirChildrenFromPayload(node.path, snap.PayloadJSON) {
					if _, exists := seen[child]; exists {
						continue
					}
					seen[child] = struct{}{}
					queue = append(queue, scanNode{path: child, depth: node.depth + 1})
				}
			}
			flushStatus(false)
			continue
		}

		reqBody, _ := json.Marshal(map[string]interface{}{
			"path":     node.path,
			"page":     1,
			"per_page": dirSyncSnapshotMaxPerPage,
			"refresh":  false,
		})
		scanCtx := withProbeSource(ctx, probeSourceDirSync)
		req, _ := http.NewRequestWithContext(scanCtx, http.MethodPost, "http://dirsync.local/api/fs/list", bytes.NewReader(reqBody))
		req.Header = headers
		req.Header.Set("Content-Type", "application/json")
		respStatus, respData, payload, itemCount, err := h.liveFsListResponse(req, reqBody, node.path, true)
		status.DirsScanned++
		statusDirty = true
		if err != nil || respStatus < 200 || respStatus >= 300 || !isSuccessfulListPayload(payload) {
			status.DirsFailed++
			logDirSyncFailure("scan", node.path, respStatus, payloadResponseCode(payload), err)
			status.LastError = "upstream list refresh failed"
			if code := payloadResponseCode(payload); code != 0 {
				status.LastError = "upstream list returned code " + strconv.Itoa(code)
			}
			flushStatus(true)
			continue
		}
		status.DirsSucceeded++
		status.ItemsSynced += itemCount
		status.LastError = ""
		h.persistSnapshot(ctx, node.path, scopeKey, dirSyncScopeScan, payload, itemCount, dirSyncModeScan, "")
		if node.depth < maxDepth {
			for _, child := range h.extractDirChildrenFromResponse(node.path, respData) {
				if _, exists := seen[child]; exists {
					continue
				}
				seen[child] = struct{}{}
				queue = append(queue, scanNode{path: child, depth: node.depth + 1})
			}
		}
		flushStatus(false)
	}
	status.Status = "done"
	status.FinishedAt = time.Now()
	status.LastSuccessAt = status.FinishedAt
	status.UpdatedAt = status.FinishedAt
	_ = h.dirSyncStore.UpsertStatus(ctx, status)
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

// publicDirSyncError deliberately never returns persisted diagnostic text. Older
// rows may contain upstream URLs, response messages, or other sensitive details.
func publicDirSyncError(raw string) string {
	if raw == "" {
		return ""
	}
	return "Directory synchronization failed; check server logs"
}

// Keep operational context internally without logging arbitrary error strings:
// URL errors and upstream messages may embed passwords, tokens, or cookies.
func logDirSyncFailure(stage, dirPath string, status, code int, err error) {
	kind := "upstream_response"
	if err != nil {
		kind = "internal"
		var networkErr net.Error
		switch {
		case errors.Is(err, context.Canceled):
			kind = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			kind = "deadline_exceeded"
		case errors.As(err, &networkErr):
			kind = "network"
			if networkErr.Timeout() {
				kind = "network_timeout"
			}
		}
	}
	log.Warn().Str("stage", stage).Str("path", dirPath).
		Int("http_status", status).Int("upstream_code", code).
		Str("error_kind", kind).Str("error_type", fmt.Sprintf("%T", err)).
		Msg("Directory synchronization failed")
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
	progressTotal := status.TotalDirsEstimate
	if status.TotalDirsDiscovered > progressTotal {
		progressTotal = status.TotalDirsDiscovered
	}
	if progressTotal > 0 {
		progress = status.DirsScanned * 100 / progressTotal
		if progress > 100 {
			progress = 100
		}
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
			"last_error":            publicDirSyncError(status.LastError),
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
	h.startDirSyncWork(func(ctx context.Context) { h.runDirSyncScan(ctx, "manual_scan") })
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
<div class="hero"><div class="title">主动探测 / 目录同步状态</div><div class="sub">同一套数据同时供后台管理与移动端查看</div><div style="margin-top:14px"><button id="refresh">刷新</button> <a href="/public/index.html#/login">登录管理后台</a></div><div id="notice" role="status"></div></div>
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
function loginToken(){try{return JSON.parse(localStorage.getItem('basic')||'{}').token||'';}catch{return '';}}
function showError(message){document.getElementById('notice').textContent=message;for(const id of ['status','progress','total','scanned','success','failed','updated','lastSuccess','nextRun','snapshots','lastError']){document.getElementById(id).textContent='-';}}
let loading=false;
async function load(){if(loading)return;const token=loginToken();if(!token){showError('请先登录管理后台，再刷新本页。');return;}loading=true;try{const res=await fetch('/api/encrypt/dir-sync/overview',{cache:'no-store',headers:{Authorization:'Bearer '+token}});if(res.status===401){showError('登录已过期，请重新登录管理后台。');return;}if(!res.ok)throw new Error('overview unavailable');const root=await res.json();if(root.code!==0)throw new Error('overview unavailable');document.getElementById('notice').textContent='';const d=root.data||{};const j=d.current_job||{};const s=d.snapshot_stats||{};
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
document.getElementById('lastError').textContent=j.last_error||'无';}catch{showError('暂时无法获取同步状态，请稍后刷新。');}finally{loading=false;}}
document.getElementById('refresh').addEventListener('click',load);load();setInterval(load,5000);
</script></body></html>`
	RespondRaw(w, http.StatusOK, "text/html; charset=utf-8", []byte(page))
}

func formatRFC3339(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Format(time.RFC3339)
}
