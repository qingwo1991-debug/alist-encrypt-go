package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

// handleStats returns runtime stats for caches and config toggles
func (p *ProxyServer) handleStats(w http.ResponseWriter, r *http.Request) {
	p.ensureRuntimeCaches()
	probeCount := 0
	probeStrategyCache.Range(func(_, _ interface{}) bool {
		probeCount++
		return true
	})
	probeStatsSnapshot := probeMethodStats.snapshot()
	probeByScope := make(map[string]map[string]interface{}, len(probeStatsSnapshot))
	type scopeRankingItem struct {
		Key           string
		Preferred     string
		Score         int64
		TotalSuccess  int64
		TotalFail     int64
		TotalCacheHit int64
	}
	rankings := make([]scopeRankingItem, 0, len(probeStatsSnapshot))
	for scopeKey, scopeStats := range probeStatsSnapshot {
		scopeEntry := map[string]interface{}{}
		methods := []ProbeMethod{ProbeMethodRange, ProbeMethodHead, ProbeMethodWebDAV}
		bestMethod := ""
		var bestScore int64 = -1 << 62
		var totalSuccess int64
		var totalFail int64
		var totalCacheHit int64
		for _, method := range methods {
			counter := scopeStats[method]
			scopeEntry[string(method)] = map[string]int64{
				"success":   counter.Success,
				"fail":      counter.Fail,
				"cache_hit": counter.CacheHit,
			}
			totalSuccess += counter.Success
			totalFail += counter.Fail
			totalCacheHit += counter.CacheHit
			score := counter.Success*4 + counter.CacheHit*2 - counter.Fail*3
			if score > bestScore {
				bestScore = score
				bestMethod = string(method)
			}
		}
		scopeEntry["preferred_method"] = bestMethod
		probeByScope[scopeKey] = scopeEntry
		rankings = append(rankings, scopeRankingItem{
			Key:           scopeKey,
			Preferred:     bestMethod,
			Score:         bestScore,
			TotalSuccess:  totalSuccess,
			TotalFail:     totalFail,
			TotalCacheHit: totalCacheHit,
		})
	}
	sort.SliceStable(rankings, func(i, j int) bool {
		if rankings[i].Score == rankings[j].Score {
			return rankings[i].TotalSuccess > rankings[j].TotalSuccess
		}
		return rankings[i].Score > rankings[j].Score
	})
	if len(rankings) > 10 {
		rankings = rankings[:10]
	}
	rankingOutput := make([]map[string]interface{}, 0, len(rankings))
	for _, item := range rankings {
		rankingOutput = append(rankingOutput, map[string]interface{}{
			"scope":            item.Key,
			"preferred_method": item.Preferred,
			"score":            item.Score,
			"success":          item.TotalSuccess,
			"fail":             item.TotalFail,
			"cache_hit":        item.TotalCacheHit,
		})
	}

	sizeMapCount := 0
	sizeMapDirty := false
	if p.sizeMap != nil {
		p.sizeMapMu.RLock()
		sizeMapCount = len(p.sizeMap)
		sizeMapDirty = p.sizeMapDirty
		p.sizeMapMu.RUnlock()
	}

	rangeCompatCount := 0
	rangeCompatFailureKeys := 0
	if p.rangeCompat != nil {
		p.rangeCompatMu.RLock()
		rangeCompatCount = len(p.rangeCompat)
		if p.rangeCompatFailures != nil {
			rangeCompatFailureKeys = len(p.rangeCompatFailures)
		}
		p.rangeCompatMu.RUnlock()
	}
	webdavNegativeCount := 0
	p.webdavNegativeMu.Lock()
	webdavNegativeCount = len(p.webdavNegativeCache)
	p.webdavNegativeMu.Unlock()

	localSizeCount := 0
	localStrategyCount := 0
	localRangeCompatCount := 0
	localRangeProbeCount := 0
	localProviderCatalogCount := 0
	dbExportSince := int64(0)
	dbExportCursor := ""
	dbExportStrategySince := int64(0)
	dbExportStrategyCursor := ""
	dbExportRangeSince := int64(0)
	dbExportRangeCursor := ""
	dbExportLastSuccessAt := ""
	dbExportLastCycleImported := 0
	dbExportTotalImported := int64(0)
	dbExportSyncMode := ""
	dbExportLastError := ""
	if p.localStore != nil {
		if sizeCount, strategyCount, rangeCompatCount, rangeProbeCount, err := p.localStore.CountsExtended(); err == nil {
			localSizeCount = sizeCount
			localStrategyCount = strategyCount
			localRangeCompatCount = rangeCompatCount
			localRangeProbeCount = rangeProbeCount
		}
		if count, err := p.localStore.CountProviderCatalog(); err == nil {
			localProviderCatalogCount = count
		}
		if since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportCheckpointName); err == nil {
			dbExportSince = since
			dbExportCursor = cursor
		}
		if since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportStrategyCheckpointName); err == nil {
			dbExportStrategySince = since
			dbExportStrategyCursor = cursor
		}
		if since, cursor, err := p.localStore.GetSyncCheckpoint(dbExportRangeCheckpointName); err == nil {
			dbExportRangeSince = since
			dbExportRangeCursor = cursor
		}
		if status, err := p.localStore.GetSyncStatus(dbExportSyncStatusName); err == nil && status != nil {
			dbExportLastSuccessAt = unixToRFC3339(status.LastSuccessAt)
			dbExportLastCycleImported = status.LastCycleImported
			dbExportTotalImported = status.TotalImported
			dbExportSyncMode = status.SyncMode
			dbExportLastError = status.LastError
		}
	}

	data := map[string]interface{}{
		"status": "ok",
		"uptime": time.Since(startTime).Round(time.Second).String(),
		"cache": map[string]interface{}{
			"file_cache_entries":     p.fileCache.Len(),
			"redirect_cache_entries": p.redirectCache.Len(),
			"probe_strategy_entries": probeCount,
			"probe_method_by_scope":  probeByScope,
			"probe_scope_ranking":    rankingOutput,
			"probe_strategy_ttl_minutes": func() int {
				if p.config != nil {
					return p.config.ProbeStrategyTTLMinutes
				}
				return 0
			}(),
			"probe_strategy_stable_threshold": func() int {
				if p.config != nil {
					return p.config.ProbeStrategyStableThreshold
				}
				return 0
			}(),
			"probe_strategy_failure_threshold": func() int {
				if p.config != nil {
					return p.config.ProbeStrategyFailureThreshold
				}
				return 0
			}(),
		},
		"size_map": map[string]interface{}{
			"enabled": p.config != nil && p.config.EnableSizeMap,
			"entries": sizeMapCount,
			"dirty":   sizeMapDirty,
			"ttl_minutes": func() int {
				if p.config != nil {
					return p.config.SizeMapTTL
				}
				return 0
			}(),
		},
		"range_compat_cache": map[string]interface{}{
			"enabled":      p.config != nil && p.config.EnableRangeCompatCache,
			"entries":      rangeCompatCount,
			"failure_keys": rangeCompatFailureKeys,
			"ttl_minutes": func() int {
				if p.config != nil {
					return p.config.RangeCompatTTL
				}
				return 0
			}(),
			"min_failures": func() int {
				if p.config != nil {
					return p.config.RangeCompatMinFailures
				}
				return 0
			}(),
		},
		"webdav_negative_cache": map[string]interface{}{
			"entries": webdavNegativeCount,
			"ttl_minutes": func() int {
				if p.config != nil {
					return p.config.WebDAVNegativeCacheTTLMinutes
				}
				return 0
			}(),
		},
		"play_fallback": map[string]interface{}{
			"enabled": p.config != nil && p.config.PlayFirstFallback,
			"count":   atomic.LoadUint64(&p.playFirstCount),
		},
		"local_store": map[string]interface{}{
			"enabled":                  p.localStore != nil,
			"size_entries":             localSizeCount,
			"strategy_entries":         localStrategyCount,
			"range_compat_entries":     localRangeCompatCount,
			"range_probe_targets":      localRangeProbeCount,
			"provider_catalog_entries": localProviderCatalogCount,
			"size_retention_days": func() int {
				if p.config != nil {
					return p.config.LocalSizeRetentionDays
				}
				return 0
			}(),
			"strategy_retention_days": func() int {
				if p.config != nil {
					return p.config.LocalStrategyRetentionDays
				}
				return 0
			}(),
		},
		"db_export_sync": map[string]interface{}{
			"enabled": func() bool {
				if p.config != nil {
					return p.config.EnableDBExportSync
				}
				return false
			}(),
			"base_url": func() string {
				if p.config != nil {
					return p.config.DBExportBaseURL
				}
				return ""
			}(),
			"interval_seconds": func() int {
				if p.config != nil {
					return p.config.DBExportSyncIntervalSeconds
				}
				return 0
			}(),
			"auth_enabled": func() bool {
				if p.config != nil {
					return p.config.DBExportAuthEnabled
				}
				return false
			}(),
			"checkpoint_since":    dbExportSince,
			"checkpoint_cursor":   dbExportCursor,
			"strategy_since":      dbExportStrategySince,
			"strategy_cursor":     dbExportStrategyCursor,
			"range_since":         dbExportRangeSince,
			"range_cursor":        dbExportRangeCursor,
			"last_success_at":     dbExportLastSuccessAt,
			"last_cycle_imported": dbExportLastCycleImported,
			"total_imported":      dbExportTotalImported,
			"sync_mode":           dbExportSyncMode,
			"last_error":          dbExportLastError,
		},
		"http_profiles": map[string]interface{}{
			"control": p.controlHTTPStats.snapshot(),
			"probe":   p.probeHTTPStats.snapshot(),
			"stream":  p.streamHTTPStats.snapshot(),
		},
		"transport": map[string]interface{}{
			"max_idle_conns": func() int {
				if p.transport != nil {
					return p.transport.MaxIdleConns
				}
				return 0
			}(),
			"max_idle_conns_per_host": func() int {
				if p.transport != nil {
					return p.transport.MaxIdleConnsPerHost
				}
				return 0
			}(),
			"max_conns_per_host": func() int {
				if p.transport != nil {
					return p.transport.MaxConnsPerHost
				}
				return 0
			}(),
			"idle_conn_timeout_seconds": func() int64 {
				if p.transport != nil {
					return int64(p.transport.IdleConnTimeout / time.Second)
				}
				return 0
			}(),
		},
		"parallel_decrypt": map[string]interface{}{
			"enabled": p.config != nil && p.config.EnableParallelDecrypt,
			"concurrency": func() int {
				if p.config != nil {
					return p.config.ParallelDecryptConcurrency
				}
				return 0
			}(),
			"auto_detected": maxParallelDecrypt,
		},
		"stream_buffer_kb": func() int {
			if p.config != nil {
				return p.config.StreamBufferKB
			}
			return 0
		}(),
		"redirect_cache_ttl_minutes": func() int {
			if p.config != nil {
				return p.config.RedirectCacheTTLMinutes
			}
			return 0
		}(),
		"debug": map[string]interface{}{
			"enabled": func() bool {
				if p.config != nil {
					return p.config.DebugEnabled
				}
				return false
			}(),
			"level": func() string {
				if p.config != nil {
					return p.config.DebugLevel
				}
				return ""
			}(),
			"modules": func() []string {
				if p.config != nil {
					return p.config.DebugModules
				}
				return nil
			}(),
			"mask_sensitive": func() bool {
				if p.config != nil {
					return p.config.DebugMaskSensitive
				}
				return true
			}(),
			"sample_rate": func() int {
				if p.config != nil {
					return p.config.DebugSampleRate
				}
				return 0
			}(),
			"log_body_bytes": func() int {
				if p.config != nil {
					return p.config.DebugLogBodyBytes
				}
				return 0
			}(),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": data,
	})
}

// handleLocalState returns local SQLite state for a key or provider/path.
func (p *ProxyServer) handleLocalState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.localStore == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"found": false,
			},
		})
		return
	}

	query := r.URL.Query()
	key := query.Get("key")
	providerURL := query.Get("providerUrl")
	originalURL := query.Get("originalUrl")
	if key == "" {
		if providerHost, originalPath, ok := parseProviderAndPath(providerURL, originalURL); ok {
			key = buildLocalKey(providerHost, originalPath)
		}
	}
	if key == "" {
		http.Error(w, "missing key or providerUrl/originalUrl", http.StatusBadRequest)
		return
	}

	sizeRec, strategies, err := p.localStore.GetSnapshot(key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"found":         sizeRec != nil,
		"key":           key,
		"network_state": string(GetNetworkState()),
	}
	if sizeRec != nil {
		data["size"] = sizeRec
		data["strategies"] = strategies
	} else {
		data["strategies"] = []LocalStrategyRecord{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": data,
	})
}

// handleLocalExport dumps local SQLite data for migration.
func (p *ProxyServer) handleLocalExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.localStore == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": &LocalExport{},
		})
		return
	}

	data, err := p.localStore.ExportAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": data,
	})
}

// handleLocalImport imports local SQLite data from a JSON payload.
func (p *ProxyServer) handleLocalImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.localStore == nil {
		http.Error(w, "local store not initialized", http.StatusServiceUnavailable)
		return
	}

	const maxImportBytes = 10 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes)
	var payload LocalExport
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := p.localStore.Import(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	counts := map[string]int{
		"sizes":      len(payload.Sizes),
		"strategies": len(payload.Strategies),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": counts,
	})
}

// handleRestart 处理重启请求
func (p *ProxyServer) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    http.StatusNotImplemented,
		"message": "restart is not implemented in current runtime",
	})
}

// handleFsList 处理文件列表
func (p *ProxyServer) handleFsList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p.debugf("list", "%s Proxy handling fs list request", internal.LogPrefix(ctx, internal.TagList))
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 转发请求到 Alist
	req, err := http.NewRequestWithContext(r.Context(), "POST", p.getAlistURL()+"/api/fs/list", bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	reqData := map[string]interface{}{}
	_ = json.Unmarshal(body, &reqData)
	dirPath, _ := reqData["path"].(string)
	parentEncPath := p.findEncryptPath(dirPath)
	p.debugf("list", "%s Handling fs list for path: %s", internal.LogPrefix(ctx, internal.TagList), dirPath)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		copyWithBuffer(w, resp.Body)
		return
	}
	prefetchDirs, err := p.streamRewriteFsListResponse(w, resp.Body, dirPath, parentEncPath)
	if err != nil {
		log.Warnf("%s stream rewrite fs list failed: %v", internal.LogPrefix(ctx, internal.TagList), err)
		return
	}
	if parentEncPath != nil && len(prefetchDirs) > 0 {
		headers := r.Header.Clone()
		go p.prefetchEncryptedSubDirs(context.Background(), reqData, prefetchDirs, headers)
	}
}

// handleFsGet 处理获取文件信息
func (p *ProxyServer) handleFsGet(w http.ResponseWriter, r *http.Request) {
	p.handleFsGetOrLink(w, r, "/api/fs/get")
}

func (p *ProxyServer) handleFsLink(w http.ResponseWriter, r *http.Request) {
	p.handleFsGetOrLink(w, r, "/api/fs/link")
}

func (p *ProxyServer) handleFsGetOrLink(w http.ResponseWriter, r *http.Request, apiPath string) {
	ctx := r.Context()
	log.Infof("%s Proxy handling %s request", internal.LogPrefix(ctx, internal.TagProxy), apiPath)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var reqData map[string]string
	if err := json.Unmarshal(body, &reqData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	originalPath := reqData["path"]
	filePath := originalPath
	convertedPathForGet := false

	// 检查是否需要转换文件名
	encPath := p.findEncryptPath(filePath)
	if encPath != nil && encPath.EncName {
		if !p.isEncryptDirRoot(filePath) {
			fileName := path.Base(filePath)
			if fileName != "/" && fileName != "." {
				candidates := buildRealPathCandidates(encPath, originalPath)
				for _, candidate := range candidates {
					if candidate == originalPath {
						continue
					}
					filePath = candidate
					reqData["path"] = filePath
					body, _ = json.Marshal(reqData)
					convertedPathForGet = filePath != originalPath
					break
				}
			}
		}
	}

	// 转发请求到 Alist
	req, err := http.NewRequestWithContext(r.Context(), "POST", p.getAlistURL()+apiPath, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	respStatusCode := resp.StatusCode

	// 读取响应
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 检查是否需要修改响应
	if encPath != nil {
		var result map[string]interface{}
		if err := json.Unmarshal(respBody, &result); err == nil {
			fsGetFailed := func(httpStatus int, body map[string]interface{}) bool {
				if httpStatus == http.StatusBadRequest || httpStatus == http.StatusNotFound {
					return true
				}
				if code, ok := body["code"].(float64); ok {
					if int(code) == http.StatusBadRequest || int(code) == http.StatusNotFound {
						return true
					}
					if int(code) != 200 {
						if msg, ok := body["message"].(string); ok {
							lowerMsg := strings.ToLower(strings.TrimSpace(msg))
							if strings.Contains(lowerMsg, "not found") || strings.Contains(lowerMsg, "object not found") {
								return true
							}
						}
					}
				}
				data, ok := body["data"].(map[string]interface{})
				if !ok || data == nil {
					return true
				}
				rawURL, _ := data["raw_url"].(string)
				return strings.TrimSpace(rawURL) == ""
			}
			if convertedPathForGet {
				needsFallback := fsGetFailed(respStatusCode, result)

				tryFsGetPath := func(targetPath, stage string) bool {
					reqData["path"] = targetPath
					body2, _ := json.Marshal(reqData)
					req2, err2 := http.NewRequestWithContext(r.Context(), "POST", p.getAlistURL()+apiPath, bytes.NewReader(body2))
					if err2 != nil {
						return false
					}
					for key, values := range r.Header {
						if key != "Host" {
							for _, value := range values {
								req2.Header.Add(key, value)
							}
						}
					}
					resp2, err3 := p.httpClient.Do(req2)
					if err3 != nil {
						return false
					}
					defer resp2.Body.Close()
					bodyRetry, err4 := io.ReadAll(resp2.Body)
					if err4 != nil {
						return false
					}
					respBody = bodyRetry
					respStatusCode = resp2.StatusCode
					if err5 := json.Unmarshal(respBody, &result); err5 != nil {
						return false
					}
					msg, _ := result["message"].(string)
					data, _ := result["data"].(map[string]interface{})
					rawURL, _ := data["raw_url"].(string)
					code, _ := result["code"].(float64)
					failed := fsGetFailed(respStatusCode, result)
					p.debugf("filename", "%s fallback stage=%s to=%s from=%s http=%d code=%d failed=%v message=%q hasRawURL=%v",
						apiPath, stage, targetPath, filePath, respStatusCode, int(code), failed, msg, strings.TrimSpace(rawURL) != "")
					return !failed
				}

				if needsFallback {
					candidates := buildRealPathCandidates(encPath, originalPath)
					for i, candidate := range candidates {
						if candidate == filePath {
							continue
						}
						if tryFsGetPath(candidate, fmt.Sprintf("candidate-%d", i)) {
							needsFallback = false
							break
						}
					}
				}
			}
			if data, ok := result["data"].(map[string]interface{}); ok {
				rawURL, _ := data["raw_url"].(string)
				rawURL = rewriteLoopbackRawURLForRequest(r, rawURL)
				if rawURL != "" {
					data["raw_url"] = rawURL
				}
				size, _ := data["size"].(float64)
				ciphertextSize := int64(size)
				meta := LegacyContentMeta(EncryptionType(encPath.EncType), ciphertextSize)
				if rawURL != "" {
					meta = p.inspectEncryptedContentWithFallback(ctx, rawURL, r.Header, encPath, ciphertextSize, filePath)
					if meta.IsV2() && meta.PlainSize > 0 {
						size = float64(meta.PlainSize)
						data["size"] = size
					}
				}
				provider, _ := data["provider"].(string)
				sign, _ := data["sign"].(string)
				isDir, _ := data["is_dir"].(bool)
				driver := p.inferDriverFromPath(ctx, originalPath, r.Header)
				p.noteProviderCandidate(provider)
				p.noteDriverCandidate(driver)

				log.Infof("%s handleFsGet: path=%s, size=%v, rawURL=%s", internal.LogPrefix(ctx, internal.TagProxy), originalPath, size, rawURL)

				p.storeFileCache(originalPath, &FileInfo{
					Name:           path.Base(originalPath),
					Size:           int64(size),
					CiphertextSize: meta.TotalCiphertextSize(),
					ContentVersion: meta.Version,
					HeaderLen:      meta.HeaderLen,
					NonceField:     cloneNonceField(meta.NonceField),
					IsDir:          isDir,
					Path:           originalPath,
					RawURL:         rawURL,
					Sign:           sign,
				})

				// 如果开启了文件名加密，将加密名转换为显示名
				if encPath.EncName {
					if name, ok := data["name"].(string); ok {
						showName := convertShowNameByRule(encPath, name)
						data["name"] = showName
						normalizeDecryptedMediaFields(data, showName)
					}
				}

				// 创建重定向缓存（使用带 TTL 的缓存方法）
				key := generateRedirectKey()
				p.storeRedirectCache(key, &RedirectInfo{
					RedirectURL:    rawURL,
					PasswdInfo:     encPath,
					FileSize:       int64(size),
					CiphertextSize: meta.TotalCiphertextSize(),
					ContentVersion: meta.Version,
					HeaderLen:      meta.HeaderLen,
					NonceField:     cloneNonceField(meta.NonceField),
					OriginalURL:    originalPath,
					EncryptedPath:  filePath,
					Provider:       provider,
					Driver:         driver,
				})

				// 修改返回的 URL
				scheme := "http"
				host := r.Host
				data["raw_url"] = fmt.Sprintf("%s://%s/redirect/%s?decode=1&lastUrl=%s",
					scheme, host, key, url.QueryEscape(originalPath))

				// 修改 provider 以支持直接播放
				if provider, ok := data["provider"].(string); ok {
					if provider == "AliyundriveOpen" {
						data["provider"] = "Local"
					}
				}

				result["data"] = data
				respBody, _ = json.Marshal(result)
			}
		}
	}

	// 对所有 fs/get 与 fs/link 响应统一处理 loopback raw_url，避免局域网远程访问拿到 127.0.0.1/localhost。
	var finalResult map[string]interface{}
	if err := json.Unmarshal(respBody, &finalResult); err == nil {
		if data, ok := finalResult["data"].(map[string]interface{}); ok {
			if rawURL, ok := data["raw_url"].(string); ok {
				if rewritten := rewriteLoopbackRawURLForRequest(r, rawURL); rewritten != rawURL && rewritten != "" {
					data["raw_url"] = rewritten
					finalResult["data"] = data
					if updatedBody, marshalErr := json.Marshal(finalResult); marshalErr == nil {
						respBody = updatedBody
					}
				}
			}
		}
	}

	// 返回响应
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(respStatusCode)
	w.Write(respBody)
}

func (p *ProxyServer) handleProviderRoutingCandidates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.maybeRefreshProviderCatalog(r.Header)
		providers, providerLabels, sourceMasks, lastRefreshAt, nextRefreshAt, lastError := p.providerCatalogSnapshot()
		p.routingMu.RLock()
		drivers := make([]string, 0, len(p.seenDrivers))
		for k := range p.seenDrivers {
			drivers = append(drivers, k)
		}
		seenCount := len(p.seenProviders)
		catalogRefreshing := p.catalogRefreshing
		p.routingMu.RUnlock()
		sort.Strings(drivers)
		builtinCount := len(builtinDirectProviders) + len(builtinProxyProviders)
		providerCount := len(providers)
		stale := nextRefreshAt.IsZero() || time.Now().After(nextRefreshAt)
		sourceStats := map[string]int{
			"builtin": 0,
			"seen":    0,
			"driver":  0,
			"storage": 0,
			"remote":  0,
		}
		for _, mask := range sourceMasks {
			if mask&providerSourceBuiltin != 0 {
				sourceStats["builtin"]++
			}
			if mask&providerSourceSeen != 0 {
				sourceStats["seen"]++
			}
			if mask&providerSourceDriverNames != 0 {
				sourceStats["driver"]++
			}
			if mask&providerSourceStorage != 0 {
				sourceStats["storage"]++
			}
			if mask&providerSourceRemote != 0 {
				sourceStats["remote"]++
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"providers":       providers,
				"provider_labels": providerLabels,
				"drivers":         drivers,
				"meta": map[string]interface{}{
					"seen_count":    seenCount,
					"builtin_count": builtinCount,
					"catalog_total": providerCount,
					"catalog_last_refresh_at": func() string {
						if lastRefreshAt.IsZero() {
							return ""
						}
						return lastRefreshAt.Format(time.RFC3339)
					}(),
					"catalog_next_refresh_at": func() string {
						if nextRefreshAt.IsZero() {
							return ""
						}
						return nextRefreshAt.Format(time.RFC3339)
					}(),
					"catalog_stale":      stale,
					"catalog_refreshing": catalogRefreshing,
					"sources":            sourceStats,
					"degraded":           strings.TrimSpace(lastError) != "",
					"last_error":         lastError,
				},
			},
		})
		return
	case http.MethodPost:
		p.refreshProviderCatalogAsync(r.Header, true)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": map[string]interface{}{
				"accepted": true,
			},
		})
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (p *ProxyServer) handleProviderRoutingCandidatesRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.refreshProviderCatalogAsync(r.Header, true)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"accepted": true,
		},
	})
}

func (p *ProxyServer) handleFsRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dir, _ := reqData["dir"].(string)
	encPath := p.findEncryptPath(dir)
	if encPath == nil || !encPath.EncName {
		p.proxyFSJSON(w, r, "/api/fs/remove", body)
		return
	}
	originalNames := anyToStringSlice(reqData["names"])
	seen := make(map[string]bool, len(originalNames)*4)
	initialNames := make([]string, 0, len(originalNames)*4)
	for _, name := range originalNames {
		for _, candidate := range p.buildRemoveNameCandidates(encPath, dir, name) {
			if !seen[candidate] {
				initialNames = append(initialNames, candidate)
				seen[candidate] = true
			}
		}
	}
	if len(initialNames) == 0 {
		initialNames = originalNames
	}
	reqData["names"] = initialNames
	status, respBody, err := p.doFSRemoveRequest(r.Context(), r.Header, reqData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if !fsRemoveNotFound(status, respBody) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(respBody)
		return
	}

	// 如果批量删除包含 not found，按条目候选逐个重试，降低误判与兼容历史命名。
	var finalStatus = status
	finalBody := respBody
	for _, name := range originalNames {
		candidates := p.buildRemoveNameCandidates(encPath, dir, name)
		if len(candidates) == 0 {
			continue
		}
		succeeded := false
		for _, candidate := range candidates {
			retryReq := map[string]interface{}{
				"dir":   dir,
				"names": []string{candidate},
			}
			retryStatus, retryBody, retryErr := p.doFSRemoveRequest(r.Context(), r.Header, retryReq)
			if retryErr != nil {
				continue
			}
			finalStatus = retryStatus
			finalBody = retryBody
			if !fsRemoveNotFound(retryStatus, retryBody) {
				succeeded = true
				break
			}
		}
		if !succeeded {
			p.debugf("filename", "fs/remove fallback failed name=%s dir=%s", name, dir)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(finalStatus)
	_, _ = w.Write(finalBody)
}

func (p *ProxyServer) handleFsMove(w http.ResponseWriter, r *http.Request) {
	p.handleFsMoveCopy(w, r, "/api/fs/move")
}

func (p *ProxyServer) handleFsCopy(w http.ResponseWriter, r *http.Request) {
	p.handleFsMoveCopy(w, r, "/api/fs/copy")
}

func (p *ProxyServer) handleFsMoveCopy(w http.ResponseWriter, r *http.Request, apiPath string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	srcDir, _ := reqData["src_dir"].(string)
	encPath := p.findEncryptPath(srcDir)
	if encPath != nil && encPath.EncName {
		names := anyToStringSlice(reqData["names"])
		converted := make([]string, 0, len(names))
		for _, name := range names {
			if name == "" {
				continue
			}
			realName := convertRealNameByRule(encPath, name)
			if realName == "" {
				realName = name
			}
			converted = append(converted, realName)
		}
		reqData["names"] = converted
		body, _ = json.Marshal(reqData)
	}
	p.proxyFSJSON(w, r, apiPath, body)
}

func (p *ProxyServer) handleFsRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var reqData map[string]interface{}
	if err := json.Unmarshal(body, &reqData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	filePath, _ := reqData["path"].(string)
	name, _ := reqData["name"].(string)
	encPath := p.findEncryptPath(filePath)
	if encPath != nil && encPath.EncName {
		if cached, ok := p.loadFileCache(filePath); ok && !cached.IsDir {
			reqData["path"] = path.Join(path.Dir(filePath), convertRealNameByRule(encPath, filePath))
			reqData["name"] = convertRealNameByRule(encPath, name)
			body, _ = json.Marshal(reqData)
		}
	}
	p.proxyFSJSON(w, r, "/api/fs/rename", body)
}

func (p *ProxyServer) handleFsPutBack(w http.ResponseWriter, r *http.Request) {
	p.handleFsPutCommon(w, r, "/api/fs/put-back")
}

// handleFsPut 处理文件上传请求
func (p *ProxyServer) handleFsPut(w http.ResponseWriter, r *http.Request) {
	p.handleFsPutCommon(w, r, "/api/fs/put")
}

func (p *ProxyServer) handleFsPutCommon(w http.ResponseWriter, r *http.Request, apiPath string) {
	ctx := r.Context()
	log.Infof("%s Proxy handling fs put request: %s", internal.LogPrefix(ctx, internal.TagUpload), apiPath)
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	targetURL := p.getAlistURL() + apiPath
	var body io.Reader = r.Body
	var uploadMeta ContentMeta

	// 获取上传路径
	filePath := r.Header.Get("File-Path")
	if filePath == "" {
		// 尝试从 URL 参数获取 (有些客户端可能通过 URL 传参)
		filePath = r.URL.Query().Get("path")
	}

	// URL 解码
	decodedPath, err := url.PathUnescape(filePath)
	if err == nil {
		filePath = decodedPath
	}

	log.Infof("%s Uploading file to path: %s", internal.LogPrefix(ctx, internal.TagUpload), filePath)

	// 检查是否需要加密
	encPath := p.findEncryptPath(filePath)

	// 记录原始文件名用于缓存
	originalFilePath := filePath

	// 如果开启了文件名加密，转换文件名（与 alist-encrypt 一致）
	if encPath != nil && encPath.EncName {
		fileName := path.Base(filePath)
		if fileName != "/" && fileName != "." {
			newRealName := convertRealNameByRule(encPath, filePath)
			newFilePath := path.Join(path.Dir(filePath), newRealName)
			p.debugf("encrypt", "%s Encrypting filename: %s -> %s", internal.LogPrefix(ctx, internal.TagEncrypt), fileName, newRealName)

			// 更新 File-Path header
			r.Header.Set("File-Path", url.PathEscape(newFilePath))

			// 更新 targetURL
			targetURL = p.getAlistURL() + apiPath
		}
	}

	if encPath != nil {
		p.debugf("encrypt", "%s Encrypting upload for path: %s", internal.LogPrefix(ctx, internal.TagEncrypt), filePath)
		contentLength := r.ContentLength
		if contentLength <= 0 {
			contentLength = 0
		}
		startOffset := parseUploadStartOffset(r.Header.Get("Content-Range"))
		if startOffset > 0 {
			uploadMeta, _ = p.getUploadMeta(filePath)
			if !uploadMeta.IsV2() {
				uploadMeta = p.inspectEncryptedContent(ctx, targetURL, r.Header, encPath, contentLength)
			}
		}
		if startOffset > 0 && uploadMeta.IsV2() {
			encryptor, err := NewCipherV2(EncryptionType(encPath.EncType), encPath.Password, uploadMeta.PlainSize, uploadMeta.NonceField)
			if err != nil {
				log.Errorf("%s Failed to create v2 encryptor: %v", internal.LogPrefix(ctx, internal.TagEncrypt), err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if err := encryptor.SetPosition(startOffset); err != nil {
				log.Errorf("%s Failed to set v2 upload offset: %v", internal.LogPrefix(ctx, internal.TagEncrypt), err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			body = NewEncryptReader(r.Body, encryptor)
		} else if startOffset == 0 && contentLength > 0 {
			contentEnc, err := NewLatestContentEncryptor(encPath.Password, string(encPath.EncType), contentLength)
			if err != nil {
				log.Errorf("%s Failed to create v2 content encryptor: %v", internal.LogPrefix(ctx, internal.TagEncrypt), err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			body, err = contentEnc.EncryptReader(r.Body, 0)
			if err != nil {
				log.Errorf("%s Failed to create v2 encrypt reader: %v", internal.LogPrefix(ctx, internal.TagEncrypt), err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			uploadMeta = contentEnc.Meta
			p.putUploadMeta(filePath, uploadMeta)
		} else {
			encryptor, err := NewFlowEncryptor(encPath.Password, encPath.EncType, contentLength)
			if err != nil {
				log.Errorf("%s Failed to create encryptor: %v", internal.LogPrefix(ctx, internal.TagEncrypt), err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if startOffset > 0 {
				if err := encryptor.SetPosition(startOffset); err != nil {
					log.Errorf("%s Failed to set upload offset: %v", internal.LogPrefix(ctx, internal.TagEncrypt), err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}
			body = NewEncryptReader(r.Body, encryptor)
			uploadMeta = LegacyContentMeta(EncryptionType(encPath.EncType), contentLength)
		}

		// 缓存文件信息（与 alist-encrypt 一致：上传前缓存，便于 rclone 的 PROPFIND）
		p.storeFileCache(originalFilePath, &FileInfo{
			Name:  path.Base(originalFilePath),
			Size:  contentLength,
			IsDir: false,
			Path:  originalFilePath,
		})
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 复制请求头
	for key, values := range r.Header {
		if key != "Host" {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}
	if encPath != nil && uploadMeta.IsV2() {
		startOffset := parseUploadStartOffset(r.Header.Get("Content-Range"))
		rewriteUploadHeadersForV2(req, uploadMeta, startOffset, r.Header.Get("Content-Range"))
	}

	uploadClient := p.streamClient
	if uploadClient == nil {
		uploadClient = p.httpClient
	}
	p.debugf("upload", "%s Using stream upload client for %s", internal.LogPrefix(ctx, internal.TagUpload), filePath)
	resp, err := uploadClient.Do(req)
	if err != nil {
		log.Errorf("%s FsPut request failed: %v", internal.LogPrefix(ctx, internal.TagUpload), err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	copyWithBuffer(w, resp.Body)
}
