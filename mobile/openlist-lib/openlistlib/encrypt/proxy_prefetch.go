package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"
)

// 流式传输优化常量

// prefetchRecentMaxEntries bounds directory cooldown bookkeeping. Entries only
// live for encryptedPrefetchCooldown, so this limit primarily protects bursts
// containing many unique paths.
const prefetchRecentMaxEntries = 2048

type prefetchRecentEvictionCandidate struct {
	key       string
	scheduled time.Time
}

// trimPrefetchRecentLocked removes malformed/expired cooldown records before
// evicting the oldest live records. prefetchRecentMu must be held by the caller.
func (p *ProxyServer) trimPrefetchRecentLocked(now time.Time, maxEntries int) {
	if p == nil || p.prefetchRecent == nil {
		return
	}
	if maxEntries < 0 {
		maxEntries = 0
	}

	// Normal full-cache insertions need one eviction, so select that entry in a
	// single O(n) pass. Allocate/sort a candidate list only to repair a cache
	// inherited in a substantially over-capacity state.
	collectAll := p.prefetchRecent.Len()-maxEntries > 1
	var candidates []prefetchRecentEvictionCandidate
	if collectAll {
		candidates = make([]prefetchRecentEvictionCandidate, 0, p.prefetchRecent.Len())
	}
	expiredKeys := make([]string, 0)
	oldest := prefetchRecentEvictionCandidate{}
	haveOldest := false
	for i := range p.prefetchRecent.shards {
		shard := &p.prefetchRecent.shards[i]
		shard.mu.RLock()
		for key, value := range shard.m {
			scheduled, ok := value.(time.Time)
			if !ok || !now.Before(scheduled.Add(encryptedPrefetchCooldown)) {
				expiredKeys = append(expiredKeys, key)
				continue
			}
			candidate := prefetchRecentEvictionCandidate{key: key, scheduled: scheduled}
			if !haveOldest || candidate.scheduled.Before(oldest.scheduled) ||
				(candidate.scheduled.Equal(oldest.scheduled) && candidate.key < oldest.key) {
				oldest = candidate
				haveOldest = true
			}
			if collectAll {
				candidates = append(candidates, candidate)
			}
		}
		shard.mu.RUnlock()
	}
	for _, key := range expiredKeys {
		p.prefetchRecent.Delete(key)
	}

	if p.prefetchRecent.Len() <= maxEntries {
		return
	}
	if p.prefetchRecent.Len()-maxEntries == 1 && haveOldest {
		p.prefetchRecent.Delete(oldest.key)
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].scheduled.Equal(candidates[j].scheduled) {
			return candidates[i].key < candidates[j].key
		}
		return candidates[i].scheduled.Before(candidates[j].scheduled)
	})
	for _, candidate := range candidates {
		if p.prefetchRecent.Len() <= maxEntries {
			break
		}
		p.prefetchRecent.Delete(candidate.key)
	}
}

func (p *ProxyServer) shouldSchedulePrefetch(dirPath string) bool {
	if p == nil || dirPath == "" {
		return false
	}
	p.ensureRuntimeCaches()
	now := time.Now()
	key := normalizeCacheKey(dirPath)
	p.prefetchRecentMu.Lock()
	defer p.prefetchRecentMu.Unlock()

	if v, ok := p.prefetchRecent.Get(key); ok {
		if ts, ok := v.(time.Time); ok && now.Before(ts.Add(encryptedPrefetchCooldown)) {
			return false
		}
		p.prefetchRecent.Delete(key)
	}
	if p.prefetchRecent.Len() >= prefetchRecentMaxEntries {
		p.trimPrefetchRecentLocked(now, prefetchRecentMaxEntries-1)
	}
	p.prefetchRecent.Set(key, now)
	return true
}

func (p *ProxyServer) prefetchEncryptedSubDirs(parentCtx context.Context, reqData map[string]interface{}, dirs []string, headers http.Header) {
	if p == nil || len(dirs) == 0 {
		return
	}
	if p.shouldFastFailUpstream() {
		return
	}

	uniq := make([]string, 0, len(dirs))
	seen := make(map[string]struct{}, len(dirs))
	for _, d := range dirs {
		if d == "" {
			continue
		}
		nd := normalizeCacheKey(d)
		if _, ok := seen[nd]; ok {
			continue
		}
		if !p.shouldSchedulePrefetch(nd) {
			continue
		}
		seen[nd] = struct{}{}
		uniq = append(uniq, nd)
		if len(uniq) >= encryptedPrefetchMaxDirs {
			break
		}
	}
	if len(uniq) == 0 {
		return
	}

	sem := make(chan struct{}, encryptedPrefetchConcurrency)
	for _, dirPath := range uniq {
		sem <- struct{}{}
		go func(targetPath string) {
			defer func() { <-sem }()

			payload := make(map[string]interface{}, len(reqData)+1)
			for k, v := range reqData {
				payload[k] = v
			}
			payload["path"] = targetPath

			body, err := json.Marshal(payload)
			if err != nil {
				return
			}

			runtime := p.runtimeSnapshot()
			if runtime.config == nil || runtime.httpClient == nil {
				return
			}
			ctx, cancel := context.WithTimeout(parentCtx, time.Duration(clampSeconds(runtime.config.ProbeTimeoutSeconds, 5, 1, 30))*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, getAlistURLFromConfig(runtime.config)+"/api/fs/list", bytes.NewReader(body))
			if err != nil {
				return
			}
			for key, values := range headers {
				if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
					continue
				}
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := runtime.httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return
			}

			var result map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				return
			}
			code, _ := result["code"].(float64)
			if code != 200 {
				return
			}
			data, _ := result["data"].(map[string]interface{})
			content, _ := data["content"].([]interface{})
			for _, item := range content {
				fileMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				name, _ := fileMap["name"].(string)
				size, _ := fileMap["size"].(float64)
				isDir, _ := fileMap["is_dir"].(bool)
				filePath := path.Join(targetPath, name)
				if apiPath, ok := fileMap["path"].(string); ok && apiPath != "" {
					filePath = apiPath
				}
				p.storeFileCache(filePath, &FileInfo{
					Name:  name,
					Size:  int64(size),
					IsDir: isDir,
					Path:  filePath,
				})
			}
		}(dirPath)
	}
}
