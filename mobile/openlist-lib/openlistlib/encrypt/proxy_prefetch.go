package encrypt

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"time"
)

// 流式传输优化常量

func (p *ProxyServer) shouldSchedulePrefetch(dirPath string) bool {
	if p == nil || dirPath == "" {
		return false
	}
	p.ensureRuntimeCaches()
	now := time.Now()
	key := normalizeCacheKey(dirPath)
	if v, ok := p.prefetchRecent.Get(key); ok {
		if ts, ok := v.(time.Time); ok && now.Sub(ts) < encryptedPrefetchCooldown {
			return false
		}
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

			ctx, cancel := context.WithTimeout(parentCtx, p.probeTimeout())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.getAlistURL()+"/api/fs/list", bytes.NewReader(body))
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

			resp, err := p.httpClient.Do(req)
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
