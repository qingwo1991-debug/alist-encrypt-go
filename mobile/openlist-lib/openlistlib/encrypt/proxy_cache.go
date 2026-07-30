package encrypt

import (
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

// redirectCacheMaxEntries bounds short-lived signed redirect URLs. A few
// thousand entries are enough to absorb bursts without allowing an attacker or
// a long-running client to grow the process indefinitely.
const redirectCacheMaxEntries = 4096

const (
	rawURLFailureCooldown   = 30 * time.Second
	rawURLFailureMaxEntries = 512
)

// CachedFileInfo 带过期时间的文件信息缓存
type CachedFileInfo struct {
	Info     *FileInfo
	ExpireAt time.Time
}

// CachedRedirectInfo 带过期时间的重定向信息缓存
type CachedRedirectInfo struct {
	Info     *RedirectInfo
	ExpireAt time.Time
}

// startCacheCleanup 启动定期缓存清理
func (p *ProxyServer) startCacheCleanup() {
	p.cleanupTicker = time.NewTicker(2 * time.Minute)
	go func() {
		defer recoverBackgroundTask("cache_cleanup")
		for {
			select {
			case <-p.cleanupTicker.C:
				p.cleanupExpiredCache()
			case <-p.cleanupDone:
				return
			}
		}
	}()
}

// stopCacheCleanup 停止缓存清理
func (p *ProxyServer) stopCacheCleanup() {
	if p.cleanupTicker != nil {
		p.cleanupTicker.Stop()
	}
	if p.cleanupDone != nil {
		close(p.cleanupDone)
	}
}

func (p *ProxyServer) redirectCacheTTL() time.Duration {
	if p == nil || p.config == nil || p.config.RedirectCacheTTLMinutes <= 0 {
		return redirectCacheTTL
	}
	return time.Duration(p.config.RedirectCacheTTLMinutes) * time.Minute
}

// cleanupExpiredCache 清理过期的缓存条目
func (p *ProxyServer) cleanupExpiredCache() {
	p.ensureRuntimeCaches()
	now := time.Now()
	var deletedCount int64

	// 清理文件缓存
	p.fileCache.Range(func(key string, value interface{}) bool {
		if cached, ok := value.(*CachedFileInfo); ok {
			if now.After(cached.ExpireAt) {
				p.fileCache.Delete(key)
				deletedCount++
			}
		}
		return true
	})

	// 清理重定向缓存，并修复任何由旧版本遗留的超限状态。
	p.redirectCacheMu.Lock()
	p.trimRedirectCacheLocked(now, redirectCacheMaxEntries)
	p.redirectCacheMu.Unlock()

	// 预热记录的有效期就是冷却窗口；过期后没有保留价值。
	p.prefetchRecentMu.Lock()
	p.trimPrefetchRecentLocked(now, prefetchRecentMaxEntries)
	p.prefetchRecentMu.Unlock()

	if deletedCount > 0 {
		log.Debugf("[%s] Cache cleanup: removed %d expired file entries", internal.TagCache, deletedCount)
	}
	p.maybeRefreshProviderCatalog(nil)
}

type redirectCacheEvictionCandidate struct {
	key      string
	expireAt time.Time
}

// trimRedirectCacheLocked drops expired/malformed entries first, then removes
// entries with the earliest expiration until maxEntries is satisfied.
// redirectCacheMu must be held by the caller.
func (p *ProxyServer) trimRedirectCacheLocked(now time.Time, maxEntries int) {
	if p == nil || p.redirectCache == nil {
		return
	}
	if maxEntries < 0 {
		maxEntries = 0
	}

	// The steady-state insertion path can only exceed its target by one. Keep
	// that path allocation-free and O(n); collect all candidates only when
	// repairing a cache left over-capacity by an older build.
	collectAll := p.redirectCache.Len()-maxEntries > 1
	var candidates []redirectCacheEvictionCandidate
	if collectAll {
		candidates = make([]redirectCacheEvictionCandidate, 0, p.redirectCache.Len())
	}
	expiredKeys := make([]string, 0)
	oldest := redirectCacheEvictionCandidate{}
	haveOldest := false
	for i := range p.redirectCache.shards {
		shard := &p.redirectCache.shards[i]
		shard.mu.RLock()
		for key, value := range shard.m {
			cached, ok := value.(*CachedRedirectInfo)
			if !ok || cached == nil || !now.Before(cached.ExpireAt) {
				expiredKeys = append(expiredKeys, key)
				continue
			}
			candidate := redirectCacheEvictionCandidate{key: key, expireAt: cached.ExpireAt}
			if !haveOldest || candidate.expireAt.Before(oldest.expireAt) ||
				(candidate.expireAt.Equal(oldest.expireAt) && candidate.key < oldest.key) {
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
		p.redirectCache.Delete(key)
	}

	if p.redirectCache.Len() <= maxEntries {
		return
	}
	if p.redirectCache.Len()-maxEntries == 1 && haveOldest {
		p.redirectCache.Delete(oldest.key)
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].expireAt.Equal(candidates[j].expireAt) {
			return candidates[i].key < candidates[j].key
		}
		return candidates[i].expireAt.Before(candidates[j].expireAt)
	})
	for _, candidate := range candidates {
		if p.redirectCache.Len() <= maxEntries {
			break
		}
		p.redirectCache.Delete(candidate.key)
	}
}

// normalizeCacheKey 统一缓存键（对齐 alist-encrypt：decodeURIComponent）
func normalizeCacheKey(p string) string {
	if decoded, err := url.PathUnescape(p); err == nil {
		return decoded
	}
	return p
}

// getFileCacheTTL 获取文件缓存 TTL（支持配置化）
func (p *ProxyServer) getFileCacheTTL() time.Duration {
	if p.config != nil && p.config.FileCacheTTL > 0 {
		return time.Duration(p.config.FileCacheTTL) * time.Minute
	}
	return fileCacheTTL // 默认 10 分钟
}

func (p *ProxyServer) rawURLFailureBlocked(rawURL string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if p == nil || rawURL == "" {
		return false
	}
	p.ensureRuntimeCaches()
	now := time.Now()
	p.rawURLNegativeMu.Lock()
	defer p.rawURLNegativeMu.Unlock()
	expireAt, ok := p.rawURLNegativeCache[rawURL]
	if !ok {
		return false
	}
	if !now.Before(expireAt) {
		delete(p.rawURLNegativeCache, rawURL)
		return false
	}
	return true
}

func (p *ProxyServer) markRawURLFailure(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if p == nil || rawURL == "" {
		return
	}
	p.ensureRuntimeCaches()
	now := time.Now()
	p.rawURLNegativeMu.Lock()
	defer p.rawURLNegativeMu.Unlock()
	if len(p.rawURLNegativeCache) >= rawURLFailureMaxEntries {
		oldestURL := ""
		var oldestExpiry time.Time
		for candidate, expireAt := range p.rawURLNegativeCache {
			if !now.Before(expireAt) {
				delete(p.rawURLNegativeCache, candidate)
				continue
			}
			if oldestURL == "" || expireAt.Before(oldestExpiry) {
				oldestURL = candidate
				oldestExpiry = expireAt
			}
		}
		if len(p.rawURLNegativeCache) >= rawURLFailureMaxEntries && oldestURL != "" {
			delete(p.rawURLNegativeCache, oldestURL)
		}
	}
	p.rawURLNegativeCache[rawURL] = now.Add(rawURLFailureCooldown)
}

func (p *ProxyServer) clearRawURLFailure(rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if p == nil || rawURL == "" {
		return
	}
	p.ensureRuntimeCaches()
	p.rawURLNegativeMu.Lock()
	delete(p.rawURLNegativeCache, rawURL)
	p.rawURLNegativeMu.Unlock()
}

// storeFileCache 存储文件信息到缓存（带 TTL）
func (p *ProxyServer) storeFileCache(path string, info *FileInfo) {
	p.ensureRuntimeCaches()
	if info == nil {
		return
	}
	key := normalizeCacheKey(path)
	if existing, ok := p.loadFileCache(path); ok && existing != nil {
		incomingRawURL := strings.TrimSpace(info.RawURL)
		existingRawURL := strings.TrimSpace(existing.RawURL)
		rawURLChanged := incomingRawURL != "" && existingRawURL != "" && incomingRawURL != existingRawURL
		incomingMetaTrusted := (info.ContentVersion == ContentVersionV1 && info.Size > 0) ||
			(info.ContentVersion == ContentVersionV2 &&
				info.Size > 0 &&
				info.CiphertextSize > 0 &&
				info.HeaderLen > 0 &&
				len(info.NonceField) == 16)
		if rawURLChanged && !incomingMetaTrusted {
			// A different signed URL can also represent a replaced object at the
			// same display path. Do not bind the previous V2 nonce/size to the
			// new identity; the next playback performs a cheap 32-byte probe.
			info.Size = 0
			info.CiphertextSize = 0
			info.ContentVersion = 0
			info.HeaderLen = 0
			info.NonceField = nil
			p.sizeMapMu.Lock()
			if p.sizeMap != nil {
				delete(p.sizeMap, key)
				p.sizeMapDirty = true
			}
			p.sizeMapMu.Unlock()
		}
		if info.Name == "" {
			info.Name = existing.Name
		}
		if !rawURLChanged && (info.Size <= 0 || (info.ContentVersion <= 0 && existing.ContentVersion == ContentVersionV2)) {
			info.Size = existing.Size
		}
		if !rawURLChanged && info.CiphertextSize <= 0 && (info.ContentVersion > 0 || existing.ContentVersion == ContentVersionV2) {
			info.CiphertextSize = existing.CiphertextSize
		}
		if !rawURLChanged && info.ContentVersion <= 0 && existing.ContentVersion == ContentVersionV2 {
			info.ContentVersion = existing.ContentVersion
		}
		if !rawURLChanged && info.HeaderLen <= 0 && (info.ContentVersion > 0 || existing.ContentVersion == ContentVersionV2) {
			info.HeaderLen = existing.HeaderLen
		}
		if !rawURLChanged && len(info.NonceField) == 0 && len(existing.NonceField) > 0 && (info.ContentVersion > 0 || existing.ContentVersion == ContentVersionV2) {
			info.NonceField = cloneNonceField(existing.NonceField)
		}
		if !info.IsDir && existing.IsDir {
			info.IsDir = false
		}
		if strings.TrimSpace(info.Path) == "" {
			info.Path = existing.Path
		}
		if strings.TrimSpace(info.RawURL) == "" {
			info.RawURL = existing.RawURL
		}
	}
	entry := &CachedFileInfo{
		Info:     info,
		ExpireAt: time.Now().Add(p.getFileCacheTTL()),
	}
	p.fileCache.Set(key, entry)
	// 兼容：也保存原始 key
	if key != path {
		p.fileCache.Set(path, entry)
	}
	if info != nil && !info.IsDir && info.Size > 0 {
		p.updateSizeMap(key, info.Size)
		if key != path {
			p.updateSizeMap(path, info.Size)
		}
	}
}

// loadFileCache 从缓存加载文件信息（检查 TTL）
func (p *ProxyServer) loadFileCache(filePath string) (*FileInfo, bool) {
	p.ensureRuntimeCaches()
	key := normalizeCacheKey(filePath)
	if value, ok := p.fileCache.Get(key); ok {
		if cached, ok := value.(*CachedFileInfo); ok {
			if time.Now().Before(cached.ExpireAt) {
				return cached.Info, true
			}
			// 过期了，删除
			p.fileCache.Delete(key)
		}
	}
	// 回退尝试原始 key
	if key != filePath {
		if value, ok := p.fileCache.Get(filePath); ok {
			if cached, ok := value.(*CachedFileInfo); ok {
				if time.Now().Before(cached.ExpireAt) {
					return cached.Info, true
				}
				p.fileCache.Delete(filePath)
			}
		}
	}
	if entry, ok := p.getSizeMap(key); ok {
		info := &FileInfo{
			Name:  path.Base(filePath),
			Size:  entry.Size,
			IsDir: false,
			Path:  filePath,
		}
		return info, true
	}
	if p != nil && p.localStore != nil && p.config != nil {
		candidates := []string{filePath}
		if strings.HasPrefix(filePath, "/dav/") {
			candidates = append(candidates, strings.TrimPrefix(filePath, "/dav"))
		}
		for _, candidate := range candidates {
			if meta, ok := p.lookupLocalFileMeta(p.getAlistURL(), candidate); ok && meta != nil {
				rawURL := ""
				if meta.UpstreamFetchedAt > 0 && time.Since(time.Unix(meta.UpstreamFetchedAt, 0)) <= p.getFileCacheTTL() {
					rawURL = strings.TrimSpace(meta.RawURL)
				}
				info := &FileInfo{
					Name:           meta.Name,
					Size:           meta.Size,
					CiphertextSize: meta.CiphertextSize,
					ContentVersion: meta.ContentVersion,
					HeaderLen:      meta.HeaderLen,
					NonceField:     cloneNonceField(meta.NonceField),
					IsDir:          false,
					Path:           candidate,
					RawURL:         rawURL,
					Sign:           strings.TrimSpace(meta.Sign),
				}
				if info.Name == "" {
					info.Name = path.Base(candidate)
				}
				p.storeFileCache(candidate, info)
				if candidate != filePath {
					p.storeFileCache(filePath, &FileInfo{
						Name:           info.Name,
						Size:           info.Size,
						CiphertextSize: info.CiphertextSize,
						ContentVersion: info.ContentVersion,
						HeaderLen:      info.HeaderLen,
						NonceField:     cloneNonceField(info.NonceField),
						IsDir:          info.IsDir,
						Path:           filePath,
						RawURL:         info.RawURL,
					})
				}
				return info, true
			}
		}
	}
	return nil, false
}

// storeRedirectCache 存储重定向信息到缓存（带 TTL）
func (p *ProxyServer) storeRedirectCache(key string, info *RedirectInfo) {
	p.ensureRuntimeCaches()
	now := time.Now()
	entry := &CachedRedirectInfo{
		Info:     info,
		ExpireAt: now.Add(p.redirectCacheTTL()),
	}

	p.redirectCacheMu.Lock()
	if p.redirectCache.Len() >= redirectCacheMaxEntries {
		_, replacing := p.redirectCache.Get(key)
		target := redirectCacheMaxEntries
		if !replacing {
			target--
		}
		p.trimRedirectCacheLocked(now, target)
		// The key may itself have been expired and removed while trimming.
		if _, stillPresent := p.redirectCache.Get(key); !stillPresent && p.redirectCache.Len() >= redirectCacheMaxEntries {
			p.trimRedirectCacheLocked(now, redirectCacheMaxEntries-1)
		}
	}
	p.redirectCache.Set(key, entry)
	p.redirectCacheMu.Unlock()
	if info != nil {
		p.debugf("retry", "store redirect key=%s ttl=%s url=%s", key, p.redirectCacheTTL().String(), p.sanitizeURLForDebug(info.RedirectURL))
	}
}

// loadRedirectCache 从缓存加载重定向信息（检查 TTL）
func (p *ProxyServer) loadRedirectCache(key string) (*RedirectInfo, bool) {
	p.ensureRuntimeCaches()
	if value, ok := p.redirectCache.Get(key); ok {
		if cached, ok := value.(*CachedRedirectInfo); ok {
			if time.Now().Before(cached.ExpireAt) {
				return cached.Info, true
			}
			// 过期了，删除
			p.redirectCache.Delete(key)
		}
	}
	return nil, false
}
