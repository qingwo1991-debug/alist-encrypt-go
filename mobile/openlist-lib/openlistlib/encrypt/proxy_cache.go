package encrypt

import (
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

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

	// 清理重定向缓存
	p.redirectCache.Range(func(key string, value interface{}) bool {
		if cached, ok := value.(*CachedRedirectInfo); ok {
			if now.After(cached.ExpireAt) {
				p.redirectCache.Delete(key)
			}
		}
		return true
	})

	if deletedCount > 0 {
		log.Debugf("[%s] Cache cleanup: removed %d expired file entries", internal.TagCache, deletedCount)
	}
	p.maybeRefreshProviderCatalog(nil)
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

// storeFileCache 存储文件信息到缓存（带 TTL）
func (p *ProxyServer) storeFileCache(path string, info *FileInfo) {
	p.ensureRuntimeCaches()
	if info == nil {
		return
	}
	key := normalizeCacheKey(path)
	if existing, ok := p.loadFileCache(path); ok && existing != nil {
		if info.Name == "" {
			info.Name = existing.Name
		}
		if info.Size <= 0 {
			info.Size = existing.Size
		}
		if info.CiphertextSize <= 0 {
			info.CiphertextSize = existing.CiphertextSize
		}
		if info.ContentVersion <= 0 {
			info.ContentVersion = existing.ContentVersion
		}
		if info.HeaderLen <= 0 {
			info.HeaderLen = existing.HeaderLen
		}
		if len(info.NonceField) == 0 && len(existing.NonceField) > 0 {
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
	p.redirectCache.Set(key, &CachedRedirectInfo{
		Info:     info,
		ExpireAt: time.Now().Add(p.redirectCacheTTL()),
	})
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
