package encrypt

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

func (p *ProxyServer) initLocalStore() {
	if p == nil || p.config == nil || p.config.ConfigPath == "" {
		return
	}
	baseDir := filepath.Dir(p.config.ConfigPath)
	store, err := newLocalStore(baseDir)
	if err != nil {
		log.Warnf("[%s] Local store init failed: %v", internal.TagCache, err)
		return
	}
	p.localStore = store
	if p.localStore != nil {
		sizeRetention := time.Duration(defaultLocalSizeRetentionDays) * 24 * time.Hour
		if p.config.LocalSizeRetentionDays > 0 {
			sizeRetention = time.Duration(p.config.LocalSizeRetentionDays) * 24 * time.Hour
		}
		strategyRetention := time.Duration(defaultLocalStrategyRetentionDays) * 24 * time.Hour
		if p.config.LocalStrategyRetentionDays > 0 {
			strategyRetention = time.Duration(p.config.LocalStrategyRetentionDays) * 24 * time.Hour
		}
		if err := p.localStore.Cleanup(sizeRetention, strategyRetention); err != nil {
			log.Warnf("[%s] Local store cleanup failed: %v", internal.TagCache, err)
		}
	}
}

func (p *ProxyServer) closeLocalStore() {
	if p == nil || p.localStore == nil {
		return
	}
	if err := p.localStore.Close(); err != nil {
		log.Warnf("[%s] Local store close failed: %v", internal.TagCache, err)
	}
	p.localStore = nil
}

func (p *ProxyServer) localKeyFromURLs(providerURL, originalURL string) (string, string, string, bool) {
	providerHost, originalPath, ok := parseProviderAndPath(providerURL, originalURL)
	if !ok {
		return "", "", "", false
	}
	key := buildLocalKey(providerHost, originalPath)
	if key == "" {
		return "", "", "", false
	}
	return key, providerHost, originalPath, true
}

func (p *ProxyServer) lookupLocalSize(providerURL, originalURL string) (int64, bool) {
	if p == nil || p.localStore == nil {
		return 0, false
	}
	key, _, _, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return 0, false
	}
	return p.localStore.GetSize(key)
}

func (p *ProxyServer) lookupLocalFileMeta(providerURL, originalURL string) (*LocalSizeRecord, bool) {
	if p == nil || p.localStore == nil {
		return nil, false
	}
	key, _, _, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return nil, false
	}
	return p.localStore.GetFileMeta(key)
}

func (p *ProxyServer) lookupLocalStrategy(providerURL, originalURL string) (StreamStrategy, bool) {
	if p == nil || p.localStore == nil {
		return "", false
	}
	key, _, _, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return "", false
	}
	networkType := string(GetNetworkState())
	return p.localStore.GetStrategy(key, networkType)
}

func (p *ProxyServer) recordLocalObservation(providerURL, originalURL string, size int64, statusCode int, contentType string, strategy StreamStrategy) {
	if p == nil || p.localStore == nil {
		return
	}
	if !isValidMediaResponse(statusCode, contentType, size) {
		return
	}
	key, providerHost, originalPath, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return
	}
	now := time.Now()
	p.localStore.AddSize(key, providerHost, originalPath, size, now)
	if strategy != "" {
		networkType := string(GetNetworkState())
		p.localStore.AddStrategy(key, providerHost, originalPath, networkType, strategy, now)
	}
}

// recordPlaybackStats 记录一次真实播放（有字节写出）到本地统计。
// displayPath 为明文展示路径；provider 为归一化 provider host。
func (p *ProxyServer) recordPlaybackStats(displayPath, provider string, bytesServed, totalBytes int64, completed bool, contentType string) {
	if p == nil || p.localStore == nil || bytesServed <= 0 {
		return
	}
	if strings.TrimSpace(displayPath) == "" {
		displayPath = "(unknown)"
	}
	if err := p.localStore.AppendPlayback(PlaybackStatsRecord{
		Path:         displayPath,
		Provider:     provider,
		BytesServed:  bytesServed,
		TotalBytes:   totalBytes,
		DurationSecs: 0,
		PlayedAt:     time.Now().Unix(),
		Completed:    completed,
		ContentType:  contentType,
	}); err != nil {
		log.Debugf("[%s] failed to record playback stats: %v", internal.TagCache, err)
	}
}

// ListPlaybackStats 返回本地播放统计（供 gomobile 导出）。
func (p *ProxyServer) ListPlaybackStats(limit int) ([]PlaybackStatsRecord, error) {
	if p == nil || p.localStore == nil {
		return nil, nil
	}
	return p.localStore.ListPlaybackStats(limit)
}

// ListDeletionStats 返回本地删除统计（供 gomobile 导出）。
func (p *ProxyServer) ListDeletionStats(limit int) ([]DeletionStatsRecord, error) {
	if p == nil || p.localStore == nil {
		return nil, nil
	}
	return p.localStore.ListDeletionStats(limit)
}

// displayPathFromPlaybackRequest 从播放请求中提取明文展示路径。
// 优先用 /redirect 的 lastUrl 查询参数（URL 解码后），回退到 info.OriginalURL 的路径部分。
func displayPathFromPlaybackRequest(r *http.Request, info *RedirectInfo) string {
	if r != nil && r.URL != nil {
		if lastURL := r.URL.Query().Get("lastUrl"); lastURL != "" {
			if decoded, err := url.QueryUnescape(lastURL); err == nil && strings.TrimSpace(decoded) != "" {
				return decoded
			}
		}
	}
	if info != nil {
		if p := strings.TrimSpace(info.OriginalURL); p != "" {
			if u, err := url.Parse(p); err == nil && u.Path != "" {
				return u.Path
			}
			return p
		}
		if p := strings.TrimSpace(info.EncryptedPath); p != "" {
			return p
		}
	}
	return ""
}

// recordDeletionStats 记录一次文件删除到本地统计。
func (p *ProxyServer) recordDeletionStats(displayPath string) {
	if p == nil || p.localStore == nil || strings.TrimSpace(displayPath) == "" {
		return
	}
	if err := p.localStore.AppendDeletion(displayPath); err != nil {
		log.Debugf("[%s] failed to record deletion stats: %v", internal.TagCache, err)
	}
}
