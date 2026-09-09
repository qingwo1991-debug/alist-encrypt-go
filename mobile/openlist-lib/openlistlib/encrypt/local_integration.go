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

// recordLocalV2Meta 把一次真实 INSPECT 的 V2 加密元数据持久化到本地 SQLite。
// 之后同一文件（含 App 重启后）播放时可直接复用，跳过对上游的重复探测。
// key 沿用 recordLocalObservation 的同一套（providerURL=upstream, originalURL=display path），
// 保证 inspect 结果与 size/strategy 观察共用一条 local_media_size 记录。
func (p *ProxyServer) recordLocalV2Meta(providerURL, originalURL string, meta ContentMeta) {
	if p == nil || p.localStore == nil {
		return
	}
	if meta.Version <= 0 || meta.PlainSize <= 0 {
		return
	}
	key, providerHost, originalPath, ok := p.localKeyFromURLs(providerURL, originalURL)
	if !ok {
		return
	}
	// 规范化 ciphertext_size：有效密文总长 = 明文 + 头。若探测回给的
	// CiphertextSize 不合理（< 明文），按结构推导，保证与播放时的 fileSize
	// 具有可比性（一致性护栏依赖这一点）。
	cipherSize := meta.CiphertextSize
	if cipherSize <= meta.PlainSize {
		cipherSize = meta.PlainSize + meta.HeaderLen
	}
	encryptedPath := originalURL
	// 注意：只走 AddSizeV2Meta（它已把明文 size 一并写入同一行）。
	// 不要额外 AddSize —— 两者共用同一条 upsert，AddSize 会用 0 覆盖
	// content_version/ciphertext_size/header_len/nonce_field，导致重读时
	// ContentVersion==0、lookup 恒 miss。
	p.localStore.AddSizeV2Meta(key, providerHost, originalPath, encryptedPath, meta.PlainSize, cipherSize, meta.Version, meta.HeaderLen, meta.NonceField, time.Now())
}

// lookupLocalV2Meta 从本地 SQLite 读取一条持久化的 V2 加密元数据。
// 命中且 ContentVersion>0 时返回 meta；否则返回 false。
// currentCipherSize 为当前请求解析出的密文总大小：若 DB 已确认的
// ciphertext_size 与之不符（文件被替换/变更），视为过期，拒绝复用旧 meta，
// 改由本次真实 INSPECT 结果在成功后覆盖。绝不拿过期 meta 去解密新文件。
// 在 inspectEncryptedContent 之前调用，避免对已探测过（含重启前）的文件重复打上游。
func (p *ProxyServer) lookupLocalV2Meta(providerURL, originalURL string, currentCipherSize int64) (ContentMeta, bool) {
	if p == nil || p.localStore == nil {
		return ContentMeta{}, false
	}
	rec, ok := p.lookupLocalFileMeta(providerURL, originalURL)
	if !ok || rec == nil {
		return ContentMeta{}, false
	}
	if rec.ContentVersion <= 0 || rec.Size <= 0 {
		return ContentMeta{}, false
	}
	// 一致性护栏：文件被替换成不同密文大小时，拒绝旧 meta 并丢弃本次复用。
	if currentCipherSize > 0 && rec.CiphertextSize > 0 && rec.CiphertextSize != currentCipherSize {
		log.Debugf("[v2-cache] ignore stale local sqlite meta: dbCipher=%d currentCipher=%d path=%q",
			rec.CiphertextSize, currentCipherSize, safeURLForLog(originalURL))
		return ContentMeta{}, false
	}
	meta := ContentMeta{
		Version:        rec.ContentVersion,
		HeaderLen:      rec.HeaderLen,
		PlainSize:      rec.Size,
		CiphertextSize: rec.CiphertextSize,
		NonceField:     append([]byte(nil), rec.NonceField...),
	}
	if meta.Version != ContentVersionV2 {
		// 只信任 V2 完整元数据；V1 结论不持久化（有赖 URL 精确匹配，风险高于收益）。
		return ContentMeta{}, false
	}
	if meta.HeaderLen <= 0 || len(meta.NonceField) < 16 {
		return ContentMeta{}, false
	}
	if meta.CiphertextSize <= 0 {
		// 未落盘真实 ciphertext 时先用当前解析值兜底。
		meta.CiphertextSize = currentCipherSize
	}
	if meta.CiphertextSize <= meta.PlainSize {
		// 二次兜底：V2=明文+header，用最常遇的长度结构。
		meta.CiphertextSize = meta.PlainSize + meta.HeaderLen
	}
	return meta, true
}

// invalidateLocalV2Meta 使某条持久化的 V2 元数据失效：删除 SQLite 行并清空
// 内存 fileCache/redirectCache 中与该文件相关的条目，迫使下一次播放重新
// 走真实 INSPECT 覆盖。这是"以结果论"失效的落地点 —— 当使用持久化元数据
// 解密后发生结构性失败（流截断/解密校验失败）时调用，宁可下次重探一次
// 上游，也不让过期元数据持续解错文件。
func (p *ProxyServer) invalidateLocalV2Meta(providerURL, originalURL string) {
	if p == nil {
		return
	}
	if p.localStore != nil {
		key, _, _, ok := p.localKeyFromURLs(providerURL, originalURL)
		if ok {
			if err := p.localStore.DeleteSize(key); err != nil {
				log.Warnf("[v2-cache] invalidate delete size failed key=%q err=%v", safeURLForLog(originalURL), err)
			}
		}
	}
	// 内存态也要清：同一路径的 fileCache 变体（redirectCache 是短 TTL 的
	// 临时缓存，条目带随机 redirect key、自然过期，无需精确逐条删除）。
	p.clearPlaybackMetaCaches(originalURL)
	log.Infof("[v2-cache] invalidated local V2 meta: path=%s", safeURLForLog(originalURL))
}

// clearPlaybackMetaCaches 删除某路径在内存 fileCache 中所有缓存的 V2 元数据
// 变体（displayPath 的多个前缀变体由 record/cache 回填），保证下一次请求
// 不再从内存态读到旧 meta。
func (p *ProxyServer) clearPlaybackMetaCaches(originalURL string) {
	if p == nil {
		return
	}
	displayPath := originalURL
	if displayPath != "" {
		if u, err := url.Parse(displayPath); err == nil && u.Path != "" {
			displayPath = u.Path
		}
		p.ensureRuntimeCaches()
		for _, cachePath := range appendUniquePathVariant(nil, displayPath) {
			if p.fileCache != nil {
				p.fileCache.Delete(cachePath)
			}
		}
	}
}

// recordPlaybackStats 记录一次真实播放（有字节写出）到本地统计。
// displayPath 为明文展示路径；provider 为归一化 provider host。
// durationSecs 为该次流式写出的墙钟耗时（近似播放时长）：首播=拉流耗时，
// seek=seek 间隔。比恒 0 更有信息量，供导出给 AI 分析。
// rangeStart 为本次请求的 Range 起始位置（无 Range 为 0），用于 seek 计数。
// headerLatencyMs 为本次请求"发起→响应头就绪"耗时（毫秒，0=未测量），
// mbps 为本次请求的平均下行速率（MiB/s，0=未测量）。
//
// 内部先喂给会话聚合器：同一路径活跃窗口内的多条请求合并为一条落库，
// 避免导出时一次播放产生几十条 seek 噪声。
func (p *ProxyServer) recordPlaybackStats(displayPath, provider string, bytesServed, totalBytes int64, completed bool, contentType string, durationSecs float64, rangeStart int64, headerLatencyMs, mbps float64) {
	if p == nil || p.localStore == nil || bytesServed <= 0 {
		return
	}
	if strings.TrimSpace(displayPath) == "" {
		displayPath = "(unknown)"
	}
	if durationSecs < 0 {
		durationSecs = 0
	}
	p.ensurePlaybackSessionTracker().record(
		displayPath, provider, contentType, bytesServed, totalBytes, durationSecs, completed, rangeStart, headerLatencyMs, mbps,
	)
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

// bytesPerSecondToMbps 把 bytes/秒换算成 MiB/秒，用于播放下行速率可观测。
// bps<=0 返回 0（未测量/无数据）。
func bytesPerSecondToMbps(bps float64) float64 {
	if bps <= 0 {
		return 0
	}
	return bps / (1024 * 1024)
}
