package encrypt

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
)

// 移动端 WebDAV 目录列表的“历史数据回退”：
//
// 手机端（openlist_mobile）没有独立的代理层，5244/5344 两条服务都跑在 App 进程
// 里，目录列表 PROPFIND 依赖同一份 storeWebdavListCache（只存 2xx）+ 负缓存。
// 冷存储/上游抖动时会出现“刚才还能列出 1000+ 项、现在却 404 / 502 报错”的
// 现象，负缓存还会把同目录锁死 10 分钟。这里让列表请求在失败时回退到上一次
// 成功的明文快照（stale list），并安排一次单发后台刷新——用户体验上就是
// “总有历史数据可看，后台偷偷更新”。
//
// 约束：
//   - 仅在 Depth=="1"（一个目录的列表，而非单文件元数据探测）时回退，避免把
//     “某个文件真不存在”误判成历史列表喂给字幕探测。
//   - 回退立即可用（不等待上游）；后台刷新只做一次，且复用既有 prefetchRecent
//     冷却窗口（45s），绝不轮询，控制手机端耗电。
//   - 不触碰内部 OMV/服务端平台逻辑，只改手机端 WebDAV 列表层。

// serveStaleWebDAVList 在“列表请求即将失败”时回退到上一次成功的目录快照。
// 返回 true 表示已写入响应（调用方应 return）。
//
// 入参：
//   - cacheKey：webdavListCacheKey（与负缓存键同源的目录路径键）
//   - listDepth：Depth 头；只有 "1" 才适用
//   - negativeCachePath：原始目录路径（命中后清理负缓存，避免连续锁死）
//   - targetDir：上游 /dav 路径（后台刷新的目标）
//   - srcHeaders：原始请求头（后台刷新沿用鉴权）
func (p *ProxyServer) serveStaleWebDAVList(w http.ResponseWriter, ctx context.Context, cacheKey, listDepth, negativeCachePath, targetDir string, srcHeaders http.Header) bool {
	if p == nil || w == nil || cacheKey == "" || listDepth != "1" {
		return false
	}
	status, body, _, ok := p.loadWebdavListCacheStale(cacheKey)
	if !ok || len(body) == 0 {
		return false
	}

	// 与“新鲜命中”分支保持一致的正文写法：统一先设 Content-Type，再写状态码，
	// 加密目录回填 fileCache（本书依赖 fileCache 判断文件是否存在）。
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("X-List-Stale", "1")
	w.WriteHeader(status)
	encPath := p.findEncryptPath(strings.TrimPrefix(negativeCachePath, "/dav"))
	if encPath != nil && encPath.EncName {
		if err := p.processPropfindResponse(bytes.NewReader(body), w, encPath); err != nil {
			log.Warnf("%s WebDAV stale list re-parse failed: dir=%s err=%v",
				internal.LogPrefix(ctx, internal.TagCache), cacheKey, err)
			return true
		}
	} else {
		_, _ = w.Write(body)
	}
	// 标注：当前是历史快照。
	log.Infof("%s WebDAV directory list served from STALE snapshot: dir=%s status=%d bytes=%d",
		internal.LogPrefix(ctx, internal.TagProxy), cacheKey, status, len(body))

	// 负缓存命中往往只是上游抖动，这里立刻清掉该目录负缓存，给后续恢复的请求
	// 重新打上游的机会（而非锁死 10 分钟）。真正删除的目录会由后台刷新 404 发现。
	p.clearWebdavNegative(negativeCachePath)
	// 把 stale 快照里的名字/尺寸也落盘（历史数据留底，重启后可直接渲染旧列表）。
	p.maybePersistDirList(ctx, cacheKey, body)
	// 一次后台重试，成功后快照更新为最新。
	p.scheduleWebDAVListRefresh(ctx, cacheKey, targetDir, srcHeaders)
	return true
}

// serveStaleWebDAVFromRequestPath 按请求路径（/dav 前缀可选）直接尝试回退历史
// 列表快照，供存储冷却等“还没算 webdavListCacheKey”的早期出口复用。与
// handleWebDAVLegacy 中 webdavListCacheKey = webdavNegativeKey(去 "/dav")
// 的键保持一致。
func (p *ProxyServer) serveStaleWebDAVFromRequestPath(w http.ResponseWriter, ctx context.Context, filePath, listDepth string, srcHeaders http.Header) bool {
	if p == nil || w == nil || filePath == "" {
		return false
	}
	originPath := filePath
	if strings.HasPrefix(originPath, "/dav") {
		originPath = strings.TrimPrefix(originPath, "/dav")
		if originPath == "" {
			originPath = "/"
		}
	}
	cacheKey := p.webdavNegativeKey(originPath)
	return p.serveStaleWebDAVList(w, ctx, cacheKey, listDepth, originPath, filePath, srcHeaders)
}

// scheduleWebDAVListRefresh 安排一次后台 PROPFIND 刷新该目录列表（一次性，非轮询）。
// 复用 shouldSchedulePrefetch 的同一份 prefetchRecent 冷却（45s 窗口、2048 上限）。
func (p *ProxyServer) scheduleWebDAVListRefresh(ctx context.Context, cacheKey, targetDir string, srcHeaders http.Header) {
	if p == nil || cacheKey == "" || targetDir == "" {
		return
	}
	if !p.shouldSchedulePrefetch("wlist-refresh:" + cacheKey) {
		return
	}
	if p.shouldFastFailUpstream() {
		// 上游还处于整体回退，此时刷新大概率又 502：放弃，继续让客户端用 stale，
		// 等用户下一次真实操作再触发后台刷新。
		return
	}

	headers := http.Header{}
	for k, vs := range srcHeaders {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") ||
			strings.EqualFold(k, "Proxy-Authorization") {
			continue
		}
		for _, v := range vs {
			headers.Add(k, v)
		}
	}
	// 后台刷新不得挂接到请求 ctx（请求返回后 ctx 即被取消，刷新根本发不出去）。
	// 用独立 Background；超时由 refreshWebDAVListOnce 内的 probeTimeout 兜底。
	go func() {
		p.refreshWebDAVListOnce(context.Background(), targetDir, headers)
	}()
}

// refreshWebDAVListOnce 执行一次深度=1 的 PROPFIND；成功后把解密后的明文正文
// 写进列表缓存并清理负缓存；失败静默（保留 stale 供后续继续回退）。
// targetDir 为请求侧的 /dav 目录路径（如 "/dav/movies"）。
func (p *ProxyServer) refreshWebDAVListOnce(parentCtx context.Context, targetDir string, headers http.Header) {
	if p == nil || targetDir == "" {
		return
	}
	timeout := p.probeTimeout()
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	// 统一成 "/dav/..." 形式，与 handleWebDAVLegacy 的上游转发路径保持一致。
	davPath := targetDir
	if !strings.HasPrefix(davPath, "/dav") {
		davPath = "/dav/" + strings.TrimPrefix(davPath, "/")
	}
	originPath := strings.TrimPrefix(davPath, "/dav")
	if originPath == "" {
		originPath = "/"
	}
	// 与主流程一致的加密信息解析：目录本身可能落在某个加密根下，明文正文
	// 需要按该根把所有条目解密回显示名，缓存才能被后续列表请求直接命中。
	matchEnc := originPath
	encObj := p.findEncryptPath(matchEnc)
	if encObj == nil && matchEnc != originPath {
		encObj = p.findEncryptPath(originPath)
	}

	targetURL := p.getAlistURL() + davPath
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", targetURL, strings.NewReader(dirWarmPropfindBody))
	if err != nil {
		return
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml")
	runtime := p.runtimeSnapshot()
	if runtime.config == nil || runtime.httpClient == nil {
		return
	}
	resp, err := runtime.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return
	}

	// 边解密边写临时 buffer；只有完整成功才落缓存，避免把解析一半的脏数据
	// 当作可恢复快照。
	var buf bytes.Buffer
	if err := p.processPropfindResponse(resp.Body, &buf, encObj); err != nil {
		log.Warnf("%s WebDAV list background refresh parse failed: dir=%s err=%v",
			internal.LogPrefix(parentCtx, internal.TagCache), originPath, err)
		return
	}
	key := p.webdavNegativeKey(originPath)
	p.storeWebdavListCache(key, resp.StatusCode, buf.Bytes())
	// 刷新成功说明目录确实存在：解除负缓存锁，并把最新条目名字/尺寸落盘。
	p.clearWebdavNegative(davPath)
	p.maybePersistDirList(parentCtx, key, buf.Bytes())
	log.Debugf("%s WebDAV list background refresh succeeded: dir=%s bytes=%d",
		internal.LogPrefix(ctx, internal.TagCache), key, buf.Len())
}
