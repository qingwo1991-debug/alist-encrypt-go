package encrypt

import (
	"net/http"
	"path"
	"strings"
	"time"
)

// 流式传输优化常量

func (p *ProxyServer) propfindRetryTimeout() time.Duration {
	// Keep retry budget short to avoid long stalls on 404/misclassified paths.
	base := p.probeTimeout()
	if base <= 0 {
		base = 1500 * time.Millisecond
	}
	if base > 1500*time.Millisecond {
		base = 1500 * time.Millisecond
	}
	if base < 300*time.Millisecond {
		base = 300 * time.Millisecond
	}
	return base
}

func shouldRetryPropfind404(depthHeader, filePath string) bool {
	name := path.Base(filePath)
	if name == "" || name == "/" || name == "." {
		return false
	}
	depth := strings.TrimSpace(depthHeader)
	if depth == "0" {
		return true
	}
	// Some clients omit Depth for single-file probes; only retry if path shape is file-like.
	if depth == "" && !strings.HasSuffix(filePath, "/") && path.Ext(name) != "" {
		return true
	}
	return false
}

func (p *ProxyServer) webdavNegativeTTL() time.Duration {
	if p == nil || p.config == nil || p.config.WebDAVNegativeCacheTTLMinutes <= 0 {
		return 10 * time.Minute
	}
	return time.Duration(p.config.WebDAVNegativeCacheTTLMinutes) * time.Minute
}

func (p *ProxyServer) webdavNegativeKey(requestPath string) string {
	key := strings.TrimSpace(requestPath)
	if key == "" {
		return ""
	}
	if !strings.HasPrefix(key, "/") {
		key = "/" + key
	}
	return normalizeCacheKey(key)
}

func (p *ProxyServer) webdavNegativeBlocked(requestPath string) bool {
	key := p.webdavNegativeKey(requestPath)
	if key == "" {
		return false
	}
	p.webdavNegativeMu.Lock()
	defer p.webdavNegativeMu.Unlock()
	expireAt, ok := p.webdavNegativeCache[key]
	if !ok {
		return false
	}
	if time.Now().After(expireAt) {
		delete(p.webdavNegativeCache, key)
		return false
	}
	return true
}

// handleWebDAV 处理 WebDAV 请求（V2 orchestrator 入口）
func (p *ProxyServer) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	if p != nil && p.streamEngineV2Enabled() {
		newPlayOrchestrator(p).ServePlayback(w, r)
		return
	}
	p.handleWebDAVLegacy(w, r)
}
