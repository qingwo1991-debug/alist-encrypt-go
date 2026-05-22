package encrypt

import (
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

// 流式传输优化常量

func clampStreamBufferKB(kb int) int {
	if kb < 32 {
		return 32
	}
	if kb > 4096 {
		return 4096
	}
	return kb
}

func clampSeconds(v, def, minV, maxV int) int {
	if v <= 0 {
		v = def
	}
	if v < minV {
		v = minV
	}
	if v > maxV {
		v = maxV
	}
	return v
}

func (p *ProxyServer) debugEnabled(module string) bool {
	if p == nil || p.config == nil || !p.config.DebugEnabled {
		return false
	}
	if len(p.config.DebugModules) > 0 {
		matched := false
		for _, m := range p.config.DebugModules {
			if strings.EqualFold(strings.TrimSpace(m), module) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	rate := p.config.DebugSampleRate
	if rate <= 0 || rate > 100 {
		rate = 100
	}
	if rate == 100 {
		return true
	}
	return int(time.Now().UnixNano()%100) < rate
}

func maskSensitiveValue(key string, value string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "token", "access_token", "authorization", "auth", "password", "passwd", "secret", "key", "signature", "sign", "cookie", "set-cookie":
		return "***"
	default:
		return value
	}
}

func (p *ProxyServer) sanitizeURLForDebug(raw string) string {
	if p == nil || p.config == nil || !p.config.DebugMaskSensitive {
		return raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := parsed.Query()
	for key, vals := range q {
		for i := range vals {
			vals[i] = maskSensitiveValue(key, vals[i])
		}
		q[key] = vals
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func (p *ProxyServer) debugf(module string, format string, args ...interface{}) {
	if !p.debugEnabled(module) {
		return
	}
	log.Debugf("[dbg:%s] "+format, append([]interface{}{module}, args...)...)
}

func (p *ProxyServer) upstreamTimeout() time.Duration {
	secs := 15
	if p != nil && p.config != nil {
		secs = clampSeconds(p.config.UpstreamTimeoutSeconds, 15, 2, 120)
	}
	return time.Duration(secs) * time.Second
}

func (p *ProxyServer) probeTimeout() time.Duration {
	secs := 5
	if p != nil && p.config != nil {
		secs = clampSeconds(p.config.ProbeTimeoutSeconds, 5, 1, 30)
	}
	return time.Duration(secs) * time.Second
}

func (p *ProxyServer) probeBudget() time.Duration {
	secs := 10
	if p != nil && p.config != nil {
		secs = clampSeconds(p.config.ProbeBudgetSeconds, 10, 1, 60)
	}
	return time.Duration(secs) * time.Second
}

func (p *ProxyServer) upstreamBackoff() time.Duration {
	secs := 20
	if p != nil && p.config != nil {
		secs = clampSeconds(p.config.UpstreamBackoffSeconds, 20, 1, 300)
	}
	return time.Duration(secs) * time.Second
}

func isLocalOrPrivateHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return false
	}
	if h == "localhost" || strings.HasSuffix(h, ".local") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}

func syncMapLen(m *sync.Map) int {
	if m == nil {
		return 0
	}
	count := 0
	m.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

type mapShard struct {
	mu sync.RWMutex
	m  map[string]interface{}
}

type shardedAnyMap struct {
	shards []mapShard
}

type upstreamHTTPStats struct {
	requests       atomic.Int64
	errors         atomic.Int64
	totalLatencyNs atomic.Int64
}

type instrumentedRoundTripper struct {
	base  http.RoundTripper
	stats *upstreamHTTPStats
}

type ProbeMethodStats struct {
	mu      sync.Mutex
	byScope map[string]map[ProbeMethod]*ProbeMethodCounter
}

// copyWithBuffer 使用大缓冲区池进行高效复制（用于流媒体）
func copyWithBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := largeBufferPool.Get().(*[]byte)
	defer largeBufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}

// copyWithSmallBuffer 使用小缓冲区池进行复制（用于小文件/API）
func copyWithSmallBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufPtr := smallBufferPool.Get().(*[]byte)
	defer smallBufferPool.Put(bufPtr)
	return io.CopyBuffer(dst, src, *bufPtr)
}
