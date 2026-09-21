package encrypt

// live_log.go — 远程实时日志流（调试模式专用）
//
// 目的：用户的 Android App 代理监听 0.0.0.0:5344，而 App 崩溃/卡死时
// 日志只保存在内存、需要手动导出，无电脑/数据线时难以取回。这里用一个
// logrus Hook 把每条日志同时写进内存环形缓冲，并通过
//   GET /api/logs/live?since=<cursor>[&n=<lines>][&k=<stats-password>]
// 提供增量轮询：调用方（例如同局域网的诊断端）固定 cursor 轮询即可
// 拿到从上次游标以来的所有新日志行，实现"实时上报/远程 tail"。
//
// 安全：仅当 config.DebugEnabled == true 时才接受请求；关闭调试时返回
// 403，避免局域网无防护暴露日志。（路由本身总在 mux 注册，但被 403 挡住，
// 这样调试开关切换不需要重启动态路由表。）

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	liveLogRingCapacity = 4096 // 环形缓冲上限：保留最近 4096 条
)

// liveLogEntry 环形缓冲里的一条日志
type liveLogEntry struct {
	N     int    `json:"n"`    // 单调递增序号（游标）
	Time  string `json:"time"` // RFC3339
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// liveLogBuffer 线程安全的 LRU 环形缓冲
type liveLogBuffer struct {
	mu      sync.Mutex
	entries []liveLogEntry // 按 N 升序
	next    int            // 下一个序号
}

func newLiveLogBuffer() *liveLogBuffer {
	return &liveLogBuffer{entries: make([]liveLogEntry, 0, liveLogRingCapacity)}
}

// append 追加一条并维护环（仍保持按 N 升序）
func (b *liveLogBuffer) append(level string, msg string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := liveLogEntry{
		N:     b.next,
		Time:  time.Now().UTC().Format(time.RFC3339),
		Level: level,
		Msg:   strings.ReplaceAll(msg, "\n", " "),
	}
	b.next++
	if len(b.entries) < liveLogRingCapacity {
		b.entries = append(b.entries, e)
		return
	}
	// 超出容量：整体左移丢弃最旧（保留有序，便于游标比较）
	copy(b.entries, b.entries[1:])
	b.entries[len(b.entries)-1] = e
}

// tail 返回序号 > since 的所有行（最多 n 行）。若 since 太旧则返回已有全部。
func (b *liveLogBuffer) tail(since int, n int) (int, []liveLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]liveLogEntry, 0)
	for _, e := range b.entries {
		if e.N > since {
			out = append(out, e)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	cursor := -1
	if len(b.entries) > 0 {
		cursor = b.entries[len(b.entries)-1].N
	}
	return cursor, out
}

// liveLogHook 把每条 logrus 日志灌入缓冲
type liveLogHook struct{ buf *liveLogBuffer }

func (h *liveLogHook) Levels() []log.Level { return log.AllLevels }
func (h *liveLogHook) Fire(entry *log.Entry) error {
	h.buf.append(strings.ToUpper(entry.Level.String()), entry.Message)
	return nil
}

var (
	// liveLogInstance 全局缓冲与 hook（包内单例）
	liveLogInstance = newLiveLogBuffer()
	liveLogHookOnce sync.Once
)

// registerLiveLogHook 把 logrus hook 挂到标准 logger（只挂一次）
func registerLiveLogHook() {
	liveLogHookOnce.Do(func() {
		log.AddHook(&liveLogHook{buf: liveLogInstance})
	})
}

// handleLiveLogs 供 mux 注册：GET /api/logs/live?since=<cursor>[&n=<lines>][&k=<key>]
func (p *ProxyServer) handleLiveLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 安全：非调试模式一律拒绝
	if !p.config.DebugEnabled {
		http.Error(w, "live logs disabled (debug off)", http.StatusForbidden)
		return
	}
	// 用统计访问密码作为可选的额外鉴权（若配置了且非空）
	pwd := p.config.StatsPassword
	if pwd != "" && r.URL.Query().Get("k") != pwd {
		http.Error(w, "invalid key", http.StatusUnauthorized)
		return
	}
	registerLiveLogHook() // 惰性挂载，不阻塞启动

	since := 0
	if v := r.URL.Query().Get("since"); v != "" {
		since = atoiSafe(v, 0)
	}
	n := 0
	if v := r.URL.Query().Get("n"); v != "" {
		n = atoiSafe(v, 0)
	}
	cursor, lines := liveLogInstance.tail(since, n)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"cursor": cursor,
		"count":  len(lines),
		"lines":  lines,
	})
}

func atoiSafe(s string, def int) int {
	if s == "" {
		return def
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
	}
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
