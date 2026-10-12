package encrypt

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

// dualProbeAttempts 双网络 RTT 主动探测发起次数（观测用，进程内累计）。
var dualProbeAttempts atomic.Uint64

// dual_network.go — WiFi + SIM 双网络延迟自适应切换（移动端，Android 为主）。
//
// 设计原则（用户明确要求，且防被 CDN 判定为攻击）：
//  1. 被动测量为主：真实 HEAD/Range 请求回程计时记入"当前网络" RTT，零新增请求。
//  2. 主动探测仅对"真实已解析出的目标 host"（由 X-Encrypt-Provider/Driver 决定）
//     发 HEAD 或 Range: bytes=0-0，绝不主动枚举 host/端口。
//  3. 严格节流 + 抖动：每个 provider 在探测间隔内最多 1 次，超时 ~2s。
//  4. 见 403/429/连接重置即停：立即对该 host 写负缓存，回退默认网络，不重试死磕。
//  5. 探测失败 = 退化为现状：任何链路探不到就走现有逻辑，绝不让探测拖慢播放。
//
// socket 绑定：仅对外部可靠提供、且进程有权限设置的 Linux SO_MARK 生效。
// Android Network handle 是 opaque，不可据此计算 fwmark；当前 Android bridge
// 显式提供零 marks，并报告 unsupported，保持系统默认路由（含 VPN/TUN）。
// 支持 Android 选网需要独立的 Network.bindSocket(fd) 桥，不能猜测内核 ABI。

const (
	// soMark 是 Linux 上 SO_MARK 的 socket 选项号（没有跨平台常量名）。
	// Android 是 Linux，Android 的网络路由按 fwmark 区分。
	soMark = 0x24
	// dualNetworkMarkNone 表示"不绑定到特定网络"
	dualNetworkMarkNone = uint32(0)
	// dualNetworkProbeTimeout 单次最小探测超时
	dualNetworkProbeTimeout = 2 * time.Second
	// dualNetworkProbeHTTPTimeout 主动探测的 HTTP 请求总超时
	dualNetworkProbeHTTPTimeout = 2 * time.Second
	// dualNetworkProbeJitterMax 节流抖动上限（秒），避免所有客户端同一时刻打 CDN
	dualNetworkProbeJitterMax = 60
	// dualNetworkNegativeTTL 风控负缓存时长
	dualNetworkNegativeTTL = 10 * time.Minute
	// dualNetworkMaxRTTEntries 延迟表容量上限
	dualNetworkMaxRTTEntries = 1024
)

// dualNetworkState 保存 Android 层传入的双网络 fwmark 与开关状态。
// 全局单例，gomobile 端 setter 写入，拨号时读取。
type dualNetworkState struct {
	mu            sync.RWMutex
	enabled       bool
	wifi          uint32
	cell          uint32
	generation    uint64
	failedMarks   map[uint32]bool
	lastBindError string
}

var globalDualNetwork = &dualNetworkState{}

// Only idle connections are retired: active video bodies retain cancellation
// and are never forcibly closed on a connectivity notification.
var networkTransports = struct {
	sync.Mutex
	items map[*http.Transport]struct{}
}{items: make(map[*http.Transport]struct{})}

func trackNetworkTransport(t *http.Transport, add bool) {
	if t == nil {
		return
	}
	networkTransports.Lock()
	defer networkTransports.Unlock()
	if add {
		networkTransports.items[t] = struct{}{}
	} else {
		delete(networkTransports.items, t)
	}
}

func invalidateNetworkRouting() {
	globalDualNetwork.mu.Lock()
	defer globalDualNetwork.mu.Unlock()
	globalDualNetwork.generation++
	globalDualNetwork.failedMarks = make(map[uint32]bool)
	globalDualNetwork.lastBindError = ""
	hostMarkHint.mu.Lock()
	clear(hostMarkHint.hints)
	hostMarkHint.mu.Unlock()
	globalDualNetworkLatency.mu.Lock()
	clear(globalDualNetworkLatency.entries)
	clear(globalDualNetworkLatency.lastProbeAt)
	clear(globalDualNetworkLatency.negativeHost)
	globalDualNetworkLatency.mu.Unlock()
	directProbeCache.Range(func(k, _ interface{}) bool { directProbeCache.Delete(k); return true })
	networkTransports.Lock()
	for t := range networkTransports.items {
		t.CloseIdleConnections()
	}
	networkTransports.Unlock()
}

// SetEncryptDualNetworkMarks 由 gomobile 导出（经 encrypt_server.go），Android 层调用。
// wifiFwmark/cellFwmark 为 0 表示"该网络不可绑定"。
func SetEncryptDualNetworkMarks(wifiFwmark, cellFwmark int64, enabled bool) {
	globalDualNetwork.mu.Lock()
	changed := globalDualNetwork.enabled != enabled || globalDualNetwork.wifi != uint32(wifiFwmark) || globalDualNetwork.cell != uint32(cellFwmark)
	globalDualNetwork.enabled = enabled
	globalDualNetwork.wifi = uint32(wifiFwmark)
	globalDualNetwork.cell = uint32(cellFwmark)
	globalDualNetwork.mu.Unlock()
	// Zero marks are also the ABI-preserving Android topology notification when
	// per-socket binding is unsupported (WiFi A -> WiFi B has the same state).
	if changed || (wifiFwmark == 0 && cellFwmark == 0) {
		invalidateNetworkRouting()
	}
}

// dualNetworkSnapshot 返回当前双网络状态的可变副本。
func dualNetworkSnapshot() (enabled bool, wifi, cell uint32) {
	globalDualNetwork.mu.RLock()
	defer globalDualNetwork.mu.RUnlock()
	return globalDualNetwork.enabled, globalDualNetwork.wifi, globalDualNetwork.cell
}

// normalizeDualNetworkPreference 规范化选路偏好。
func normalizeDualNetworkPreference(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case dualNetworkPrefWiFi:
		return dualNetworkPrefWiFi
	case dualNetworkPrefCellular:
		return dualNetworkPrefCellular
	default:
		return dualNetworkPrefAuto
	}
}

// networkPath 描述一个可绑定网络。
type networkPath struct {
	kind string // "wifi" | "cell"
	mark uint32 // 0 = 不可绑定
}

// rttEntry 记录某个 provider/目标 host 在两条网络上的最近延迟。
type rttEntry struct {
	provider string
	host     string
	wifiRTT  time.Duration
	cellRTT  time.Duration
	updated  time.Time
}

// dualNetworkLatencyTable 按 provider 维护最近实测延迟 + 节流 + 风控负缓存。
type dualNetworkLatencyTable struct {
	mu           sync.Mutex
	entries      map[string]*rttEntry // key: provider normalized
	lastProbeAt  map[string]time.Time // key: provider -> 上次主动探测时间（节流）
	negativeHost map[string]time.Time // key: host -> 风控冷却截止
}

var globalDualNetworkLatency = &dualNetworkLatencyTable{
	entries:      make(map[string]*rttEntry),
	lastProbeAt:  make(map[string]time.Time),
	negativeHost: make(map[string]time.Time),
}

// providerKeyFromRequest 从请求头提取 provider（用于延迟表与选路）。
// 请求头由 applyRoutingHints 在 play/proxy 路径注入。
func providerKeyFromRequest(req *http.Request) string {
	if req == nil || req.Header == nil {
		return ""
	}
	p := normalizeProviderToken(req.Header.Get("X-Encrypt-Provider"))
	if p == "" {
		p = normalizeProviderToken(req.Header.Get("X-Encrypt-Driver"))
	}
	return p
}

// targetHostFromRequest 从请求 URL 提取目标 CDN host。为空则不参与主动探测。
func targetHostFromRequest(req *http.Request) string {
	if req == nil || req.URL == nil || req.URL.Hostname() == "" {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(req.URL.Hostname()))
}

// negativeBlocked 报告该 host 是否处于风控负缓存冷却期。
func (t *dualNetworkLatencyTable) negativeBlocked(host string) bool {
	if t == nil || host == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	until, ok := t.negativeHost[host]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(t.negativeHost, host)
		return false
	}
	return true
}

// markNegative 记录一次风控信号（403/429/连接重置），冷却期内不再探测该 host。
func (t *dualNetworkLatencyTable) markNegative(host string) {
	if t == nil || host == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.negativeHost) >= dualNetworkMaxRTTEntries {
		// 简单清理：清掉一半最老的
		oldest := make([]string, 0, len(t.negativeHost)/2)
		for h := range t.negativeHost {
			oldest = append(oldest, h)
		}
		sort.Strings(oldest)
		for _, h := range oldest[:len(oldest)/2] {
			delete(t.negativeHost, h)
		}
	}
	t.negativeHost[host] = time.Now().Add(dualNetworkNegativeTTL)
}

// recordPassive 用真实请求的回程计时记录"当前网络" RTT（零新增请求）。
func (t *dualNetworkLatencyTable) recordPassive(provider, host string, rtt time.Duration) {
	if t == nil || provider == "" || host == "" || rtt <= 0 {
		return
	}
	kind := "wifi"
	switch GetNetworkState() {
	case NetworkState4G, NetworkState5G, NetworkStateCellular:
		kind = "cell"
	}
	t.recordPath(provider, host, kind, rtt)
}

func (t *dualNetworkLatencyTable) recordPath(provider, host, kind string, rtt time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) >= dualNetworkMaxRTTEntries && t.entries[provider] == nil {
		return // 容量已满且是新增 provider
	}
	e := t.entries[provider]
	if e == nil {
		e = &rttEntry{provider: provider, host: host}
		t.entries[provider] = e
	}
	// 当前生效网络由 GetNetworkState() 判定；只更新对应槽位。
	if kind == "cell" {
		e.cellRTT = rtt
	} else {
		e.wifiRTT = rtt
	}
	e.host = host
	e.updated = time.Now()
}

// chooseNetwork 选当前 provider 更快的网络，并遵守偏好。
// 偏好：auto=纯延迟；wifi=除非蜂窝显著更快（迟滞阈值）否则用 WiFi；cellular 同理。
// 任一条未知时回退到"已知更优"，都未知返回 (默认路径, 不绑定)。
// enabled=false 或 mark=0 时不绑定。
func (t *dualNetworkLatencyTable) chooseNetwork(provider, preference string) networkPath {
	enabled, wifiMark, cellMark := dualNetworkSnapshot()
	if !enabled {
		return networkPath{}
	}
	wifiOK := wifiMark != dualNetworkMarkNone
	cellOK := cellMark != dualNetworkMarkNone
	if !wifiOK && !cellOK {
		return networkPath{}
	}
	preference = normalizeDualNetworkPreference(preference)

	t.mu.Lock()
	var e *rttEntry
	if current := t.entries[provider]; current != nil {
		copy := *current
		e = &copy
	}
	t.mu.Unlock()

	// 无任何记录：按偏好优先（默认 WiFi），交给被动测量去积累。
	if e == nil {
		switch preference {
		case dualNetworkPrefCellular:
			if cellOK {
				return networkPath{kind: "cell", mark: cellMark}
			}
			if wifiOK {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			return networkPath{}
		default:
			if wifiOK {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			if cellOK {
				return networkPath{kind: "cell", mark: cellMark}
			}
			return networkPath{}
		}
	}

	hasWifi := e.wifiRTT > 0
	hasCell := e.cellRTT > 0

	// 偏好影响 + 迟滞：非优先网络必须"显著更快"（超过 hysteresis）才切过去。
	switch preference {
	case dualNetworkPrefWiFi:
		if wifiOK {
			if !hasCell || !hasWifi || e.wifiRTT <= e.cellRTT+dualNetworkPrefHysteresis {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			return networkPath{kind: "cell", mark: cellMark}
		}
		if cellOK {
			return networkPath{kind: "cell", mark: cellMark}
		}
		return networkPath{}
	case dualNetworkPrefCellular:
		if cellOK {
			if !hasCell || !hasWifi || e.cellRTT <= e.wifiRTT+dualNetworkPrefHysteresis {
				return networkPath{kind: "cell", mark: cellMark}
			}
			return networkPath{kind: "wifi", mark: wifiMark}
		}
		if wifiOK {
			return networkPath{kind: "wifi", mark: wifiMark}
		}
		return networkPath{}
	default: // auto：纯延迟
		switch {
		case hasWifi && hasCell:
			if e.wifiRTT <= e.cellRTT {
				if wifiOK {
					return networkPath{kind: "wifi", mark: wifiMark}
				}
				if cellOK {
					return networkPath{kind: "cell", mark: cellMark}
				}
			}
			if cellOK {
				return networkPath{kind: "cell", mark: cellMark}
			}
			if wifiOK {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			return networkPath{}
		case hasWifi:
			if wifiOK {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			if cellOK {
				return networkPath{kind: "cell", mark: cellMark}
			}
			return networkPath{}
		case hasCell:
			if cellOK {
				return networkPath{kind: "cell", mark: cellMark}
			}
			if wifiOK {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			return networkPath{}
		default:
			if wifiOK {
				return networkPath{kind: "wifi", mark: wifiMark}
			}
			if cellOK {
				return networkPath{kind: "cell", mark: cellMark}
			}
			return networkPath{}
		}
	}
}

// shouldProbe 判断是否到了主动探测"另一条网络"的时机（严格节流）。
func (t *dualNetworkLatencyTable) shouldProbe(provider string, interval time.Duration) bool {
	if t == nil || provider == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.lastProbeAt[provider]
	if !ok {
		return true
	}
	if interval <= 0 {
		interval = time.Duration(defaultDualNetworkProbeIntervalSecs) * time.Second
	}
	// 节流窗口 = 配置间隔 + 随机抖动，避免全端同时打 CDN。
	return time.Since(last) > interval+time.Duration(randJitterN(dualNetworkProbeJitterMax))*time.Second
}

func (t *dualNetworkLatencyTable) noteProbed(provider string) {
	if t == nil || provider == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.lastProbeAt) >= dualNetworkMaxRTTEntries && t.lastProbeAt[provider] == (time.Time{}) {
		return
	}
	t.lastProbeAt[provider] = time.Now()
}

// probeDualNetworkAsync 后台探测"另一条网络"到真实目标 host 的 RTT。
// 只发 HEAD 或 Range: bytes=0-0 的极小请求，且遇到风控信号立即写负缓存停手。
// 探测完全在后台异步进行，绝不阻塞任何请求。
func probeDualNetworkAsync(provider, targetHost string, req *http.Request, probeInterval time.Duration) {
	if targetHost == "" || provider == "" {
		return
	}
	enabled, _, _ := dualNetworkSnapshot()
	if !enabled {
		return
	}
	if globalDualNetworkLatency.negativeBlocked(targetHost) {
		return
	}
	if !globalDualNetworkLatency.shouldProbe(provider, probeInterval) {
		return
	}
	globalDualNetworkLatency.noteProbed(provider)

	// 目标网络：探测当前没走的那条（若只有一条可用，则探测它）。
	_, wifiMark, cellMark := dualNetworkSnapshot()
	wifiOK := wifiMark != dualNetworkMarkNone
	cellOK := cellMark != dualNetworkMarkNone
	probePath := networkPath{}
	switch GetNetworkState() {
	case NetworkState4G, NetworkState5G, NetworkStateCellular:
		if wifiOK {
			probePath = networkPath{kind: "wifi", mark: wifiMark}
		} else {
			probePath = networkPath{kind: "cell", mark: cellMark}
		}
	default:
		if cellOK {
			probePath = networkPath{kind: "cell", mark: cellMark}
		} else {
			probePath = networkPath{kind: "wifi", mark: wifiMark}
		}
	}
	if probePath.mark == dualNetworkMarkNone {
		return
	}
	// 观测：一次双网络 RTT 主动探测（已通过节流/风控检查，将真实发起请求）。
	dualProbeAttempts.Add(1)

	// 探测只对真实目标 host 的根路径做极小 HEAD/Range，绝不对端口/路径枚举。
	scheme := "http"
	if req != nil && req.URL != nil && req.URL.Scheme == "https" {
		scheme = "https"
	}
	probeURL := fmt.Sprintf("%s://%s/", scheme, targetHost)

	globalDualNetwork.mu.RLock()
	generation := globalDualNetwork.generation
	failed := globalDualNetwork.failedMarks[probePath.mark]
	globalDualNetwork.mu.RUnlock()
	if failed {
		return
	}
	go func() {
		start := time.Now()
		probeReq, err := http.NewRequest(http.MethodHead, probeURL, nil)
		if err != nil {
			return
		}
		probeReq.Header.Set("Range", "bytes=0-0")
		probeReq.Header.Set("Accept-Encoding", "identity")
		ctx, cancel := context.WithTimeout(context.Background(), dualNetworkProbeHTTPTimeout)
		defer cancel()
		probeReq = probeReq.WithContext(ctx)

		dialer := &net.Dialer{Timeout: dualNetworkProbeTimeout, KeepAlive: 30 * time.Second}
		client := &http.Client{
			Timeout:   dualNetworkProbeHTTPTimeout,
			Transport: &http.Transport{DialContext: dualNetworkDialContext(dialer, probePath)},
		}
		resp, err := client.Do(probeReq)
		if err != nil {
			var bindErr *dualNetworkBindError
			if errors.As(err, &bindErr) {
				recordDualNetworkBindFailure(probePath.mark, generation, bindErr)
				return // Never attribute a default-route probe RTT to this path.
			}
			globalDualNetwork.mu.RLock()
			if generation == globalDualNetwork.generation {
				globalDualNetworkLatency.markNegative(targetHost)
			}
			globalDualNetwork.mu.RUnlock()
			return
		}
		defer resp.Body.Close()
		// 见 403/429：风控，立即停手冷却。
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			globalDualNetwork.mu.RLock()
			if generation == globalDualNetwork.generation {
				globalDualNetworkLatency.markNegative(targetHost)
			}
			globalDualNetwork.mu.RUnlock()
			return
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			globalDualNetwork.mu.RLock()
			if globalDualNetwork.enabled && generation == globalDualNetwork.generation {
				globalDualNetworkLatency.recordPath(provider, targetHost, probePath.kind, time.Since(start))
			}
			globalDualNetwork.mu.RUnlock()
		}
	}()
}

func recordDualNetworkBindFailure(mark uint32, generation uint64, err error) {
	globalDualNetwork.mu.Lock()
	defer globalDualNetwork.mu.Unlock()
	if generation != globalDualNetwork.generation {
		return
	}
	if globalDualNetwork.failedMarks == nil {
		globalDualNetwork.failedMarks = make(map[uint32]bool)
	}
	if !globalDualNetwork.failedMarks[mark] {
		log.Warnf("[dual-network] socket binding failed; using default system route until network changes: %v", err)
	}
	globalDualNetwork.failedMarks[mark] = true
	globalDualNetwork.lastBindError = err.Error()
}

var setDualNetworkSocketMark = func(fd int, mark uint32) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soMark, int(mark))
}

type dualNetworkBindError struct{ err error }

func (e *dualNetworkBindError) Error() string { return "SO_MARK: " + e.err.Error() }
func (e *dualNetworkBindError) Unwrap() error { return e.err }

// dualNetworkDialContext 返回一个 net.Dialer.DialContext，拨号时把 socket 绑定到指定网络。
func dualNetworkDialContext(d *net.Dialer, path networkPath) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{}
	}
	ctrl := d.Control
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := *d
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			if ctrl != nil {
				if err := ctrl(network, address, c); err != nil {
					return err
				}
			}
			if path.mark != dualNetworkMarkNone {
				var ctrlErr error
				if err := c.Control(func(fd uintptr) {
					ctrlErr = setDualNetworkSocketMark(int(fd), path.mark)
				}); err != nil {
					return err
				}
				if ctrlErr != nil {
					return &dualNetworkBindError{err: ctrlErr}
				}
			}
			return nil
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

// hostMarkHint 记录"目标 host -> 最近一次选定的 mark"，供 DialContext 拨号时
// 按 addr 里的 host 查表。HTTP/1 keep-alive 会复用连接，所以命中率很高。
// 容量很小，LRU 由全局延迟表驱动（同一 provider 的目标 host 稳定）。
var hostMarkHint struct {
	mu    sync.Mutex
	hints map[string]uint32
}

func init() {
	hostMarkHint.hints = make(map[string]uint32)
}

// resolveDualNetworkMark 由 newProxyResolver 调用：请求级选路，记录该 host 的 mark。
// 返回选定的 mark（0 = 不绑定）。会做被动记录 + 触发后台异步探测。
// 只依赖全局状态 + config 快照，因此可在 transport 构造阶段（server 未建）调用。
func resolveDualNetworkMark(req *http.Request, probeInterval time.Duration, preference string) uint32 {
	if req == nil || req.URL == nil {
		return 0
	}
	enabled, _, _ := dualNetworkSnapshot()
	if !enabled {
		return 0
	}
	provider := providerKeyFromRequest(req)
	host := targetHostFromRequest(req)
	if host == "" {
		return 0
	}
	path := globalDualNetworkLatency.chooseNetwork(provider, preference)
	if path.mark == dualNetworkMarkNone {
		return 0
	}
	globalDualNetwork.mu.RLock()
	if !globalDualNetwork.enabled || (path.mark != globalDualNetwork.wifi && path.mark != globalDualNetwork.cell) {
		globalDualNetwork.mu.RUnlock()
		return 0
	}
	hostMarkHint.mu.Lock()
	hostMarkHint.hints[host] = path.mark
	if len(hostMarkHint.hints) > 256 {
		for h := range hostMarkHint.hints {
			if len(hostMarkHint.hints) <= 128 {
				break
			}
			delete(hostMarkHint.hints, h)
		}
	}
	hostMarkHint.mu.Unlock()
	globalDualNetwork.mu.RUnlock()
	// 后台异步探测"另一条网络"的真实延迟（严格节流，绝不阻塞本请求）。
	probeDualNetworkAsync(provider, host, req, probeInterval)
	return path.mark
}

// hostMarkFromAddr 从 DialContext 的 addr 里提取 host 并查询绑定的 mark。
func hostMarkFromAddr(addr string) uint32 {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.ToLower(strings.TrimSpace(host))
	hostMarkHint.mu.Lock()
	mark, ok := hostMarkHint.hints[host]
	hostMarkHint.mu.Unlock()
	if ok && mark != dualNetworkMarkNone {
		return mark
	}
	return 0
}

// newDualNetworkDialer 在配置启用时返回一个按 host 绑定 fwmark 的拨号器；
// 否则返回与 base 完全一致的拨号器（零行为变化）。
func newDualNetworkDialer(base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if base == nil {
		return nil
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		mark := hostMarkFromAddr(addr)
		globalDualNetwork.mu.RLock()
		enabled := globalDualNetwork.enabled
		failed := globalDualNetwork.failedMarks[mark]
		generation := globalDualNetwork.generation
		valid := mark == globalDualNetwork.wifi || mark == globalDualNetwork.cell
		globalDualNetwork.mu.RUnlock()
		if !enabled || failed || !valid || mark == dualNetworkMarkNone {
			return base.DialContext(ctx, network, addr)
		}
		conn, err := dualNetworkDialContext(base, networkPath{mark: mark})(ctx, network, addr)
		var bindErr *dualNetworkBindError
		if !errors.As(err, &bindErr) {
			return conn, err
		}
		recordDualNetworkBindFailure(mark, generation, bindErr)
		// Exactly one default-route attempt, under the caller's original budget.
		return base.DialContext(ctx, network, addr)
	}
}

// randJitterN 返回 [0, n) 的随机整数（用于探测节流抖动）。
// 探测是低频路径，直接用 crypto/rand：真随机，避免并发探测在同一时钟纳秒
// 碰撞导致节流窗口同步（看起来像突发攻击）。
func randJitterN(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		// crypto/rand 不可用（理论上不会），退化为时钟抖动。
		return int(time.Now().UnixNano() % int64(n))
	}
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % n
}

// GetEncryptDualNetworkStatusJson 导出双网络状态（enabled + 双网络 fwmark + 延迟表样例）。
// 供 Flutter 延迟面板 / gomobile 读取。
func GetEncryptDualNetworkStatusJson() string {
	enabled, wifiMark, cellMark := dualNetworkSnapshot()
	globalDualNetwork.mu.RLock()
	lastBindError := globalDualNetwork.lastBindError
	failedCount := len(globalDualNetwork.failedMarks)
	globalDualNetwork.mu.RUnlock()
	status := "disabled"
	if wifiMark == 0 && cellMark == 0 {
		status = "unsupported"
	} else if enabled {
		status = "available"
	}
	if failedCount > 0 {
		status = "default-route-fallback"
	}
	type netInfo struct {
		Fwmark uint32 `json:"fwmark"`
		RttMs  int64  `json:"rtt_ms"`
		Active bool   `json:"active"`
		Bound  bool   `json:"bound"`
	}
	out := struct {
		Enabled       bool     `json:"enabled"`
		BindingStatus string   `json:"binding_status"`
		LastBindError string   `json:"last_bind_error,omitempty"`
		Wifi          netInfo  `json:"wifi"`
		Cellular      netInfo  `json:"cellular"`
		Providers     []string `json:"providers"`
	}{
		Enabled:       enabled,
		BindingStatus: status,
		LastBindError: lastBindError,
		Wifi: netInfo{
			Fwmark: wifiMark,
			Bound:  wifiMark != dualNetworkMarkNone,
			Active: GetNetworkState() == NetworkStateWiFi,
		},
		Cellular: netInfo{
			Fwmark: cellMark,
			Bound:  cellMark != dualNetworkMarkNone,
			Active: GetNetworkState() == NetworkState4G || GetNetworkState() == NetworkState5G || GetNetworkState() == NetworkStateCellular,
		},
	}

	// 附带当前生效网络与最近记录的 RTT 样例（最多列几个 provider，避免超大响应）。
	globalDualNetworkLatency.mu.Lock()
	count := 0
	for _, e := range globalDualNetworkLatency.entries {
		if count >= 8 {
			break
		}
		out.Providers = append(out.Providers, e.provider)
		count++
	}
	globalDualNetworkLatency.mu.Unlock()

	data, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(data)
}
