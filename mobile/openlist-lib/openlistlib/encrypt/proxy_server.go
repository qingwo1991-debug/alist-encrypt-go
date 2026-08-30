package encrypt

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

// 流式传输优化常量

// ProxyServer is the main mobile proxy server.
//
// Lock ordering convention (acquire in this order to prevent deadlocks):
//   1. mutex (general state)
//   2. redirectCacheMu
//   3. prefetchRecentMu
//   4. sizeMapMu
//   5. rangeCompatMu
//   6. rangeProbeMu
//   7. upstreamMu
//   8. routingMu
//   9. webdavNegativeMu
//  10. uploadMetaMu
//  11. dbExportTokenMu
// Never hold two locks simultaneously unless following this order.

// ProxyServer 加密代理服务器
type ProxyServer struct {
	config          *ProxyConfig
	httpClient      *http.Client
	probeClient     *http.Client
	streamClient    *http.Client
	transport       *http.Transport
	streamTransport *http.Transport
	h2cTransport    *http2.Transport // H2C Transport (如果启用)
	server          *http.Server
	running         bool
	stopping        bool
	stopDone        chan struct{}
	stopErr         error
	mutex           sync.RWMutex
	// runtimeConfig is immutable after publication. p.config remains the
	// mutable working copy used by the legacy configuration handlers.
	runtimeConfig       *ProxyConfig
	fileCache           *shardedAnyMap
	fileCacheCount      int64 // 缓存条目计数
	redirectCacheMu     sync.Mutex
	redirectCache       *shardedAnyMap
	webdavListCacheMu   sync.Mutex
	webdavListCache     map[string]*webdavListCacheEntry
	sizeMapMu           sync.RWMutex
	sizeMap             map[string]SizeMapEntry
	sizeMapPath         string
	sizeMapDirty        bool
	sizeMapDone         chan struct{}
	rangeCompatMu       sync.RWMutex
	rangeCompat         map[string]time.Time
	rangeCompatFailures map[string]int
	rangeProbeMu        sync.Mutex
	rangeProbeTargets   map[string]rangeProbeTarget
	rangeProbeQueue     chan string
	rangeProbeDone      chan struct{}
	rangeProbeWG        sync.WaitGroup
	decryptedBlockCache *decryptedBlockCache
	cleanupTicker       *time.Ticker
	cleanupDone         chan struct{}
	localStore          *localStore
	metaSyncDone        chan struct{}
	metaSyncWG          sync.WaitGroup
	upstreamMu          sync.RWMutex
	upstreamDownAt      time.Time
	upstreamError       string
	upstreamFailures    int
	prefetchRecentMu    sync.Mutex
	prefetchRecent      *shardedAnyMap // dirPath -> time.Time
	webdavNegativeMu    sync.Mutex
	webdavNegativeCache map[string]time.Time // path -> expireAt
	storageCooldownMu   sync.Mutex
	storageCooldown     map[string]time.Time // storage prefix -> cooldown until
	redirectSizeMu      sync.Mutex
	redirectSizeCache   map[string]redirectSizeEntry // encryptedPath -> last confirmed size
	rawURLNegativeMu    sync.Mutex
	rawURLNegativeCache map[string]time.Time // signed URL -> expireAt
	prefixRules         []encryptPrefixRule
	routingMu           sync.RWMutex
	seenProviders       map[string]time.Time
	seenDrivers         map[string]time.Time
	storageDriverMap    map[string]string
	storageMapExpireAt  time.Time
	providerCatalog     map[string]string
	providerSourceMask  map[string]int
	catalogLastRefresh  time.Time
	catalogLastError    string
	catalogRefreshing   bool
	catalogNextRefresh  time.Time
	controlHTTPStats    upstreamHTTPStats
	probeHTTPStats      upstreamHTTPStats
	streamHTTPStats     upstreamHTTPStats
	playFirstCount      uint64
	strategySelector    *StrategySelector
	uploadMetaMu        sync.Mutex
	uploadMeta          map[string]uploadMetaEntry

	playbackActivityOnce sync.Once
	playbackActivity     *playbackActivityTracker
	playbackSessionOnce  sync.Once
	playbackSession      *playbackSessionTracker

	// DB export sync JWT token cache: reused across sync cycles to avoid
	// redundant login calls. Invalidated on 401 errors.
	dbExportTokenMu     sync.Mutex
	dbExportToken       string
	dbExportTokenExpiry time.Time
	runtimeCachesOnce   sync.Once
}

func (s *ProxyServer) ensureRuntimeCaches() {
	if s == nil {
		return
	}
	s.runtimeCachesOnce.Do(func() {
		if s.fileCache == nil {
			s.fileCache = newShardedAnyMap(cacheShardCount)
		}
		if s.redirectCache == nil {
			s.redirectCache = newShardedAnyMap(cacheShardCount)
		}
		if s.prefetchRecent == nil {
			s.prefetchRecent = newShardedAnyMap(cacheShardCount)
		}
		if s.webdavNegativeCache == nil {
			s.webdavNegativeCache = make(map[string]time.Time)
		}
		if s.storageCooldown == nil {
			s.storageCooldown = make(map[string]time.Time)
		}
		if s.redirectSizeCache == nil {
			s.redirectSizeCache = make(map[string]redirectSizeEntry)
		}
		if s.rawURLNegativeCache == nil {
			s.rawURLNegativeCache = make(map[string]time.Time)
		}
		if s.webdavListCache == nil {
			s.webdavListCache = make(map[string]*webdavListCacheEntry)
		}
	})
}

// cloneProxyConfig returns a detached configuration snapshot. ProxyConfig
// contains slices and pointers, so a shallow copy is not sufficient when the
// snapshot is used by long-running requests or transport callbacks.
func cloneProxyConfig(src *ProxyConfig) *ProxyConfig {
	if src == nil {
		return nil
	}
	dst := *src
	if len(src.EncryptPaths) > 0 {
		dst.EncryptPaths = make([]*EncryptPath, len(src.EncryptPaths))
		for i, rule := range src.EncryptPaths {
			if rule == nil {
				continue
			}
			clonedRule := *rule
			dst.EncryptPaths[i] = &clonedRule
		}
	}
	if len(src.ProviderRoutingRules) > 0 {
		dst.ProviderRoutingRules = make([]ProviderRoutingRule, len(src.ProviderRoutingRules))
		for i := range src.ProviderRoutingRules {
			dst.ProviderRoutingRules[i] = src.ProviderRoutingRules[i]
			dst.ProviderRoutingRules[i].MatchValues = append([]string(nil), src.ProviderRoutingRules[i].MatchValues...)
		}
	}
	dst.DebugModules = append([]string(nil), src.DebugModules...)
	return &dst
}

type proxyRuntimeSnapshot struct {
	config       *ProxyConfig
	httpClient   *http.Client
	probeClient  *http.Client
	streamClient *http.Client
}

// runtimeSnapshot publishes configuration and clients through the same lock.
// runtimeConfig and the clients are immutable after publication, so callers do
// not have to hold the server lock during I/O and the hot path does not need to
// deep-copy every routing rule for every request. Callers must treat config as
// read-only.
func (p *ProxyServer) runtimeSnapshot() proxyRuntimeSnapshot {
	if p == nil {
		return proxyRuntimeSnapshot{}
	}
	p.mutex.RLock()
	runtimeConfig := p.runtimeConfig
	if runtimeConfig == nil {
		// Keep manually constructed/zero-value servers usable in tests and
		// embedders. Normal servers publish an immutable runtimeConfig, so this
		// detached fallback has no cost on the request hot path.
		runtimeConfig = cloneProxyConfig(p.config)
	}
	snapshot := proxyRuntimeSnapshot{
		config:       runtimeConfig,
		httpClient:   p.httpClient,
		probeClient:  p.probeClient,
		streamClient: p.streamClient,
	}
	p.mutex.RUnlock()
	return snapshot
}

func (p *ProxyServer) clientSnapshot() proxyRuntimeSnapshot {
	if p == nil {
		return proxyRuntimeSnapshot{}
	}
	p.mutex.RLock()
	snapshot := proxyRuntimeSnapshot{
		httpClient:   p.httpClient,
		probeClient:  p.probeClient,
		streamClient: p.streamClient,
	}
	p.mutex.RUnlock()
	return snapshot
}

func (p *ProxyServer) configSnapshot() *ProxyConfig {
	if p == nil {
		return nil
	}
	p.mutex.RLock()
	config := cloneProxyConfig(p.config)
	p.mutex.RUnlock()
	return config
}

func (p *ProxyServer) httpClientSnapshot() *http.Client {
	if p == nil {
		return nil
	}
	p.mutex.RLock()
	client := p.httpClient
	p.mutex.RUnlock()
	return client
}

func (p *ProxyServer) probeClientSnapshot() *http.Client {
	if p == nil {
		return nil
	}
	p.mutex.RLock()
	client := p.probeClient
	p.mutex.RUnlock()
	return client
}

func (p *ProxyServer) streamClientSnapshot() *http.Client {
	if p == nil {
		return nil
	}
	p.mutex.RLock()
	client := p.streamClient
	p.mutex.RUnlock()
	return client
}

// NewProxyServer 创建代理服务器
func NewProxyServer(config *ProxyConfig) (*ProxyServer, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	config = cloneProxyConfig(config)
	applyLearningDefaults(config)

	// 编译路径正则表达式
	// 使用安全的通配符->正则转换：先 QuoteMeta 再恢复通配符
	wildcardToRegex := func(raw string) string {
		a := "__AST__"
		q := "__QST__"
		tmp := strings.ReplaceAll(raw, "*", a)
		tmp = strings.ReplaceAll(tmp, "?", q)
		tmp = regexp.QuoteMeta(tmp)
		tmp = strings.ReplaceAll(tmp, a, ".*")
		tmp = strings.ReplaceAll(tmp, q, ".")
		return tmp
	}

	for _, ep := range config.EncryptPaths {
		if ep.Path == "" {
			continue
		}
		ep.EncSuffix = NormalizeEncSuffix(ep.EncSuffix)
		raw := ep.Path
		if pref, ok := normalizeRulePrefix(raw); ok {
			ep.prefix = pref
		} else {
			ep.prefix = ""
		}
		// 处理以 /* 结尾的目录匹配
		if strings.HasSuffix(raw, "/*") {
			base := strings.TrimSuffix(raw, "/*")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("[%s] Init path %s -> regex pattern: %s", internal.TagConfig, ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("[%s] Invalid path pattern: %s, error: %v", internal.TagConfig, ep.Path, err)
			}
			continue
		}

		// 处理以 / 结尾的目录匹配（与 /* 类似，匹配目录及其子路径）
		if strings.HasSuffix(raw, "/") {
			base := strings.TrimSuffix(raw, "/")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("[%s] Init path %s -> regex pattern: %s", internal.TagConfig, ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("[%s] Invalid path pattern: %s, error: %v", internal.TagConfig, ep.Path, err)
			}
			continue
		}

		converted := wildcardToRegex(raw)
		var pattern string
		if strings.HasPrefix(raw, "^") {
			pattern = converted
		} else if strings.HasPrefix(raw, "/") {
			pattern = "^" + converted + "(/.*)?$"
		} else {
			pattern = "^/?" + converted + "(/.*)?$"
		}
		log.Infof("[%s] Init path %s -> regex pattern: %s", internal.TagConfig, ep.Path, pattern)
		if reg, err := regexp.Compile(pattern); err == nil {
			ep.regex = reg
		} else {
			log.Warnf("[%s] Invalid path pattern: %s, error: %v", internal.TagConfig, ep.Path, err)
		}
	}

	// ProbeOnDownload is controlled by configuration / frontend; do not override here.
	if config.StreamBufferKB > 0 {
		effectiveKB := clampStreamBufferKB(config.StreamBufferKB)
		config.StreamBufferKB = effectiveKB
		streamBufferSize.Store(int64(effectiveKB * 1024))
	}

	upstreamTimeout := time.Duration(clampSeconds(config.UpstreamTimeoutSeconds, 60, 5, 600)) * time.Second
	probeTimeout := time.Duration(clampSeconds(config.ProbeTimeoutSeconds, 5, 1, 30)) * time.Second

	proxyFunc := newProxyResolver(config)

	// 创建 Transport，支持 HTTP/2 over TLS
	transport := &http.Transport{
		Proxy:                 proxyFunc,
		MaxIdleConns:          200,               // 增加最大空闲连接
		MaxIdleConnsPerHost:   100,               // 增加每主机空闲连接（从50提升）
		MaxConnsPerHost:       200,               // 增加每主机最大连接（从100提升）
		IdleConnTimeout:       300 * time.Second, // 延长空闲超时（从120s提升到5分钟）
		DisableCompression:    true,              // 禁用压缩，减少 CPU 开销（视频流通常已压缩）
		ResponseHeaderTimeout: upstreamTimeout + 2*time.Second,
		ForceAttemptHTTP2:     true, // 启用 HTTP/2 (HTTPS)
		TLSClientConfig:       &tls.Config{},
	}
	// 连接建立优化：IPv4 优先（IPv6 出站被拒时回退 IPv4）+ TCP KeepAlive。
	baseDialer := &net.Dialer{
		Timeout:   upstreamTimeout,
		KeepAlive: 60 * time.Second, // TCP KeepAlive，防止连接被中间设备断开
	}
	upstreamDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return baseDialer.DialContext(ctx, network, addr)
	}
	// 双网络（可选）：若开关开启且拿到双 fwmark，DialContext 按 host 绑定网络。
	// 开关关闭时 newDualNetworkDialer 返回 base.DialContext，零行为变化。
	if dualDialer := newDualNetworkDialer(baseDialer); dualDialer != nil {
		upstreamDial = dualDialer
	}
	transport.DialContext = preferIPv4DialContext(upstreamDial)
	streamTransport := transport.Clone()
	// Limit only the wait for response headers. streamClient.Timeout remains
	// zero, so long-running video bodies are not capped by this deadline.
	streamTransport.ResponseHeaderTimeout = upstreamTimeout + 2*time.Second

	// 配置 HTTP/2 over TLS 支持
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Warnf("[%s] Failed to configure HTTP/2: %v, falling back to HTTP/1.1", internal.TagServer, err)
	}
	if err := http2.ConfigureTransport(streamTransport); err != nil {
		log.Warnf("[%s] Failed to configure stream HTTP/2: %v, falling back to HTTP/1.1", internal.TagServer, err)
	}

	var httpClient, probeClient, streamClient *http.Client
	var h2cTransport *http2.Transport

	if config.EnableH2C {
		log.Info("[" + internal.TagServer + "] H2C (HTTP/2 Cleartext) enabled for backend connections")
		h2cTransport = &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		}

		testClient := &http.Client{Timeout: 1200 * time.Millisecond, Transport: h2cTransport}
		testURL := fmt.Sprintf("http://%s:%d/ping", config.AlistHost, config.AlistPort)
		resp, err := testClient.Get(testURL)
		if err != nil {
			log.Warnf("[%s] H2C connection test failed quickly: %v, falling back to HTTP/1.1", internal.TagServer, err)
			h2cTransport = nil
		} else {
			resp.Body.Close()
			log.Info("[" + internal.TagServer + "] H2C connection test successful")
		}
	}

	httpClient = &http.Client{
		Timeout: upstreamTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	probeClient = &http.Client{
		Timeout: probeTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	streamClient = &http.Client{
		Timeout: 0,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if h2cTransport != nil {
		httpClient.Transport = h2cTransport
		probeClient.Transport = h2cTransport
		streamClient.Transport = h2cTransport
	} else {
		httpClient.Transport = transport
		probeClient.Transport = transport
		streamClient.Transport = streamTransport
	}

	selStore := NewMemoryStrategyStore()
	strategySelector, err := NewStrategySelector(
		config.ProbeStrategyFailureThreshold,
		config.ProbeStrategyStableThreshold,
		time.Duration(config.ProbeStrategyTTLMinutes)*time.Minute,
		selStore,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create strategy selector: %w", err)
	}

	server := &ProxyServer{
		config:             cloneProxyConfig(config),
		runtimeConfig:      config,
		transport:          transport,
		streamTransport:    streamTransport,
		h2cTransport:       h2cTransport,
		httpClient:         httpClient,
		probeClient:        probeClient,
		streamClient:       streamClient,
		strategySelector:   strategySelector,
		fileCache:          newShardedAnyMap(cacheShardCount),
		redirectCache:      newShardedAnyMap(cacheShardCount),
		prefetchRecent:     newShardedAnyMap(cacheShardCount),
		seenProviders:      make(map[string]time.Time),
		seenDrivers:        make(map[string]time.Time),
		storageDriverMap:   make(map[string]string),
		providerCatalog:    make(map[string]string),
		providerSourceMask: make(map[string]int),
		uploadMeta:         make(map[string]uploadMetaEntry),
		decryptedBlockCache: newDecryptedBlockCacheFromProxyConfig(config),
		cleanupDone:        make(chan struct{}),
		metaSyncDone:       make(chan struct{}),
	}
	httpClient.Transport = &instrumentedRoundTripper{base: httpClient.Transport, stats: &server.controlHTTPStats}
	probeClient.Transport = &instrumentedRoundTripper{base: probeClient.Transport, stats: &server.probeHTTPStats}
	streamClient.Transport = &instrumentedRoundTripper{base: streamClient.Transport, stats: &server.streamHTTPStats}
	server.rebuildEncryptPathIndex()

	// 启动缓存清理协程
	server.startCacheCleanup()
	server.initSizeMap()
	server.initLocalStore()
	server.initProviderCatalog()
	server.initRangeCompat()
	server.startRangeProbeLoop()
	server.startDBExportSyncLoop()

	return server, nil
}

// Start 启动代理服务器
func (p *ProxyServer) Start() error {
	if p == nil {
		return errors.New("proxy server is nil")
	}
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running || p.stopping {
		return errors.New("proxy server is already running")
	}

	mux := http.NewServeMux()

	// 路由配置 - 使用 WrapHandler 注入日志上下文实现全链路追踪
	mux.HandleFunc("/ping", p.handlePing)
	mux.HandleFunc("/healthz", p.handleHealthz)
	// 加密配置 API（供 App 前端的加密 tab 使用）
	mux.HandleFunc("/enc-api/getAlistConfig", p.handleConfig)
	mux.HandleFunc("/enc-api/saveAlistConfig", p.handleConfig)
	mux.HandleFunc("/enc-api/getStats", p.handleStats)
	mux.HandleFunc("/enc-api/getUserInfo", p.handleUserInfo)
	mux.HandleFunc("/enc-api/localState", p.handleLocalState)
	mux.HandleFunc("/enc-api/localExport", p.handleLocalExport)
	mux.HandleFunc("/enc-api/localImport", p.handleLocalImport)
	mux.HandleFunc("/api/encrypt/config", p.handleConfig)
	mux.HandleFunc("/api/encrypt/v2/config", p.handleConfigV2)
	mux.HandleFunc("/api/encrypt/v2/config/schema", p.handleConfigV2Schema)
	mux.HandleFunc("/api/encrypt/provider-routing-candidates", p.handleProviderRoutingCandidates)
	mux.HandleFunc("/api/encrypt/provider-routing-candidates/refresh", p.handleProviderRoutingCandidatesRefresh)
	mux.HandleFunc("/api/encrypt/stats", p.handleStats)
	mux.HandleFunc("/api/encrypt/v2/stats", p.handleStats)
	mux.HandleFunc("/api/encrypt/sync/overview", p.handleSyncOverview)
	mux.HandleFunc("/api/encrypt/localState", p.handleLocalState)
	mux.HandleFunc("/api/encrypt/localExport", p.handleLocalExport)
	mux.HandleFunc("/api/encrypt/localImport", p.handleLocalImport)
	mux.HandleFunc("/api/encrypt/exportStats", p.handleExportStats)
	mux.HandleFunc("/api/encrypt/restart", p.handleRestart)
	mux.HandleFunc("/public/sync-stats.html", p.handleSyncStatsPage)
	mux.HandleFunc("/api/play/resolve", internal.WrapHandler(p.handlePlayResolve))
	mux.HandleFunc("/api/play/stream/", internal.WrapHandler(p.withPlaybackActivity(p.handlePlayStream)))
	mux.HandleFunc("/api/play/stats", internal.WrapHandler(p.handlePlayStats))
	mux.HandleFunc("/api/play/activity", p.handlePlaybackActivity)
	// 文件操作相关 - 包装以支持全链路追踪
	mux.HandleFunc("/redirect/", internal.WrapHandler(p.withPlaybackActivity(p.handleRedirect)))
	mux.HandleFunc("/api/fs/list", internal.WrapHandler(p.handleFsList))
	mux.HandleFunc("/api/fs/get", internal.WrapHandler(p.handleFsGet))
	mux.HandleFunc("/api/fs/link", internal.WrapHandler(p.handleFsLink))
	mux.HandleFunc("/api/fs/put", internal.WrapHandler(p.handleFsPut))
	mux.HandleFunc("/api/fs/put-back", internal.WrapHandler(p.handleFsPutBack))
	mux.HandleFunc("/api/fs/remove", internal.WrapHandler(p.handleFsRemove))
	mux.HandleFunc("/api/fs/move", internal.WrapHandler(p.handleFsMove))
	mux.HandleFunc("/api/fs/copy", internal.WrapHandler(p.handleFsCopy))
	mux.HandleFunc("/api/fs/rename", internal.WrapHandler(p.handleFsRename))
	// 下载和 WebDAV - 包装以支持全链路追踪
	mux.HandleFunc("/d/", internal.WrapHandler(p.withPlaybackActivity(p.handleDownload)))
	mux.HandleFunc("/p/", internal.WrapHandler(p.withPlaybackActivity(p.handleDownload)))
	mux.HandleFunc("/dav/", internal.WrapHandler(p.withPlaybackActivity(p.handleWebDAV)))
	mux.HandleFunc("/dav", internal.WrapHandler(p.withPlaybackActivity(p.handleWebDAV)))
	mux.HandleFunc("/dav2/", internal.WrapHandler(p.withPlaybackActivity(p.handleWebDAVV2)))
	mux.HandleFunc("/dav2", internal.WrapHandler(p.withPlaybackActivity(p.handleWebDAVV2)))
	// 管理后台（enc-webui）：与 docker 版本对齐，挂在 /index 和 /public 下，
	// 根路径 / 留给 OpenList 文件列表（透传到 5244）。
	mux.HandleFunc("/index", p.handleEncWebUIIndex)
	if encFS := encWebUIFileServer(); encFS != nil {
		mux.Handle("/public/", http.StripPrefix("/public/", encFS))
	}
	// 根路径：直接代理到 OpenList (Alist)
	mux.HandleFunc("/", p.handleRoot)

	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", p.config.ProxyPort),
		Handler:           internal.TraceMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second, // 防慢连接 header 攻击
		ReadTimeout:       0,                // 上传/流式场景允许长时间读 body
		WriteTimeout:      0,                // 下载流允许长连接写出
		IdleTimeout:       300 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", server.Addr, err)
	}

	p.server = server
	p.running = true
	proxyPort := p.config.ProxyPort
	prewarmConfiguredV2KeysAsync(p.config)
	warmEncryptedRootDirsAsync(p, p.config)
	go func() {
		log.Infof("[%s] Encrypt proxy server starting on port %d", internal.TagServer, proxyPort)
		err := server.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("[%s] Proxy server error: %v", internal.TagServer, err)
		}
		p.mutex.Lock()
		if p.server == server {
			p.running = false
		}
		p.mutex.Unlock()
	}()

	return nil
}

// Stop 停止代理服务器
func (p *ProxyServer) Stop() error {
	if p == nil {
		return nil
	}
	p.mutex.Lock()
	if p.stopping {
		done := p.stopDone
		p.mutex.Unlock()
		if done != nil {
			<-done
		}
		p.mutex.RLock()
		err := p.stopErr
		p.mutex.RUnlock()
		return err
	}

	if !p.running {
		p.mutex.Unlock()
		return nil
	}
	p.stopping = true
	p.stopErr = nil
	p.stopDone = make(chan struct{})
	done := p.stopDone
	server := p.server
	transport := p.transport
	streamTransport := p.streamTransport
	h2cTransport := p.h2cTransport
	p.mutex.Unlock()

	// Never hold p.mutex while waiting for background workers or active HTTP
	// handlers. Both paths can legitimately take a runtime/config snapshot.
	p.stopCacheCleanup()
	p.stopRangeProbeLoop()
	p.stopDBExportSyncLoop()
	if p.sizeMapDone != nil {
		close(p.sizeMapDone)
		p.sizeMapDone = nil
	}

	var stopErr error
	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			log.Errorf("[%s] Error shutting down proxy server: %v", internal.TagServer, err)
			stopErr = err
		}
		cancel()
	}

	// 关闭 HTTP Transport 的连接池，确保重启时没有残留连接
	if transport != nil {
		transport.CloseIdleConnections()
	}
	if streamTransport != nil && streamTransport != transport {
		streamTransport.CloseIdleConnections()
	}

	// 关闭 H2C Transport 的连接池
	if h2cTransport != nil {
		h2cTransport.CloseIdleConnections()
	}

	p.closeLocalStore()

	p.mutex.Lock()
	if p.server == server {
		p.server = nil
		p.running = false
	}
	p.stopping = false
	p.stopErr = stopErr
	close(done)
	p.mutex.Unlock()
	log.Info("[" + internal.TagServer + "] Encrypt proxy server stopped")
	return stopErr
}

// UpdateConfig 更新配置（热更新）
func (p *ProxyServer) UpdateConfig(config *ProxyConfig) {
	if p == nil || config == nil {
		return
	}
	config = cloneProxyConfig(config)
	// Compile regex BEFORE locking to avoid blocking reads too long?
	// Or just do it all under lock but ensure assignment is last.
	applyLearningDefaults(config)

	log.Infof("[%s] Updating Proxy Config with %d paths", internal.TagConfig, len(config.EncryptPaths))

	// Re-compile regex first using the same safe wildcard->regex conversion as NewProxyServer
	wildcardToRegex := func(raw string) string {
		a := "__AST__"
		q := "__QST__"
		tmp := strings.ReplaceAll(raw, "*", a)
		tmp = strings.ReplaceAll(tmp, "?", q)
		tmp = regexp.QuoteMeta(tmp)
		tmp = strings.ReplaceAll(tmp, a, ".*")
		tmp = strings.ReplaceAll(tmp, q, ".")
		return tmp
	}

	for _, ep := range config.EncryptPaths {
		log.Infof("[%s] Compiling regex for path: %s", internal.TagConfig, ep.Path)
		if ep.Path == "" {
			continue
		}
		ep.EncSuffix = NormalizeEncSuffix(ep.EncSuffix)
		raw := ep.Path
		if pref, ok := normalizeRulePrefix(raw); ok {
			ep.prefix = pref
		} else {
			ep.prefix = ""
		}
		// 处理以 /* 结尾的目录匹配
		if strings.HasSuffix(raw, "/*") {
			base := strings.TrimSuffix(raw, "/*")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("[%s] Path %s -> regex pattern: %s", internal.TagConfig, ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("[%s] Invalid path pattern update: %s, error: %v", internal.TagConfig, ep.Path, err)
			}
			continue
		}
		// 处理以 / 结尾的目录匹配（与 NewProxyServer 保持一致）
		if strings.HasSuffix(raw, "/") {
			base := strings.TrimSuffix(raw, "/")
			converted := wildcardToRegex(base)
			var pattern string
			if strings.HasPrefix(base, "/") {
				pattern = "^" + converted + "(/.*)?$"
			} else {
				pattern = "^/?" + converted + "(/.*)?$"
			}
			log.Infof("[%s] Path %s -> regex pattern: %s", internal.TagConfig, ep.Path, pattern)
			if reg, err := regexp.Compile(pattern); err == nil {
				ep.regex = reg
			} else {
				log.Warnf("[%s] Invalid path pattern update: %s, error: %v", internal.TagConfig, ep.Path, err)
			}
			continue
		}

		converted := wildcardToRegex(raw)
		var pattern string
		if strings.HasPrefix(raw, "^") {
			pattern = converted
		} else if strings.HasPrefix(raw, "/") {
			pattern = "^" + converted + "(/.*)?$"
		} else {
			pattern = "^/?" + converted + "(/.*)?$"
		}
		log.Infof("[%s] Path %s -> regex pattern: %s", internal.TagConfig, ep.Path, pattern)
		if reg, err := regexp.Compile(pattern); err == nil {
			ep.regex = reg
		} else {
			log.Warnf("[%s] Invalid path pattern update: %s, error: %v", internal.TagConfig, ep.Path, err)
		}
	}

	if config.StreamBufferKB > 0 {
		effectiveKB := clampStreamBufferKB(config.StreamBufferKB)
		config.StreamBufferKB = effectiveKB
		streamBufferSize.Store(int64(effectiveKB * 1024))
	}
	workingConfig := cloneProxyConfig(config)

	p.mutex.Lock()
	if p.stopping {
		p.mutex.Unlock()
		return
	}
	p.config = workingConfig
	p.runtimeConfig = config
	p.rebuildEncryptPathIndex()

	// http.Client and http.Transport configuration must not be mutated after
	// requests have started. Build fresh transports/clients and atomically
	// publish them; in-flight requests continue safely on the previous runtime.
	oldTransport := p.transport
	oldStreamTransport := p.streamTransport
	transport := oldTransport
	if oldTransport != nil {
		transport = oldTransport.Clone()
		transport.ResponseHeaderTimeout = time.Duration(clampSeconds(config.UpstreamTimeoutSeconds, 60, 5, 600))*time.Second + 2*time.Second
		transport.Proxy = newProxyResolver(config)
		baseDialer := &net.Dialer{
			Timeout:   time.Duration(clampSeconds(config.UpstreamTimeoutSeconds, 60, 5, 600)) * time.Second,
			KeepAlive: 60 * time.Second,
		}
		upstreamDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return baseDialer.DialContext(ctx, network, addr)
		}
		if dualDialer := newDualNetworkDialer(baseDialer); dualDialer != nil {
			upstreamDial = dualDialer
		}
		transport.DialContext = preferIPv4DialContext(upstreamDial)
	}
	streamTransport := oldStreamTransport
	if oldStreamTransport != nil {
		streamTransport = oldStreamTransport.Clone()
		streamTransport.ResponseHeaderTimeout = time.Duration(clampSeconds(config.UpstreamTimeoutSeconds, 60, 5, 600))*time.Second + 2*time.Second
		streamTransport.Proxy = newProxyResolver(config)
	}

	controlBase := http.RoundTripper(transport)
	probeBase := http.RoundTripper(transport)
	streamBase := http.RoundTripper(streamTransport)
	if p.h2cTransport != nil {
		controlBase = p.h2cTransport
		probeBase = p.h2cTransport
		streamBase = p.h2cTransport
	}
	noRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	p.httpClient = &http.Client{
		Timeout:       time.Duration(clampSeconds(config.UpstreamTimeoutSeconds, 60, 5, 600)) * time.Second,
		CheckRedirect: noRedirect,
		Transport:     &instrumentedRoundTripper{base: controlBase, stats: &p.controlHTTPStats},
	}
	p.probeClient = &http.Client{
		Timeout:       time.Duration(clampSeconds(config.ProbeTimeoutSeconds, 5, 1, 30)) * time.Second,
		CheckRedirect: noRedirect,
		Transport:     &instrumentedRoundTripper{base: probeBase, stats: &p.probeHTTPStats},
	}
	p.streamClient = &http.Client{
		Timeout:       0,
		CheckRedirect: noRedirect,
		Transport:     &instrumentedRoundTripper{base: streamBase, stats: &p.streamHTTPStats},
	}
	p.transport = transport
	p.streamTransport = streamTransport
	p.mutex.Unlock()

	if p.IsRunning() {
		prewarmConfiguredV2KeysAsync(workingConfig)
	}
	if oldTransport != nil && oldTransport != transport {
		oldTransport.CloseIdleConnections()
	}
	if oldStreamTransport != nil && oldStreamTransport != streamTransport {
		oldStreamTransport.CloseIdleConnections()
	}
	log.Infof("[%s] Proxy Config updated successfully", internal.TagConfig)
}
