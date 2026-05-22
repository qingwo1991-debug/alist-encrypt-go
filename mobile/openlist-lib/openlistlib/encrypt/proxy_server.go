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

// ProxyServer 加密代理服务器
type ProxyServer struct {
	config              *ProxyConfig
	httpClient          *http.Client
	probeClient         *http.Client
	streamClient        *http.Client
	transport           *http.Transport
	h2cTransport        *http2.Transport // H2C Transport (如果启用)
	server              *http.Server
	running             bool
	mutex               sync.RWMutex
	fileCache           *shardedAnyMap
	fileCacheCount      int64 // 缓存条目计数
	redirectCache       *shardedAnyMap
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
	cleanupTicker       *time.Ticker
	cleanupDone         chan struct{}
	localStore          *localStore
	metaSyncDone        chan struct{}
	metaSyncWG          sync.WaitGroup
	upstreamMu          sync.RWMutex
	upstreamDownAt      time.Time
	upstreamError       string
	upstreamFailures    int
	prefetchRecent      *shardedAnyMap // dirPath -> time.Time
	webdavNegativeMu    sync.Mutex
	webdavNegativeCache map[string]time.Time // path -> expireAt
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
}

func (p *ProxyServer) ensureRuntimeCaches() {
	if p == nil {
		return
	}
	if p.fileCache == nil {
		p.fileCache = newShardedAnyMap(cacheShardCount)
	}
	if p.redirectCache == nil {
		p.redirectCache = newShardedAnyMap(cacheShardCount)
	}
	if p.prefetchRecent == nil {
		p.prefetchRecent = newShardedAnyMap(cacheShardCount)
	}
	if p.webdavNegativeCache == nil {
		p.webdavNegativeCache = make(map[string]time.Time)
	}
}

// NewProxyServer 创建代理服务器
func NewProxyServer(config *ProxyConfig) (*ProxyServer, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
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
		streamBufferSize = effectiveKB * 1024
	}

	upstreamTimeout := time.Duration(clampSeconds(config.UpstreamTimeoutSeconds, 15, 2, 120)) * time.Second
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
		// 连接建立优化
		DialContext: (&net.Dialer{
			Timeout:   upstreamTimeout,
			KeepAlive: 60 * time.Second, // TCP KeepAlive，防止连接被中间设备断开
		}).DialContext,
	}

	// 配置 HTTP/2 over TLS 支持
	if err := http2.ConfigureTransport(transport); err != nil {
		log.Warnf("[%s] Failed to configure HTTP/2: %v, falling back to HTTP/1.1", internal.TagServer, err)
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
		streamClient.Transport = transport
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
		config:             config,
		transport:          transport,
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
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running {
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
	mux.HandleFunc("/api/encrypt/restart", p.handleRestart)
	mux.HandleFunc("/public/sync-stats.html", p.handleSyncStatsPage)
	mux.HandleFunc("/api/play/resolve", internal.WrapHandler(p.handlePlayResolve))
	mux.HandleFunc("/api/play/stream/", internal.WrapHandler(p.handlePlayStream))
	mux.HandleFunc("/api/play/stats", internal.WrapHandler(p.handlePlayStats))
	// 文件操作相关 - 包装以支持全链路追踪
	mux.HandleFunc("/redirect/", internal.WrapHandler(p.handleRedirect))
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
	mux.HandleFunc("/d/", internal.WrapHandler(p.handleDownload))
	mux.HandleFunc("/p/", internal.WrapHandler(p.handleDownload))
	mux.HandleFunc("/dav/", internal.WrapHandler(p.handleWebDAV))
	mux.HandleFunc("/dav", internal.WrapHandler(p.handleWebDAV))
	mux.HandleFunc("/dav2/", internal.WrapHandler(p.handleWebDAVV2))
	mux.HandleFunc("/dav2", internal.WrapHandler(p.handleWebDAVV2))
	// 根路径：直接代理到 OpenList (Alist)
	mux.HandleFunc("/", p.handleRoot)

	p.server = &http.Server{
		Addr:              fmt.Sprintf(":%d", p.config.ProxyPort),
		Handler:           internal.TraceMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second, // 防慢连接 header 攻击
		ReadTimeout:       0,                // 上传/流式场景允许长时间读 body
		WriteTimeout:      0,                // 下载流允许长连接写出
		IdleTimeout:       300 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	go func() {
		log.Infof("[%s] Encrypt proxy server starting on port %d", internal.TagServer, p.config.ProxyPort)
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("[%s] Proxy server error: %v", internal.TagServer, err)
		}
	}()

	p.running = true
	return nil
}

// Stop 停止代理服务器
func (p *ProxyServer) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.running {
		return nil
	}

	// 停止缓存清理协程
	p.stopCacheCleanup()
	p.stopRangeProbeLoop()
	p.stopDBExportSyncLoop()
	if p.sizeMapDone != nil {
		close(p.sizeMapDone)
		p.sizeMapDone = nil
	}

	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := p.server.Shutdown(ctx); err != nil {
			log.Errorf("[%s] Error shutting down proxy server: %v", internal.TagServer, err)
			return err
		}
	}

	// 关闭 HTTP Transport 的连接池，确保重启时没有残留连接
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}

	// 关闭 H2C Transport 的连接池
	if p.h2cTransport != nil {
		p.h2cTransport.CloseIdleConnections()
	}

	p.closeLocalStore()

	p.running = false
	log.Info("[" + internal.TagServer + "] Encrypt proxy server stopped")
	return nil
}

// UpdateConfig 更新配置（热更新）
func (p *ProxyServer) UpdateConfig(config *ProxyConfig) {
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

	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.config = config
	if p.config.StreamBufferKB > 0 {
		effectiveKB := clampStreamBufferKB(p.config.StreamBufferKB)
		p.config.StreamBufferKB = effectiveKB
		streamBufferSize = effectiveKB * 1024
	}
	p.rebuildEncryptPathIndex()
	if p.httpClient != nil {
		p.httpClient.Timeout = p.upstreamTimeout()
	}
	if p.probeClient != nil {
		p.probeClient.Timeout = p.probeTimeout()
	}
	if p.transport != nil {
		p.transport.ResponseHeaderTimeout = p.upstreamTimeout() + 2*time.Second
		p.transport.Proxy = newProxyResolver(config)
	}
	log.Infof("[%s] Proxy Config updated successfully", internal.TagConfig)
}
