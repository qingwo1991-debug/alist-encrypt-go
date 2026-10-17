package server

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/internal/storage/mysqlstore"
)

// Server represents the HTTP/2 server
type Server struct {
	cfg                *config.Config
	store              *storage.Store
	mysqlStore         *mysqlstore.Store
	engine             *gin.Engine
	httpServer         *http.Server
	httpsServer        *http.Server
	unixServer         *http.Server
	streamProxy        *proxy.StreamProxy
	userDAO            *dao.UserDAO
	fileDAO            *dao.FileDAO
	passwdDAO          *dao.PasswdDAO
	proxyHandler       *handler.ProxyHandler
	alistHandler       *handler.AlistHandler
	webdavHandler      *handler.WebDAVHandler
	foreground         *handler.ForegroundTracker
	probeScheduler     *handler.ProbeScheduler
	probeCancel        context.CancelFunc
	probeWG            sync.WaitGroup
	statsExportHandler *handler.StatsExportHandler
	statsShutdown      func() // 停服前冲刷统计（recorder.FlushSessions + store.Stop）
	rangeCompatStore   proxy.RangeCompatStore
	backups            *backupOwner
	shutdownOnce       sync.Once
	shutdownErr        error
	lifecycleMu        sync.Mutex
	started            bool
	stopping           bool
	sealedSignal       chan struct{}
	prepareWG          sync.WaitGroup
	serveWG            sync.WaitGroup
	requestWG          sync.WaitGroup
	listeners          []net.Listener
	listenFactory      func(string, string) (net.Listener, error)
	requestContext     context.Context
	requestCancel      context.CancelFunc
	connections        map[net.Conn]http.ConnState
}

// New creates a new server instance
func New(cfg *config.Config) (*Server, error) {
	// When MySQL is explicitly configured it is the authoritative persistence
	// backend. Starting with a silent BoltDB fallback would split runtime state
	// and make the failure easy to miss.
	mysqlStore, mysqlErr := mysqlstore.NewStore(cfg)
	if mysqlErr != nil {
		return nil, fmt.Errorf("failed to initialize MySQL store: %w", mysqlErr)
	}

	// BoltDB is always created for users/passwd/config (minimal, always needed).
	store, err := storage.NewStore(cfg.DataDir)
	if err != nil {
		if mysqlStore != nil {
			_ = mysqlStore.Close()
		}
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	backups, err := newBackupOwner(store, cfg.DataDir)
	if err != nil {
		_ = store.Close()
		if mysqlStore != nil {
			_ = mysqlStore.Close()
		}
		return nil, fmt.Errorf("failed to initialize backup owner: %w", err)
	}

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	s := &Server{
		cfg:         cfg,
		store:       store,
		engine:      gin.New(),
		streamProxy: proxy.NewStreamProxy(cfg),
		userDAO:     dao.NewUserDAO(store),
		fileDAO:     dao.NewFileDAO(store, cfg),
		passwdDAO:   dao.NewPasswdDAO(store, cfg),
		mysqlStore:  mysqlStore,
		backups:     backups,
	}

	// If MySQL is available, hook it into FileDAO for file metadata persistence.
	if mysqlStore != nil {
		s.fileDAO.SetFileMetaWriter(handler.NewMySQLFileMetaWriter(mysqlStore))
	}

	// Ensure default admin user exists
	if err := s.userDAO.EnsureDefaultUser(); err != nil {
		log.Warn().Err(err).Msg("Failed to ensure default user")
	}

	s.setupRoutes()
	return s, nil
}

func (s *Server) setupRoutes() {
	r := s.engine

	// Middleware
	r.Use(gin.Recovery())
	r.Use(TraceMiddleware())
	r.Use(LoggerMiddleware())
	r.Use(CORSMiddleware())
	r.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedPaths([]string{"/dav"})))

	// Force HTTPS redirect if enabled
	scheme := s.cfg.SchemeSnapshot()
	if scheme.ForceHTTPS && scheme.HTTPSPort > 0 && scheme.CertFile != "" && scheme.KeyFile != "" {
		r.Use(ForceHTTPSMiddleware(scheme.HTTPSPort))
	}

	// Health check endpoints (no auth required)
	r.GET("/health", HealthHandler)
	r.GET("/ready", ReadyHandler)

	s.setupWebUIRoutes(r)

	// Create handlers
	apiHandler, proxyHandler, alistHandler, webdavHandler, statsHandler := s.createHandlers()

	// Register actual media demand before handlers perform any upstream lookup.
	r.Use(s.foregroundPlaybackMiddleware())

	// Register all routes
	s.registerRoutes(r, apiHandler, proxyHandler, alistHandler, webdavHandler, statsHandler)

	// Start startup probe goroutine if enabled
	s.startStartupProbe(webdavHandler)
}

// createHandlers initializes all request handlers.
func (s *Server) createHandlers() (*handler.APIHandler, *handler.ProxyHandler, *handler.AlistHandler, *handler.WebDAVHandler, *handler.StatsHandler) {
	apiHandler := handler.NewAPIHandler(s.cfg, s.userDAO, s.passwdDAO, s.fileDAO, s.mysqlStore)
	strategyStore := handler.StrategyStore(handler.NewMemoryStrategyStore())
	var metaStore handler.FileMetaStore

	// Initialize range compatibility store: MySQL > file > memory. The active
	// store is retained on the Server so Shutdown can drain its buffered writes.
	var rangeStore proxy.RangeCompatStore
	if s.mysqlStore != nil {
		strategyStore = handler.NewMySQLStrategyStore(s.mysqlStore)
		metaStore = handler.NewMySQLFileMetaStore(s.mysqlStore)
		rangeStore = handler.NewMySQLRangeCompatStore(s.mysqlStore)
		s.streamProxy.SetRangeCompatStore(rangeStore)
		if err := migrateStrategyStore(s.cfg, strategyStore); err != nil {
			log.Warn().Err(err).Msg("Failed to migrate strategy store JSON")
		}
	} else {
		if fileRange := s.initRangeCompatStore(); fileRange != nil {
			rangeStore = fileRange
			s.streamProxy.SetRangeCompatStore(rangeStore)
		}
	}
	s.rangeCompatStore = rangeStore
	strategySelector, err := handler.NewStrategySelector(s.cfg, strategyStore)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize strategy selector")
		strategySelector, _ = handler.NewStrategySelector(s.cfg, handler.NewMemoryStrategyStore())
	}
	// 进程级唯一的 Metadata/Size 解析器：proxy/webdav/后台 probe 共用同一份
	// 探测状态（host RTT、熔断、provider meta 冲突、hot cache、并发预算），
	// 避免三套相互独立的 HEAD/Range 探测与重复请求。
	sizeResolver := handler.NewFileSizeResolver(s.cfg, s.fileDAO, metaStore, 20, handler.MinMetaSize(s.cfg), handler.RedirectMaxHops(s.cfg))
	probeScheduler := handler.NewProbeScheduler(s.cfg, s.fileDAO, metaStore, s.streamProxy, s.store, sizeResolver)
	s.probeScheduler = probeScheduler
	s.foreground = handler.NewForegroundTracker(func() bool {
		return s.cfg.AlistServerSnapshot().PlaybackProfile == config.PlaybackProfileTrustedLocal
	})
	probeScheduler.SetForegroundTracker(s.foreground)
	proxyHandler := handler.NewProxyHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO, strategySelector, metaStore)
	proxyHandler.SetProbeScheduler(probeScheduler)
	proxyHandler.SetSizeResolver(sizeResolver)
	alistHandler := handler.NewAlistHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO, proxyHandler, metaStore, probeScheduler)
	s.alistHandler = alistHandler
	alistHandler.SetForegroundTracker(s.foreground)
	var dirSyncStore handler.DirSyncStore
	if s.mysqlStore != nil {
		dirSyncStore = handler.NewMySQLDirSyncStore(s.mysqlStore)
	} else {
		dirSyncStore = handler.NewBoltDirSyncStore(s.store)
	}
	alistHandler.SetDirSyncStore(dirSyncStore)
	alistHandler.StartDirSyncLoop()
	webdavHandler := handler.NewWebDAVHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO, strategySelector, metaStore, proxyHandler)
	webdavHandler.SetForegroundTracker(s.foreground)
	webdavHandler.SetProbeScheduler(probeScheduler)
	webdavHandler.SetSizeResolver(sizeResolver)
	// WebDAV shares the same dir-sync snapshot store as the HTTP fs/list path so
	// directory listings on whitelisted encrypted paths read the cache too.
	webdavHandler.SetDirSyncStore(dirSyncStore)
	// 播放/删除统计：BoltDB stats bucket + 记录器接入三个 handler。
	statsStore := handler.NewStatsStore(s.store)
	statsRecorder := handler.NewBoltStatsRecorder(statsStore)
	proxyHandler.SetStatsRecorder(statsRecorder)
	webdavHandler.SetStatsRecorder(statsRecorder)
	alistHandler.SetStatsRecorder(statsRecorder)
	s.statsExportHandler = handler.NewStatsExportHandler(s.cfg, statsStore)
	s.statsExportHandler.SetFlusher(statsRecorder.FlushSessions)
	statsHandler := handler.NewStatsHandler(s.cfg, s.fileDAO, alistHandler, proxyHandler, webdavHandler, s.streamProxy, startTime)
	statsHandler.SetStatsStore(statsStore)
	statsHandler.SetStatsFlusher(statsRecorder.FlushSessions)
	// 停服前：先落库进行中的播放会话，再停止后台 writer 并冲刷排队中的统计事件。
	s.statsShutdown = func() {
		statsRecorder.FlushSessions()
		statsStore.Stop()
	}
	s.proxyHandler = proxyHandler
	s.webdavHandler = webdavHandler

	return apiHandler, proxyHandler, alistHandler, webdavHandler, statsHandler
}

// registerRoutes registers all HTTP routes on the gin engine.
func (s *Server) registerRoutes(r *gin.Engine, apiHandler *handler.APIHandler, proxyHandler *handler.ProxyHandler, alistHandler *handler.AlistHandler, webdavHandler *handler.WebDAVHandler, statsHandler *handler.StatsHandler) {
	// Handle frontend error collection API
	r.POST("/integration-front/errorCollection/insert", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok"})
	})

	// /enc-api/* routes - Authentication and config management
	encAPI := r.Group("/enc-api")
	{
		// Public routes (no auth required)
		encAPI.POST("/login", newLoginAttemptLimiter().middleware(), ginWrap(apiHandler.Login))
		encAPI.Any("/getBuildInfo", ginWrap(apiHandler.GetBuildInfo))

		// Protected routes (auth required)
		protected := encAPI.Group("")
		protected.Use(AuthMiddleware(s.cfg.JWTSecret, s.cfg.JWTExpire))
		s.registerBackupRoutes(protected)
		{
			protected.POST("/playbackInterest", playbackInterestHandler(s.cfg, s.fileDAO, s.probeScheduler))
			protected.Any("/getUserInfo", ginWrap(apiHandler.GetUserInfo))
			protected.Any("/updatePasswd", ginWrap(apiHandler.UpdatePasswd))
			protected.Any("/updateUsername", ginWrap(apiHandler.UpdateUsername))
			protected.Any("/getAlistConfig", ginWrap(apiHandler.GetAlistConfig))
			protected.Any("/saveAlistConfig", ginWrap(apiHandler.SaveAlistConfig))
			protected.Any("/validateScanConfig", ginWrap(apiHandler.ValidateScanConfig))
			protected.Any("/getWebdavonfig", ginWrap(apiHandler.GetWebdavConfig)) // Typo matches original
			protected.Any("/getWebdavConfig", ginWrap(apiHandler.GetWebdavConfig))
			protected.Any("/saveWebdavConfig", ginWrap(apiHandler.SaveWebdavConfig))
			protected.Any("/updateWebdavConfig", ginWrap(apiHandler.UpdateWebdavConfig))
			protected.Any("/delWebdavConfig", ginWrap(apiHandler.DelWebdavConfig))
			protected.Any("/encodeFoldName", ginWrap(apiHandler.EncodeFoldName))
			protected.Any("/decodeFoldName", ginWrap(apiHandler.DecodeFoldName))
			protected.Any("/getSchemeConfig", ginWrap(apiHandler.GetSchemeConfig))
			protected.Any("/saveSchemeConfig", ginWrap(apiHandler.SaveSchemeConfig))
			protected.Any("/exportFileMeta", ginWrap(apiHandler.ExportFileMeta))
			protected.Any("/exportStrategy", ginWrap(apiHandler.ExportStrategy))
			protected.Any("/exportRangeCompat", ginWrap(apiHandler.ExportRangeCompat))
			protected.Any("/cleanupLegacyBoltDB", ginWrap(apiHandler.CleanupLegacyBoltDB))
			protected.Any("/getStats", ginWrap(statsHandler.HandleStats))
			protected.Any("/getPlaybackStats", ginWrap(statsHandler.HandlePlaybackStats))
			protected.Any("/clearPlaybackStats", ginWrap(statsHandler.HandleClearPlaybackStats))
			protected.Any("/getProxyDomainDictionary", ginWrap(apiHandler.GetProxyDomainDictionary))
			protected.Any("/refreshProxyDomainDictionary", ginWrap(apiHandler.RefreshProxyDomainDictionary))
			protected.Any("/getProxyRoutingConfig", ginWrap(apiHandler.GetProxyRoutingConfig))
			protected.Any("/saveProxyRoutingConfig", ginWrap(apiHandler.SaveProxyRoutingConfig))
			// Local file encrypt/decrypt with progress tracking
			protected.Any("/checkFilePath", ginWrap(handler.HandleCheckFilePath))
			protected.Any("/encryptFile", ginWrap(handler.HandleEncryptFile))
			protected.Any("/encryptStatus/*taskId", ginWrap(handler.HandleEncryptTaskStatus))
			protected.Any("/encryptTasks", ginWrap(handler.HandleEncryptTaskList))
		}
	}

	// /redirect/:key - 302 redirect decryption
	// No JWT auth required: the redirect key is an MD5 hash of url:size:nanosecond,
	// effectively a 128-bit unpredictable token with 72h expiry. Browser video
	// players (Artplayer etc.) cannot include JWT headers when fetching media,
	// so requiring auth here would block all playback in web UI.
	r.Any("/redirect/:key", ginWrap(proxyHandler.HandleRedirect))

	// /api/encrypt/exportStats - 播放/删除统计导出。
	// 无 JWT：用独立的 stats_password 鉴权（query ?password= 或 X-Stats-Password 头）。
	// 未配置 StatsPassword 时返回 404（功能关闭）。
	if s.statsExportHandler != nil {
		r.GET("/api/encrypt/exportStats", ginWrap(s.statsExportHandler.ExportStats))
	}

	// /debug/* - optional troubleshooting endpoints (recent logs + runtime
	// status). Only registered when cfg.Debug.Enabled is true; an optional
	// X-Debug-Token / Bearer token from cfg.Debug.Token is enforced when set.
	if s.cfg.DebugEnabled() {
		debugHandler := handler.NewDebugHandler(s.cfg, s.mysqlStore)
		debugGroup := r.Group("/debug")
		if token := s.cfg.DebugToken(); token != "" {
			debugGroup.Use(debugTokenMiddleware(token))
		}
		debugGroup.GET("/status", debugHandler.ServeStatus)
		debugGroup.GET("/logs", debugHandler.ServeLogs)
	}

	// /dav/* - WebDAV proxy (supports all WebDAV methods: PROPFIND, MKCOL, etc.)
	davGroup := r.Group("/dav")
	{
		davGroup.Any("", ginWrap(webdavHandler.Handle))
		davGroup.Any("/*path", ginWrap(webdavHandler.Handle))
		// Explicitly handle WebDAV methods
		davGroup.Handle("PROPFIND", "", ginWrap(webdavHandler.Handle))
		davGroup.Handle("PROPFIND", "/*path", ginWrap(webdavHandler.Handle))
		davGroup.Handle("PROPPATCH", "/*path", ginWrap(webdavHandler.Handle))
		davGroup.Handle("MKCOL", "/*path", ginWrap(webdavHandler.Handle))
		davGroup.Handle("COPY", "/*path", ginWrap(webdavHandler.Handle))
		davGroup.Handle("MOVE", "/*path", ginWrap(webdavHandler.Handle))
		davGroup.Handle("LOCK", "/*path", ginWrap(webdavHandler.Handle))
		davGroup.Handle("UNLOCK", "/*path", ginWrap(webdavHandler.Handle))
	}

	// /d/* and /p/* - File download with decryption (GET + HEAD)
	r.GET("/d/*path", ginWrap(proxyHandler.HandleDownload))
	r.HEAD("/d/*path", ginWrap(proxyHandler.HandleDownload))
	r.GET("/p/*path", ginWrap(proxyHandler.HandleDownload))
	r.HEAD("/p/*path", ginWrap(proxyHandler.HandleDownload))

	// /api/fs/* - Alist API interception
	r.POST("/api/fs/get", ginWrap(alistHandler.HandleFsGet))
	r.POST("/api/fs/link", ginWrap(alistHandler.HandleFsLink))
	r.POST("/api/fs/list", ginWrap(alistHandler.HandleFsList))
	r.POST("/api/fs/search", ginWrap(alistHandler.HandleFsSearch))
	r.PUT("/api/fs/put", ginWrap(alistHandler.HandleFsPut))
	r.POST("/api/fs/remove", ginWrap(alistHandler.HandleFsRemove))
	r.POST("/api/fs/rename", ginWrap(alistHandler.HandleFsRename))
	r.POST("/api/fs/move", ginWrap(alistHandler.HandleFsMove))
	r.POST("/api/fs/copy", ginWrap(alistHandler.HandleFsCopy))
	r.GET("/api/encrypt/dir-sync/overview", AuthMiddleware(s.cfg.JWTSecret, s.cfg.JWTExpire), ginWrap(alistHandler.HandleDirSyncOverview))
	r.POST("/api/encrypt/dir-sync/run", AuthMiddleware(s.cfg.JWTSecret, s.cfg.JWTExpire), ginWrap(alistHandler.HandleDirSyncRun))
	r.GET("/api/encrypt/dir-sync/page", ginWrap(alistHandler.HandleDirSyncPage))

	// Catch-all - Proxy to Alist with version injection
	r.NoRoute(ginWrap(proxyHandler.HandleProxy))
}

// startStartupProbe launches a background goroutine for startup probing if enabled.
func (s *Server) startStartupProbe(webdavHandler *handler.WebDAVHandler) {
	if s.cfg != nil {
		alist := s.cfg.AlistServerSnapshot()
		if !alist.EnableStartupProbe {
			return
		}
		prefixes := s.passwdDAO.GetEncPathPrefixes()
		probeCtx, probeCancel := context.WithCancel(context.Background())
		s.probeCancel = probeCancel
		s.probeWG.Add(1)
		go func(ctx context.Context, paths []string) {
			defer s.probeWG.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("Startup probe scheduler panicked")
				}
			}()
			if len(paths) == 0 {
				return
			}
			delay := time.Duration(alist.StartupProbeDelaySeconds) * time.Second
			if delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
			interval := time.Duration(alist.StartupProbeIntervalMinutes) * time.Minute
			if interval <= 0 {
				log.Info().Int("paths", len(paths)).Msg("Startup probe running")
				webdavHandler.StartupProbe(ctx, paths)
				log.Info().Msg("Startup probe completed")
				return
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				log.Info().Int("paths", len(paths)).Msg("Startup probe running")
				webdavHandler.StartupProbe(ctx, paths)
				log.Info().Msg("Startup probe completed")
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}(probeCtx, prefixes)
	}
}

func migrateStrategyStore(cfg *config.Config, store handler.StrategyStore) error {
	if cfg == nil || store == nil {
		return nil
	}
	path := cfg.AlistServerSnapshot().StrategyStoreFile
	if path == "" {
		path = filepath.Join(cfg.DataDir, "strategy_cache.json")
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}

	data, err := handler.LoadStrategyStoreFile(path)
	if err != nil {
		return err
	}
	for provider, state := range data {
		_ = store.Set(provider, state)
	}

	backupPath := path + ".bak"
	if err := os.Rename(path, backupPath); err != nil {
		return err
	}
	log.Info().Str("path", backupPath).Msg("Strategy store migrated to MySQL")
	return nil
}

// ginWrap wraps a http.HandlerFunc to gin.HandlerFunc
func ginWrap(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
	}
}

// debugTokenMiddleware enforces the configured /debug bearer token when one is
// set (X-Debug-Token header, or a standard Authorization: Bearer header).
func debugTokenMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		provided := strings.TrimSpace(c.GetHeader("X-Debug-Token"))
		if provided == "" {
			auth := strings.TrimSpace(c.GetHeader("Authorization"))
			if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
				provided = strings.TrimSpace(auth[7:])
			}
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid debug token"})
			return
		}
		c.Next()
	}
}

// Start starts the server(s)
func (s *Server) Start() error {
	s.lifecycleMu.Lock()
	if s.started || s.stopping {
		s.lifecycleMu.Unlock()
		return fmt.Errorf("server already started or stopped")
	}
	s.started = true
	// Preparation admission and Add are atomic with Shutdown's seal.
	s.prepareWG.Add(1)
	s.lifecycleMu.Unlock()
	servers, err := s.prepareListeners()
	s.prepareWG.Done()
	if err != nil {
		_ = s.Shutdown(context.Background())
		return err
	}
	errChan := make(chan error, len(servers))
	for _, endpoint := range servers {
		go func(endpoint serverEndpoint) {
			defer s.serveWG.Done()
			var err error
			if endpoint.tls {
				scheme := s.cfg.SchemeSnapshot()
				err = endpoint.server.ServeTLS(endpoint.listener, scheme.CertFile, scheme.KeyFile)
			} else {
				err = endpoint.server.Serve(endpoint.listener)
			}
			errChan <- err
		}(endpoint)
	}
	err = <-errChan
	// A failed endpoint stops its siblings and drains requests before store close.
	_ = s.Shutdown(context.Background())
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) prepareHTTP() *http.Server {
	addr := s.cfg.GetHTTPAddr()

	var httpHandler http.Handler = s.ownedHTTPHandler(s.engine)

	// Enable h2c (HTTP/2 cleartext) if configured
	if s.cfg.IsH2CEnabled() {
		h2s := &http2.Server{
			MaxConcurrentStreams: 1000,
			IdleTimeout:          120 * time.Second,
		}
		httpHandler = h2c.NewHandler(httpHandler, h2s)
		log.Info().Msg("HTTP/2 cleartext (h2c) enabled")
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           httpHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0, // No timeout for streaming
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	log.Info().Str("addr", addr).Msg("Starting HTTP server")
	log.Info().Str("alist_url", s.cfg.GetAlistURL()).Msg("Proxying to Alist")

	server.ConnState = s.ownedConnState
	server.Handler = httpHandler
	return server
}

func (s *Server) prepareHTTPS() *http.Server {
	addr := s.cfg.GetHTTPSAddr()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           s.engine,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	// Enable HTTP/2
	http2.ConfigureServer(server, &http2.Server{
		MaxConcurrentStreams: 1000,
		IdleTimeout:          120 * time.Second,
	})

	log.Info().Str("addr", addr).Msg("Starting HTTPS server with HTTP/2")

	server.ConnState = s.ownedConnState
	server.Handler = s.ownedHTTPHandler(s.engine)
	return server
}

func (s *Server) prepareUnix() (*http.Server, net.Listener, error) {
	scheme := s.cfg.SchemeSnapshot()
	socketPath := scheme.UnixFile

	// Remove existing socket file
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := s.listen("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create unix socket: %w", err)
	}

	// Set socket permissions if specified
	if scheme.UnixFilePerm != "" {
		var perm os.FileMode
		if _, err := fmt.Sscanf(scheme.UnixFilePerm, "%o", &perm); err == nil {
			os.Chmod(socketPath, perm)
		}
	}

	server := &http.Server{
		Handler:           s.engine,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}

	log.Info().Str("socket", socketPath).Msg("Starting Unix socket server")

	server.ConnState = s.ownedConnState
	server.Handler = s.ownedHTTPHandler(s.engine)
	return server, listener, nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() { s.shutdownErr = s.shutdown(ctx) })
	return s.shutdownErr
}

func (s *Server) shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down server...")
	s.lifecycleMu.Lock()
	s.stopping = true
	if s.sealedSignal == nil {
		s.sealedSignal = make(chan struct{})
	}
	close(s.sealedSignal)
	if s.requestCancel != nil {
		s.requestCancel()
	}
	s.lifecycleMu.Unlock()
	// Seal admission before HTTP shutdown, including on a never-started server.
	if s.backups != nil {
		s.backups.seal()
	}

	// Cancel startup probe goroutine
	if s.probeCancel != nil {
		s.probeCancel()
	}

	var lastErr error

	// A late prepared listener cannot publish after the seal. Join preparation
	// before snapshotting the server fields, then close every owned listener.
	s.prepareWG.Wait()
	s.lifecycleMu.Lock()
	servers := []*http.Server{s.httpServer, s.httpsServer, s.unixServer}
	listeners := append([]net.Listener(nil), s.listeners...)
	s.lifecycleMu.Unlock()
	for _, server := range servers {
		if server != nil {
			if err := server.Shutdown(ctx); err != nil {
				lastErr = err
				// Force-close connections to cancel actual request contexts on timeout.
				_ = server.Close()
			}
		}
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	s.serveWG.Wait()
	// Hijacked h2c sockets are not closed by http.Server.Shutdown/Close.
	// Release them explicitly so blocked transport I/O and idle sessions end.
	s.closeOwnedConnections()
	// Close cancels network I/O, not arbitrary handler code. Always wait for
	// actual return before tearing down DAOs/stores, even after ctx expiry.
	s.requestWG.Wait()
	s.probeWG.Wait()

	if s.proxyHandler != nil {
		s.proxyHandler.Stop()
	}
	if s.webdavHandler != nil {
		s.webdavHandler.Stop()
	}
	if s.alistHandler != nil {
		s.alistHandler.Stop()
	}
	if s.probeScheduler != nil {
		s.probeScheduler.Stop()
	}
	if s.fileDAO != nil {
		s.fileDAO.Stop()
	}

	// Flush playback statistics: recorder drains open sessions, store drains its
	// pending queue and stops the background writer.
	if s.statsShutdown != nil {
		s.statsShutdown()
	}

	// Flush learned range-state. For the file-backed store this drains
	// buffered writes so the tail of range-learning survives shutdown.
	if s.rangeCompatStore != nil {
		if err := s.rangeCompatStore.Close(); err != nil {
			lastErr = err
		}
	}

	// A deadline signals cancellation but cannot abandon owned disk I/O.
	// Always join the actual snapshot return before closing the Bolt store.
	if s.backups != nil {
		s.backups.wait()
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			lastErr = err
		}
	}

	// Flush and close MySQL store if active (prevents data loss from write-behind buffers).
	if s.mysqlStore != nil {
		if err := s.mysqlStore.Close(); err != nil {
			lastErr = err
		}
	}

	// Stop PasswdDAO background cleanup
	if s.passwdDAO != nil {
		s.passwdDAO.Stop()
	}

	// Clean up Unix socket
	if s.cfg.IsUnixSocketEnabled() {
		os.Remove(s.cfg.SchemeSnapshot().UnixFile)
	}

	return lastErr
}

// initRangeCompatStore creates a persistent range compatibility store.
// Priority: MySQL > JSON file > memory.
func (s *Server) initRangeCompatStore() proxy.RangeCompatStore {
	// Use file-based store for persistence across restarts
	dataDir := s.cfg.DataDir
	if dataDir == "" {
		dataDir = "data"
	}
	filePath := filepath.Join(dataDir, "range_compat.json")
	store, err := proxy.NewFileRangeCompatStore(filePath)
	if err != nil {
		log.Warn().Err(err).Str("path", filePath).Msg("Failed to create file range compat store, falling back to memory")
		return nil
	}
	log.Info().Str("path", filePath).Msg("Using file-based range compatibility store")
	return store
}
