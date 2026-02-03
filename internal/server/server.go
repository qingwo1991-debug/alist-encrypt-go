package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
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
	"github.com/alist-encrypt-go/web"
)

// Server represents the HTTP/2 server
type Server struct {
	cfg         *config.Config
	store       *storage.Store
	engine      *gin.Engine
	httpServer  *http.Server
	httpsServer *http.Server
	streamProxy *proxy.StreamProxy
	userDAO     *dao.UserDAO
	fileDAO     *dao.FileDAO
	passwdDAO   *dao.PasswdDAO
}

// New creates a new server instance
func New(cfg *config.Config) (*Server, error) {
	store, err := storage.NewStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}

	// Set Gin mode
	gin.SetMode(gin.ReleaseMode)

	s := &Server{
		cfg:         cfg,
		store:       store,
		engine:      gin.New(),
		streamProxy: proxy.NewStreamProxy(cfg),
		userDAO:     dao.NewUserDAO(store),
		fileDAO:     dao.NewFileDAO(store),
		passwdDAO:   dao.NewPasswdDAO(store),
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
	r.Use(LoggerMiddleware())
	r.Use(CORSMiddleware())
	r.Use(gzip.Gzip(gzip.DefaultCompression, gzip.WithExcludedPaths([]string{"/dav"})))

	// Force HTTPS redirect if enabled
	if s.cfg.Scheme != nil && s.cfg.Scheme.ForceHTTPS && s.cfg.IsHTTPSEnabled() {
		r.Use(ForceHTTPSMiddleware(s.cfg.Scheme.HTTPSPort))
	}

	// Health check endpoints (no auth required)
	r.GET("/health", HealthHandler)
	r.GET("/ready", ReadyHandler)

	// Serve static files (WebUI)
	r.StaticFS("/public", web.GetFileSystem())
	r.StaticFS("/static", web.GetFileSystem())

	// Redirect /index to admin page
	r.GET("/index", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/public/index.html")
	})

	// Create handlers
	apiHandler := handler.NewAPIHandler(s.cfg, s.userDAO, s.passwdDAO)
	proxyHandler := handler.NewProxyHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO)
	alistHandler := handler.NewAlistHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO, proxyHandler)
	webdavHandler := handler.NewWebDAVHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO)

	// Handle frontend error collection API
	r.POST("/integration-front/errorCollection/insert", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok"})
	})

	// /enc-api/* routes - Authentication and config management
	encAPI := r.Group("/enc-api")
	{
		// Public routes (no auth required)
		encAPI.POST("/login", ginWrap(apiHandler.Login))

		// Protected routes (auth required)
		protected := encAPI.Group("")
		protected.Use(AuthMiddleware(s.cfg.JWTSecret))
		{
			protected.Any("/getUserInfo", ginWrap(apiHandler.GetUserInfo))
			protected.Any("/updatePasswd", ginWrap(apiHandler.UpdatePasswd))
			protected.Any("/updateUsername", ginWrap(apiHandler.UpdateUsername))
			protected.Any("/getAlistConfig", ginWrap(apiHandler.GetAlistConfig))
			protected.Any("/saveAlistConfig", ginWrap(apiHandler.SaveAlistConfig))
			protected.Any("/getWebdavonfig", ginWrap(apiHandler.GetWebdavConfig)) // Typo matches original
			protected.Any("/getWebdavConfig", ginWrap(apiHandler.GetWebdavConfig))
			protected.Any("/saveWebdavConfig", ginWrap(apiHandler.SaveWebdavConfig))
			protected.Any("/updateWebdavConfig", ginWrap(apiHandler.UpdateWebdavConfig))
			protected.Any("/delWebdavConfig", ginWrap(apiHandler.DelWebdavConfig))
			protected.Any("/encodeFoldName", ginWrap(apiHandler.EncodeFoldName))
			protected.Any("/decodeFoldName", ginWrap(apiHandler.DecodeFoldName))
		}
	}

	// /redirect/:key - 302 redirect decryption
	r.Any("/redirect/:key", ginWrap(proxyHandler.HandleRedirect))

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

	// /d/* and /p/* - File download with decryption
	r.GET("/d/*path", ginWrap(proxyHandler.HandleDownload))
	r.GET("/p/*path", ginWrap(proxyHandler.HandleDownload))

	// /api/fs/* - Alist API interception
	r.POST("/api/fs/get", ginWrap(alistHandler.HandleFsGet))
	r.POST("/api/fs/list", ginWrap(alistHandler.HandleFsList))
	r.PUT("/api/fs/put", ginWrap(alistHandler.HandleFsPut))
	r.POST("/api/fs/remove", ginWrap(alistHandler.HandleFsRemove))
	r.POST("/api/fs/rename", ginWrap(alistHandler.HandleFsRename))
	r.POST("/api/fs/move", ginWrap(alistHandler.HandleFsMove))
	r.POST("/api/fs/copy", ginWrap(alistHandler.HandleFsCopy))

	// Catch-all - Proxy to Alist with version injection
	r.NoRoute(ginWrap(proxyHandler.HandleProxy))
}

// ginWrap wraps a http.HandlerFunc to gin.HandlerFunc
func ginWrap(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
	}
}

// Start starts the server(s)
func (s *Server) Start() error {
	errChan := make(chan error, 3)

	// Start HTTP server
	go func() {
		if err := s.startHTTP(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server if enabled
	if s.cfg.IsHTTPSEnabled() {
		go func() {
			if err := s.startHTTPS(); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Start Unix socket if enabled
	if s.cfg.IsUnixSocketEnabled() {
		go func() {
			if err := s.startUnix(); err != nil && err != http.ErrServerClosed {
				errChan <- fmt.Errorf("Unix socket error: %w", err)
			}
		}()
	}

	// Wait for error
	return <-errChan
}

func (s *Server) startHTTP() error {
	addr := s.cfg.GetHTTPAddr()

	var httpHandler http.Handler = s.engine

	// Enable h2c (HTTP/2 cleartext) if configured
	if s.cfg.IsH2CEnabled() {
		h2s := &http2.Server{
			MaxConcurrentStreams: 1000,
			IdleTimeout:          120 * time.Second,
		}
		httpHandler = h2c.NewHandler(s.engine, h2s)
		log.Info().Msg("HTTP/2 cleartext (h2c) enabled")
	}

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      httpHandler,
		ReadTimeout:  0, // No timeout for streaming
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	log.Info().Str("addr", addr).Msg("Starting HTTP server")
	log.Info().Str("alist_url", s.cfg.GetAlistURL()).Msg("Proxying to Alist")

	return s.httpServer.ListenAndServe()
}

func (s *Server) startHTTPS() error {
	addr := s.cfg.GetHTTPSAddr()

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}

	s.httpsServer = &http.Server{
		Addr:         addr,
		Handler:      s.engine,
		TLSConfig:    tlsConfig,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	// Enable HTTP/2
	http2.ConfigureServer(s.httpsServer, &http2.Server{
		MaxConcurrentStreams: 1000,
		IdleTimeout:          120 * time.Second,
	})

	log.Info().Str("addr", addr).Msg("Starting HTTPS server with HTTP/2")

	return s.httpsServer.ListenAndServeTLS(s.cfg.Scheme.CertFile, s.cfg.Scheme.KeyFile)
}

func (s *Server) startUnix() error {
	socketPath := s.cfg.Scheme.UnixFile

	// Remove existing socket file
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to create unix socket: %w", err)
	}

	// Set socket permissions if specified
	if s.cfg.Scheme.UnixFilePerm != "" {
		var perm os.FileMode
		if _, err := fmt.Sscanf(s.cfg.Scheme.UnixFilePerm, "%o", &perm); err == nil {
			os.Chmod(socketPath, perm)
		}
	}

	server := &http.Server{
		Handler:      s.engine,
		ReadTimeout:  0,
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	log.Info().Str("socket", socketPath).Msg("Starting Unix socket server")

	return server.Serve(listener)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down server...")

	var lastErr error

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			lastErr = err
		}
	}

	if s.httpsServer != nil {
		if err := s.httpsServer.Shutdown(ctx); err != nil {
			lastErr = err
		}
	}

	if err := s.store.Close(); err != nil {
		lastErr = err
	}

	// Clean up Unix socket
	if s.cfg.IsUnixSocketEnabled() {
		os.Remove(s.cfg.Scheme.UnixFile)
	}

	return lastErr
}
