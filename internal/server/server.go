package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	router      *chi.Mux
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

	s := &Server{
		cfg:         cfg,
		store:       store,
		router:      chi.NewRouter(),
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
	r := s.router

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(CORSMiddleware)
	// Debug middleware to log all requests
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug().Str("method", r.Method).Str("path", r.URL.Path).Msg("HTTP request")
			next.ServeHTTP(w, r)
		})
	})

	// Force HTTPS redirect if enabled
	if s.cfg.Scheme != nil && s.cfg.Scheme.ForceHTTPS && s.cfg.IsHTTPSEnabled() {
		r.Use(ForceHTTPSMiddleware(s.cfg.Scheme.HTTPSPort))
	}

	// Serve static files (WebUI)
	// Use the filesystem with "public" prefix already stripped
	fileServer := http.FileServer(web.GetFileSystem())
	// Handle /public/* requests by stripping the prefix
	r.Handle("/public/*", http.StripPrefix("/public", fileServer))
	// Also handle /static/* for direct access to static resources
	// The file system already has "static/" at root, so no StripPrefix needed
	r.Handle("/static/*", fileServer)
	// Special handler for /public/index.html to avoid redirect loop
	r.Get("/public/index.html", func(w http.ResponseWriter, r *http.Request) {
		f, err := web.GetFileSystem().Open("index.html")
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ := f.Stat()
		http.ServeContent(w, r, "index.html", stat.ModTime(), f)
	})
	// Redirect / to index page for better UX
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/public/index.html", http.StatusFound)
	})
	r.Get("/index", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/public/index.html", http.StatusFound)
	})
	// Debug route for testing static files
	r.Get("/debug-static/*", func(w http.ResponseWriter, r *http.Request) {
		path := chi.URLParam(r, "*")
		log.Debug().Str("path", path).Msg("Static file debug request")
		http.ServeFile(w, r, "web/public/"+path)
	})
	// Debug embedded filesystem
	r.Get("/debug-embed/*", func(w http.ResponseWriter, r *http.Request) {
		path := chi.URLParam(r, "*")
		log.Debug().Str("path", path).Msg("Embedded file debug request")
		fs := web.GetFileSystem()
		f, err := fs.Open(path)
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("Failed to open embedded file")
			http.Error(w, "File not found: "+err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, err := f.Stat()
		if err != nil {
			log.Error().Err(err).Str("path", path).Msg("Failed to stat embedded file")
			http.Error(w, "Stat failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, path, stat.ModTime(), f)
	})

	// Create handlers
	apiHandler := handler.NewAPIHandler(s.cfg, s.userDAO, s.passwdDAO)
	proxyHandler := handler.NewProxyHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO)
	alistHandler := handler.NewAlistHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO)
	webdavHandler := handler.NewWebDAVHandler(s.cfg, s.streamProxy, s.fileDAO, s.passwdDAO)

	// Handle frontend error collection API (built into the Vue template, not needed)
	// Return success to prevent 502 errors when Alist is not configured
	r.Post("/integration-front/errorCollection/insert", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code":0,"msg":"ok"}`))
	})

	// /enc-api/* routes - Authentication and config management (compatible with original)
	r.Route("/enc-api", func(r chi.Router) {
		// Public routes (no auth required)
		r.Post("/login", apiHandler.Login)

		// Protected routes (auth required) - use Group to apply middleware
		r.Group(func(r chi.Router) {
			r.Use(AuthMiddleware(s.cfg.JWTSecret))
			r.MethodFunc("GET", "/getUserInfo", apiHandler.GetUserInfo)
			r.MethodFunc("POST", "/getUserInfo", apiHandler.GetUserInfo)
			r.MethodFunc("GET", "/updatePasswd", apiHandler.UpdatePasswd)
			r.MethodFunc("POST", "/updatePasswd", apiHandler.UpdatePasswd)
			r.MethodFunc("GET", "/getAlistConfig", apiHandler.GetAlistConfig)
			r.MethodFunc("POST", "/getAlistConfig", apiHandler.GetAlistConfig)
			r.MethodFunc("GET", "/saveAlistConfig", apiHandler.SaveAlistConfig)
			r.MethodFunc("POST", "/saveAlistConfig", apiHandler.SaveAlistConfig)
			r.MethodFunc("GET", "/getWebdavonfig", apiHandler.GetWebdavConfig) // Note: typo matches original
			r.MethodFunc("POST", "/getWebdavonfig", apiHandler.GetWebdavConfig)
			r.MethodFunc("GET", "/getWebdavConfig", apiHandler.GetWebdavConfig)
			r.MethodFunc("POST", "/getWebdavConfig", apiHandler.GetWebdavConfig)
			r.MethodFunc("GET", "/saveWebdavConfig", apiHandler.SaveWebdavConfig)
			r.MethodFunc("POST", "/saveWebdavConfig", apiHandler.SaveWebdavConfig)
			r.MethodFunc("GET", "/updateWebdavConfig", apiHandler.UpdateWebdavConfig)
			r.MethodFunc("POST", "/updateWebdavConfig", apiHandler.UpdateWebdavConfig)
			r.MethodFunc("GET", "/delWebdavConfig", apiHandler.DelWebdavConfig)
			r.MethodFunc("POST", "/delWebdavConfig", apiHandler.DelWebdavConfig)
			r.MethodFunc("GET", "/encodeFoldName", apiHandler.EncodeFoldName)
			r.MethodFunc("POST", "/encodeFoldName", apiHandler.EncodeFoldName)
			r.MethodFunc("GET", "/decodeFoldName", apiHandler.DecodeFoldName)
			r.MethodFunc("POST", "/decodeFoldName", apiHandler.DecodeFoldName)
		})
	})

	// /redirect/:key - 302 redirect decryption
	r.HandleFunc("/redirect/{key}", proxyHandler.HandleRedirect)

	// /dav/* - WebDAV proxy
	r.HandleFunc("/dav/*", webdavHandler.Handle)

	// /d/* and /p/* - File download with decryption
	r.Get("/d/*", proxyHandler.HandleDownload)
	r.Get("/p/*", proxyHandler.HandleDownload)

	// /api/fs/* - Alist API interception
	r.Post("/api/fs/get", alistHandler.HandleFsGet)
	r.Post("/api/fs/list", alistHandler.HandleFsList)
	r.Put("/api/fs/put", alistHandler.HandleFsPut)
	r.Post("/api/fs/remove", alistHandler.HandleFsRemove)
	r.Post("/api/fs/rename", alistHandler.HandleFsRename)
	r.Post("/api/fs/move", alistHandler.HandleFsMove)
	r.Post("/api/fs/copy", alistHandler.HandleFsCopy)

	// Catch-all - Proxy to Alist with version injection
	r.HandleFunc("/*", proxyHandler.HandleProxy)
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

	var httpHandler http.Handler = s.router

	// Enable h2c (HTTP/2 cleartext) if configured
	if s.cfg.IsH2CEnabled() {
		h2s := &http2.Server{
			MaxConcurrentStreams: 1000,
			IdleTimeout:          120 * time.Second,
		}
		httpHandler = h2c.NewHandler(s.router, h2s)
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
		Handler:      s.router,
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
		Handler:      s.router,
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

