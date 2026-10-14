package bootstrap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/cmd/flags"
	"github.com/OpenListTeam/OpenList/v4/internal/bootstrap/data"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/fs"
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server"
	"github.com/OpenListTeam/OpenList/v4/server/middlewares"
	"github.com/OpenListTeam/sftpd-openlist"
	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go/http3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func Init() error { return InitOwned(nil) }
func InitOwned(owner *internalnet.EmbeddedLease) error {
	bootstrapLifecycleMu.Lock()
	defer bootstrapLifecycleMu.Unlock()
	if err := internalnet.AuthorizeBootstrap(owner); err != nil {
		return err
	}
	InitConfig()
	Log()
	InitDB()
	data.InitData()
	InitStreamLimit()
	InitIndex()
	InitUpgradePatch()
	return nil
}

func Release() error { return ReleaseOwned(nil) }
func ReleaseOwned(owner *internalnet.EmbeddedLease) error {
	bootstrapLifecycleMu.Lock()
	defer bootstrapLifecycleMu.Unlock()
	if err := internalnet.AuthorizeBootstrap(owner); err != nil {
		return err
	}
	db.Close()
	return nil
}

var bootstrapLifecycleMu sync.Mutex

var (
	endpointOwnerMu    sync.Mutex
	endpointOwner      *endpointGeneration
	endpointShutdownMu sync.Mutex
)

// Called by OpenList-Mobile. State is generation-local and synchronized.
func IsRunning(t string) bool {
	endpointOwnerMu.Lock()
	g := endpointOwner
	endpointOwnerMu.Unlock()
	if g == nil {
		return false
	}
	switch t {
	case "http", "https", "unix", "quic", "s3", "ftp", "sftp":
		return g.isRunning(t)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.sealed
}

func endpointNotification(name string) func(error) {
	// Snapshot this generation's subscribers before launch. Delayed asynchronous
	// delivery must not send an old endpoint event to a new owner's hooks.
	endpointHooksMu.Lock()
	failed := make([]EndpointStartFailedHook, 0, len(endpointStartFailedHooks))
	stopped := make([]EndpointShutdownHook, 0, len(endpointShutdownHooks))
	for _, hook := range endpointStartFailedHooks {
		failed = append(failed, hook)
	}
	for _, hook := range endpointShutdownHooks {
		stopped = append(stopped, hook)
	}
	endpointHooksMu.Unlock()
	return func(err error) {
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			for _, hook := range failed {
				hook(name, err.Error())
			}
			utils.Log.Errorf("failed to serve %s: %s", name, err)
		} else {
			for _, hook := range stopped {
				hook(name)
			}
		}
	}
}

func Start() error { return StartOwned(nil) }
func StartOwned(owner *internalnet.EmbeddedLease) error {
	bootstrapLifecycleMu.Lock()
	defer bootstrapLifecycleMu.Unlock()
	if err := internalnet.AuthorizeBootstrap(owner); err != nil {
		return err
	}
	endpointOwnerMu.Lock()
	if endpointOwner != nil {
		endpointOwnerMu.Unlock()
		return fmt.Errorf("endpoint_generation_overlap")
	}
	g := &endpointGeneration{}
	endpointOwner = g
	endpointOwnerMu.Unlock()
	// Everything below registers with this captured generation. Shutdown may seal
	// it during initialization, in which case no later socket preparation runs.
	if conf.Conf.DelayedStart != 0 {
		utils.Log.Infof("delayed start for %d seconds", conf.Conf.DelayedStart)
		time.Sleep(time.Duration(conf.Conf.DelayedStart) * time.Second)
	}
	InitOfflineDownloadTools()
	LoadStorages()
	InitTaskManager()
	if !flags.Debug && !flags.Dev {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	if conf.Conf.Log.Filter.Enable {
		r.Use(middlewares.FilteredLogger())
	} else {
		r.Use(gin.LoggerWithWriter(log.StandardLogger().Out))
	}
	r.Use(gin.RecoveryWithWriter(log.StandardLogger().Out))
	server.Init(r)
	var httpHandler http.Handler = r
	if conf.Conf.Scheme.EnableH2c {
		httpHandler = h2c.NewHandler(r, &http2.Server{})
	}
	// Snapshot paths and options before asynchronous use.
	scheme, s3 := conf.Conf.Scheme, conf.Conf.S3
	certFile, keyFile := scheme.CertFile, scheme.KeyFile
	if scheme.EnableH3 && scheme.HttpsPort != -1 {
		port := scheme.HttpsPort
		r.Use(func(c *gin.Context) {
			if c.Request.TLS != nil {
				c.Header("Alt-Svc", fmt.Sprintf("h3=\":%d\"; ma=86400", port))
			}
			c.Next()
		})
	}
	startHTTP := func(name, addr string, handler http.Handler, ssl bool) {
		srv := &http.Server{Addr: addr, Handler: handler}
		serve := srv.ListenAndServe
		if ssl {
			serve = func() error { return srv.ListenAndServeTLS(certFile, keyFile) }
		}
		utils.Log.Infof("start %s server @ %s", name, addr)
		// net/http permanently seals a local server on Shutdown, including when
		// Shutdown precedes the goroutine's first instruction.
		g.start(name, nil, serve, srv.Shutdown, nil, endpointNotification(name))
	}
	if scheme.HttpPort != -1 {
		startHTTP("http", fmt.Sprintf("%s:%d", scheme.Address, scheme.HttpPort), httpHandler, false)
	}
	if scheme.HttpsPort != -1 {
		addr := fmt.Sprintf("%s:%d", scheme.Address, scheme.HttpsPort)
		startHTTP("https", addr, r, true)
		if scheme.EnableH3 {
			srv := &http3.Server{Addr: addr, Handler: r}
			var conn net.PacketConn
			prepare := func() error {
				certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err != nil {
					return err
				}
				srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}}
				conn, err = net.ListenPacket("udp", addr)
				return err
			}
			// Own the UDP socket synchronously; http3.Shutdown alone is not a
			// preparation barrier. Serve does not close caller-provided PacketConn.
			stop := func(ctx context.Context) error {
				err := srv.Shutdown(ctx)
				if err != nil {
					return err
				}
				err = conn.Close()
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			}
			g.start("quic", prepare, func() error { return srv.Serve(conn) }, stop, nil, endpointNotification("quic"))
		}
	}
	if scheme.UnixFile != "" {
		srv := &http.Server{Handler: httpHandler}
		var listener net.Listener
		prepare := func() error {
			var err error
			listener, err = net.Listen("unix", scheme.UnixFile)
			if err != nil {
				return err
			}
			mode, err := strconv.ParseUint(scheme.UnixFilePerm, 8, 32)
			if err == nil {
				err = os.Chmod(scheme.UnixFile, os.FileMode(mode))
			}
			if err != nil {
				utils.Log.Errorf("failed to set socket file permission: %+v", err)
			}
			return nil
		}
		stop := func(ctx context.Context) error {
			if err := srv.Shutdown(ctx); err != nil {
				return err
			}
			// Shutdown before Serve cannot know this prepared listener.
			err := listener.Close()
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		g.start("unix", prepare, func() error { return srv.Serve(listener) }, stop, nil, endpointNotification("unix"))
	}
	if s3.Port != -1 && s3.Enable {
		s3r := gin.New()
		s3r.Use(gin.LoggerWithWriter(log.StandardLogger().Out), gin.RecoveryWithWriter(log.StandardLogger().Out))
		server.InitS3(s3r)
		startHTTP("s3", fmt.Sprintf("%s:%d", scheme.Address, s3.Port), s3r, s3.SSL)
	}
	if conf.Conf.FTP.Listen != "" && conf.Conf.FTP.Enable {
		var driver *server.FtpMainDriver
		var srv *ftpserver.FtpServer
		var listener net.Listener
		prepare := func() error {
			var err error
			driver, err = server.NewMainDriver()
			if err != nil {
				return err
			}
			settings, err := driver.GetSettings()
			if err != nil {
				driver.Stop()
				return err
			}
			listener, err = net.Listen("tcp", settings.ListenAddr)
			if err != nil {
				driver.Stop()
				return err
			}
			if settings.TLSRequired == ftpserver.ImplicitEncryption {
				tlsConfig, err := driver.GetTLSConfig()
				if err != nil {
					_ = listener.Close()
					driver.Stop()
					return err
				}
				listener = tls.NewListener(listener, tlsConfig)
			}
			settings.Listener = listener
			srv = ftpserver.NewFtpServer(driver)
			if err = srv.Listen(); err != nil {
				_ = listener.Close()
				driver.Stop()
				return err
			}
			return nil
		}
		stop := func(context.Context) error {
			// Close the captured listener, not srv.Stop: Serve writes the library's
			// listener field on exit. Driver.Stop also lacks a session join, so do
			// not race its client-map cleanup against live callbacks here.
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				return err
			}
			return fmt.Errorf("FTP accepted-session drain is not supported; ownership retained")
		}
		g.start("ftp", prepare, func() error { return srv.Serve() }, stop, nil, endpointNotification("ftp"))
	}
	if conf.Conf.SFTP.Listen != "" && conf.Conf.SFTP.Enable {
		var driver *server.SftpDriver
		var srv *sftpd.SftpServer
		prepare := func() error {
			var err error
			driver, err = server.NewSftpDriver()
			if err != nil {
				return err
			}
			srv = sftpd.NewSftpServer(driver)
			return nil
		}
		stop := func(context.Context) error {
			if err := srv.Close(); err != nil {
				return err
			}
			return fmt.Errorf("SFTP accepted-session drain is not supported; ownership retained")
		}
		// The API binds only within RunServer. Hold admission through its ready
		// notification so Shutdown cannot finish before that bind occurs.
		g.start("sftp", prepare, func() error { return srv.RunServer() }, stop, func() error { return srv.BlockTillReady() }, endpointNotification("sftp"))
	}
	return nil
}

// ShutdownDrainError is non-nil unless every stop and Serve join succeeded.
// The mobile lifecycle caller serializes access and retains the process lease on
// error. Failed/in-flight endpoints remain reachable for a subsequent retry.
var ShutdownDrainError error

func Shutdown(timeout time.Duration) { _ = ShutdownOwned(nil, timeout) }
func ShutdownOwned(owner *internalnet.EmbeddedLease, timeout time.Duration) error {
	bootstrapLifecycleMu.Lock()
	defer bootstrapLifecycleMu.Unlock()
	if err := internalnet.AuthorizeBootstrap(owner); err != nil {
		return err
	}
	endpointShutdownMu.Lock()
	defer endpointShutdownMu.Unlock()
	endpointOwnerMu.Lock()
	g := endpointOwner
	endpointOwnerMu.Unlock()
	ShutdownDrainError = nil
	if g == nil {
		return nil
	}
	utils.Log.Println("Shutdown server...")
	fs.ArchiveContentUploadTaskManager.RemoveAll()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := g.drain(ctx); err != nil {
		ShutdownDrainError = fmt.Errorf("endpoint drain failed: %w", err)
		utils.Log.Error(ShutdownDrainError)
		return ShutdownDrainError
	}
	endpointOwnerMu.Lock()
	if endpointOwner == g {
		endpointOwner = nil
	}
	endpointOwnerMu.Unlock()
	utils.Log.Println("Server exit")
	return nil
}

type EndpointStartFailedHook func(string, string)
type EndpointShutdownHook func(string)

var (
	endpointHooksMu          sync.Mutex
	endpointStartFailedHooks = make(map[string]EndpointStartFailedHook)
	endpointShutdownHooks    = make(map[string]EndpointShutdownHook)
)

func RegisterEndpointStartFailedHook(hook EndpointStartFailedHook) string {
	id := uuid.NewString()
	endpointHooksMu.Lock()
	endpointStartFailedHooks[id] = hook
	endpointHooksMu.Unlock()
	return id
}
func RemoveEndpointStartFailedHook(id string) {
	endpointHooksMu.Lock()
	delete(endpointStartFailedHooks, id)
	endpointHooksMu.Unlock()
}
func RegisterEndpointShutdownHook(hook EndpointShutdownHook) string {
	id := uuid.NewString()
	endpointHooksMu.Lock()
	endpointShutdownHooks[id] = hook
	endpointHooksMu.Unlock()
	return id
}
func RemoveEndpointShutdownHook(id string) {
	endpointHooksMu.Lock()
	delete(endpointShutdownHooks, id)
	endpointHooksMu.Unlock()
}
func handleEndpointStartFailedHooks(t string, err error) {
	endpointHooksMu.Lock()
	hooks := make([]EndpointStartFailedHook, 0, len(endpointStartFailedHooks))
	for _, hook := range endpointStartFailedHooks {
		hooks = append(hooks, hook)
	}
	endpointHooksMu.Unlock()
	for _, hook := range hooks {
		hook(t, err.Error())
	}
}
func handleEndpointShutdownHooks(t string) {
	endpointHooksMu.Lock()
	hooks := make([]EndpointShutdownHook, 0, len(endpointShutdownHooks))
	for _, hook := range endpointShutdownHooks {
		hooks = append(hooks, hook)
	}
	endpointHooksMu.Unlock()
	for _, hook := range hooks {
		hook(t)
	}
}
