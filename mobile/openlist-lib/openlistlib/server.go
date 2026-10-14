package openlistlib

import (
	"context"
	"errors"
	"fmt"
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/bootstrap"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/openlistlib/encrypt"
	"github.com/OpenListTeam/OpenList/v4/openlistlib/internal"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	log "github.com/sirupsen/logrus"
)

type LogCallback interface {
	OnLog(level int16, time int64, message string)
}

type Event interface {
	OnStartError(t string, err string)
	OnShutdown(t string)
	OnProcessExit(code int)
}

var startFailedHookUuid = ""
var shutdownHookUuid = ""
var logFormatter *internal.MyFormatter

var embeddedLifecycle sync.Mutex
var embeddedLease *internalnet.EmbeddedLease
var embeddedStarted bool

func Init(event Event, cb LogCallback) (err error) {
	embeddedLifecycle.Lock()
	defer embeddedLifecycle.Unlock()
	lease, err := internalnet.AcquireEmbeddedLease()
	if err != nil {
		return err
	}
	embeddedLease = lease
	defer func() {
		if err != nil {
			_ = lease.BeginStop()
			if releaseErr := lease.Release(); releaseErr == nil {
				embeddedLease = nil
			} else {
				err = fmt.Errorf("%w; cleanup: %v", err, releaseErr)
			}
		}
	}()
	// Acquire before hooks, configuration, logging or DB initialization.
	if event == nil || cb == nil {
		return errors.New("embedded_instance_callbacks_required")
	}
	if startFailedHookUuid != "" {
		bootstrap.RemoveEndpointStartFailedHook(startFailedHookUuid)
		startFailedHookUuid = ""
	}
	if shutdownHookUuid != "" {
		bootstrap.RemoveEndpointShutdownHook(shutdownHookUuid)
		shutdownHookUuid = ""
	}
	bootstrap.Init()
	startFailedHookUuid = bootstrap.RegisterEndpointStartFailedHook(event.OnStartError)
	shutdownHookUuid = bootstrap.RegisterEndpointShutdownHook(event.OnShutdown)
	logFormatter = &internal.MyFormatter{
		OnLog: func(entry *log.Entry) {
			msg := entry.Message
			if len(entry.Data) > 0 {
				var sb strings.Builder
				sb.WriteString(msg)
				for k, v := range entry.Data {
					sb.WriteString(fmt.Sprintf(" [%s=%v]", k, v))
				}
				msg = sb.String()
			}
			cb.OnLog(int16(entry.Level), entry.Time.UnixMilli(), msg)
		},
	}
	if utils.Log == nil {
		return errors.New("utils.log is nil")
	} else {
		utils.Log.SetFormatter(logFormatter)
		utils.Log.ExitFunc = event.OnProcessExit
	}
	return nil
}

// SetLogLevel sets the log level for the main alist service (5244).
// level should be one of: "panic", "fatal", "error", "warn", "info", "debug", "trace".
func SetLogLevel(level string) {
	if utils.Log == nil {
		return
	}
	lvl, err := log.ParseLevel(level)
	if err != nil {
		lvl = log.InfoLevel
	}
	utils.Log.SetLevel(lvl)
	// Also propagate to the global encrypt proxy log level if set.
	encryptLog := log.StandardLogger()
	if encryptLog != nil {
		encryptLog.SetLevel(lvl)
	}
}

func IsRunning(t string) bool {
	return bootstrap.IsRunning(t)
}

// Start starts the server
func Start() {
	if err := StartEmbedded(); err != nil {
		log.Error(err)
	}
}

// StartEmbedded rejects overlap synchronously; Start retains the mobile ABI.
func StartEmbedded() error {
	config := GetEncryptManager().GetConfig()
	embeddedLifecycle.Lock()
	defer embeddedLifecycle.Unlock()
	if embeddedLease == nil {
		return errors.New("embedded_instance_not_initialized")
	}
	if embeddedStarted {
		return errors.New("embedded_instance_overlap")
	}
	// Storage initialization/login precedes starting the optional media proxy.
	// Register its independent driver transport factory before bootstrap loads drivers.
	if config == nil {
		config = encrypt.DefaultConfig()
	}
	if err := encrypt.PublishDriverRouteFactory(embeddedLease, config); err != nil {
		return err
	}
	embeddedStarted = true
	bootstrap.Start()
	return nil
}

func publishEmbeddedFactory(config *encrypt.ProxyConfig) {
	embeddedLifecycle.Lock()
	defer embeddedLifecycle.Unlock()
	if embeddedLease != nil && embeddedStarted {
		_ = encrypt.PublishDriverRouteFactory(embeddedLease, config)
	}
}

// DriverConfigurationPendingEpoch reports the snapshot for new sessions;
// existing driver sessions require explicit reinitialization (not hot update).
func DriverConfigurationPendingEpoch() int64 {
	embeddedLifecycle.Lock()
	defer embeddedLifecycle.Unlock()
	if embeddedLease == nil {
		return 0
	}
	return int64(embeddedLease.PendingEpoch())
}

// Shutdown timeout 毫秒
func Shutdown(timeout int64) (err error) {
	embeddedLifecycle.Lock()
	defer embeddedLifecycle.Unlock()
	if embeddedLease == nil {
		return nil
	}
	if err := embeddedLease.BeginStop(); err != nil {
		return err
	}
	timeoutDuration := time.Duration(timeout) * time.Millisecond
	if embeddedStarted {
		bootstrap.Shutdown(timeoutDuration)
		if bootstrap.ShutdownDrainError != nil {
			return bootstrap.ShutdownDrainError
		}
	}
	bootstrap.JoinStorageLoads()
	// These actual Drop calls provide driver-specific cleanup. Unsupported driver
	// cancellation/join remains P3; never pretend the global lease proves it.
	for _, storage := range op.GetAllStorages() {
		if err := storage.Drop(context.Background()); err != nil {
			return err
		}
	}
	ForceDBSync()
	if err := embeddedLease.Release(); err != nil {
		return err
	}
	embeddedLease = nil
	embeddedStarted = false
	return nil
}

// ForceDBSync forces SQLite WAL checkpoint to sync data to main database file
func ForceDBSync() error {
	mode := strings.ToUpper(strings.TrimSpace(os.Getenv("OPENLIST_WAL_CHECKPOINT_MODE")))
	if mode == "" {
		mode = "PASSIVE"
	}
	switch mode {
	case "PASSIVE", "FULL", "RESTART", "TRUNCATE":
	default:
		mode = "PASSIVE"
	}
	timeout := 2 * time.Second
	if raw := strings.TrimSpace(os.Getenv("OPENLIST_WAL_CHECKPOINT_TIMEOUT_MS")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}
	log.Infof("[%s] Forcing database sync (WAL checkpoint mode=%s timeout=%s)...", internal.TagServer, mode, timeout)

	// Get the database instance and execute WAL checkpoint
	gormDB := db.GetDb()
	if gormDB != nil {
		sqlDB, err := gormDB.DB()
		if err != nil {
			log.Errorf("[%s] Failed to get database connection: %v", internal.TagServer, err)
			return err
		}

		// Execute WAL checkpoint with TRUNCATE mode to force sync and remove WAL files
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		_, err = sqlDB.ExecContext(ctx, fmt.Sprintf("PRAGMA wal_checkpoint(%s)", mode))
		if err != nil {
			log.Errorf("[%s] Failed to execute WAL checkpoint: %v", internal.TagServer, err)
			return err
		}

		// Also execute synchronous commit to ensure data is written to disk
		_, err = sqlDB.Exec("PRAGMA synchronous=FULL")
		if err != nil {
			log.Warnf("[%s] Failed to set synchronous mode: %v", internal.TagServer, err)
		}

		log.Info("[" + internal.TagServer + "] Database sync completed successfully")
	} else {
		log.Warn("[" + internal.TagServer + "] Database instance is nil, skipping sync")
	}

	return nil
}
