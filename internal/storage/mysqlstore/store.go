package mysqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/rs/zerolog/log"
)

type Store struct {
	db                *sql.DB
	flushInterval     time.Duration
	cleanupInterval   time.Duration
	cleanupDays       int
	dirSnapCleanupDay int
	disableCleanup    bool
	strategyBuffer    *strategyBuffer
	fileMetaBuffer    *fileMetaBuffer
	rangeCompatBuffer *rangeCompatBuffer
	cancelLoops       context.CancelFunc // cancels background flush/cleanup goroutines
	loopWG            sync.WaitGroup
	closeOnce         sync.Once
	closeErr          error
}

var openDB = sql.Open

func NewStore(cfg *config.Config) (*Store, error) {
	if cfg == nil || cfg.Database == nil {
		return nil, nil
	}
	if cfg.Database.Type == "" || cfg.Database.DSN == "" {
		return nil, nil
	}
	if cfg.Database.Type != "mysql" {
		return nil, fmt.Errorf("unsupported db type: %s", cfg.Database.Type)
	}

	dsn := normalizeDSN(cfg.Database.DSN)
	if dsn != cfg.Database.DSN {
		log.Info().Msg("DB_DSN normalized with parseTime/loc parameters")
	}

	db, err := openDB("mysql", dsn)
	if err != nil {
		return nil, err
	}

	maxOpenConns := 100
	if cfg.Database.MaxOpenConns > 0 {
		maxOpenConns = cfg.Database.MaxOpenConns
	}
	maxIdleConns := 10
	if cfg.Database.MaxIdleConns > 0 {
		maxIdleConns = cfg.Database.MaxIdleConns
	}
	connMaxLifetime := time.Hour
	if cfg.Database.ConnMaxLifetimeSeconds > 0 {
		connMaxLifetime = time.Duration(cfg.Database.ConnMaxLifetimeSeconds) * time.Second
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)
	if cfg.Database.ConnMaxIdleSeconds > 0 {
		db.SetConnMaxIdleTime(time.Duration(cfg.Database.ConnMaxIdleSeconds) * time.Second)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, closeDBAfterInitError(db, err)
	}
	log.Info().Msg("MySQL connected")

	flushInterval := time.Duration(cfg.Database.FlushIntervalSeconds) * time.Second
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	cleanupInterval := time.Duration(cfg.Database.CleanupIntervalHours) * time.Hour
	if cleanupInterval <= 0 {
		cleanupInterval = 24 * time.Hour
	}

	cleanupDays := cfg.Database.CleanupDays
	if cleanupDays <= 0 {
		cleanupDays = 30
	}
	dirSnapCleanupDays := cfg.Database.DirSnapshotCleanupDays
	if dirSnapCleanupDays <= 0 {
		// 未单独配置时,目录快照沿用通用清理窗口。
		// 目录快照的 payload 是完整目录列表,体积通常远大于其它元数据表,
		// 建议显式配置一个较短的保留天数以控制磁盘占用。
		dirSnapCleanupDays = cleanupDays
	}

	store := &Store{
		db:                 db,
		flushInterval:      flushInterval,
		cleanupInterval:    cleanupInterval,
		cleanupDays:        cleanupDays,
		dirSnapCleanupDays: dirSnapCleanupDays,
		disableCleanup:     cfg.Database.DisableCleanup,
		strategyBuffer:     newStrategyBuffer(),
		fileMetaBuffer:     newFileMetaBuffer(),
		rangeCompatBuffer:  newRangeCompatBuffer(),
	}

	schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer schemaCancel()
	if err := store.ensureSchema(schemaCtx); err != nil {
		return nil, closeDBAfterInitError(db, err)
	}
	if !store.disableCleanup {
		if err := store.cleanup(context.Background()); err != nil {
			log.Warn().Err(err).Msg("MySQL cleanup failed on startup")
		}
	} else {
		log.Info().Msg("MySQL cleanup disabled")
	}

	// Create a cancellable context for background goroutines
	loopsCtx, loopsCancel := context.WithCancel(context.Background())
	store.cancelLoops = loopsCancel

	store.startLoops(loopsCtx)
	return store, nil
}

func closeDBAfterInitError(db *sql.DB, initErr error) error {
	if db == nil {
		return initErr
	}
	if closeErr := db.Close(); closeErr != nil {
		return fmt.Errorf("%w; additionally failed to close database: %v", initErr, closeErr)
	}
	return initErr
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		// Stop and join background flush/cleanup goroutines before the final drain
		// so they cannot race the database close or re-enqueue records afterward.
		if s.cancelLoops != nil {
			s.cancelLoops()
		}
		s.loopWG.Wait()
		flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.flushBuffers(flushCtx)
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

func (s *Store) startLoops(ctx context.Context) {
	s.loopWG.Add(1)
	go func() {
		defer s.loopWG.Done()
		ticker := time.NewTicker(s.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.flushBuffers(ctx)
			}
		}
	}()

	if !s.disableCleanup {
		s.loopWG.Add(1)
		go func() {
			defer s.loopWG.Done()
			ticker := time.NewTicker(s.cleanupInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := s.cleanup(ctx); err != nil {
						if ctx.Err() != nil {
							return // context cancelled, shutting down
						}
						log.Warn().Err(err).Msg("MySQL cleanup failed")
					}
				}
			}
		}()
	}
}

func (s *Store) flushBuffers(ctx context.Context) {
	strategyRecords := s.strategyBuffer.drain()
	if len(strategyRecords) > 0 {
		if err := s.upsertStrategies(ctx, strategyRecords); err != nil {
			log.Warn().Err(err).Int("count", len(strategyRecords)).Msg("MySQL strategy flush failed, re-enqueue")
			s.strategyBuffer.reEnqueue(strategyRecords)
		} else {
			log.Debug().Int("count", len(strategyRecords)).Msg("MySQL strategy flush complete")
		}
	}

	metaRecords := s.fileMetaBuffer.drain()
	if len(metaRecords) > 0 {
		if err := s.upsertFileMeta(ctx, metaRecords); err != nil {
			log.Warn().Err(err).Int("count", len(metaRecords)).Msg("MySQL file meta flush failed, re-enqueue")
			s.fileMetaBuffer.reEnqueue(metaRecords)
		} else {
			log.Debug().Int("count", len(metaRecords)).Msg("MySQL file meta flush complete")
		}
	}

	rangeCompatRecords := s.rangeCompatBuffer.drain()
	if len(rangeCompatRecords) > 0 {
		if err := s.upsertRangeCompats(ctx, rangeCompatRecords); err != nil {
			log.Warn().Err(err).Int("count", len(rangeCompatRecords)).Msg("MySQL range compat flush failed, re-enqueue")
			s.rangeCompatBuffer.reEnqueue(rangeCompatRecords)
		} else {
			log.Debug().Int("count", len(rangeCompatRecords)).Msg("MySQL range compat flush complete")
		}
	}
}

func (s *Store) cleanup(ctx context.Context) error {
	cutoff := time.Now().Add(-time.Duration(s.cleanupDays) * 24 * time.Hour)
	if err := s.markStrategyExpired(ctx, cutoff); err != nil {
		return err
	}
	if err := s.markFileMetaExpired(ctx, cutoff); err != nil {
		return err
	}
	if err := s.markRangeCompatExpired(ctx, cutoff); err != nil {
		return err
	}
	// 目录快照是纯缓存:命中后由请求侧按需重建,删除旧行不影响功能与播放链路。
	// 它的 payload 为完整目录列表,必须物理 DELETE 才能回收磁盘(软删不释放空间)。
	snapCutoff := time.Now().Add(-time.Duration(s.dirSnapCleanupDays) * 24 * time.Hour)
	if err := s.deleteExpiredDirSnapshots(ctx, snapCutoff); err != nil {
		return err
	}
	// 按目录收敛:同目录不同会话会产生大量几乎相同的大体积副本,收敛为 scan + 最新一份。
	if err := s.dedupeDirSnapshots(ctx); err != nil {
		return err
	}
	log.Debug().Time("cutoff", cutoff).Time("snap_cutoff", snapCutoff).Msg("MySQL cleanup complete")
	return nil
}

func normalizeDSN(dsn string) string {
	if dsn == "" {
		return dsn
	}
	params := []string{}
	if !strings.Contains(dsn, "parseTime=") {
		params = append(params, "parseTime=true")
	}
	if !strings.Contains(dsn, "loc=") {
		params = append(params, "loc=Local")
	}
	if len(params) == 0 {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + strings.Join(params, "&")
}
