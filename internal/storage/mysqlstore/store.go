package mysqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
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
	disableCleanup    bool
	strategyBuffer    *strategyBuffer
	fileMetaBuffer    *fileMetaBuffer
	rangeCompatBuffer *rangeCompatBuffer
	cancelLoops       context.CancelFunc // cancels background flush/cleanup goroutines
}

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

	db, err := sql.Open("mysql", dsn)
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
		return nil, err
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

	store := &Store{
		db:                db,
		flushInterval:     flushInterval,
		cleanupInterval:   cleanupInterval,
		cleanupDays:       cleanupDays,
		disableCleanup:    cfg.Database.DisableCleanup,
		strategyBuffer:    newStrategyBuffer(),
		fileMetaBuffer:    newFileMetaBuffer(),
		rangeCompatBuffer: newRangeCompatBuffer(),
	}

	schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer schemaCancel()
	if err := store.ensureSchema(schemaCtx); err != nil {
		return nil, err
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

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	// Stop background flush/cleanup goroutines
	if s.cancelLoops != nil {
		s.cancelLoops()
	}
	// Flush all pending write-behind buffers before closing the connection,
	// otherwise data buffered within the flush interval window will be lost.
	flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.flushBuffers(flushCtx)
	return s.db.Close()
}

func (s *Store) startLoops(ctx context.Context) {
	go func() {
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
		go func() {
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
	log.Debug().Time("cutoff", cutoff).Msg("MySQL cleanup complete")
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
