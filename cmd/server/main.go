package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/restart"
	"github.com/alist-encrypt-go/internal/server"
)

func main() {
	// Load configuration first
	cfg := config.Load()

	// Setup logging based on config
	setupLogging(cfg)

	log.Info().Msg("Starting alist-encrypt-go")
	log.Info().
		Str("http_addr", cfg.GetHTTPAddr()).
		Bool("h2c", cfg.Scheme.EnableH2C).
		Bool("https", cfg.IsHTTPSEnabled()).
		Str("alist_url", cfg.GetAlistURL()).
		Msg("Configuration loaded")

	// Server restart loop - allows graceful restart when H2C changes
	for {
		// Create and start server
		srv, err := server.New(cfg)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create server")
		}

		// Channel to signal restart
		restartChan := make(chan struct{})
		shutdownChan := make(chan struct{})
		doneChan := make(chan struct{})

		// Graceful shutdown handler
		go func() {
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			select {
			case <-sigChan:
				log.Info().Msg("Received shutdown signal")
				close(shutdownChan)
			case <-restartChan:
				log.Info().Msg("Restart requested")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if err := srv.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msg("Error during shutdown")
			}
			close(doneChan)
		}()

		// Export restart channel for API to trigger restart
		restart.SetChan(restartChan)

		// Start server (blocks until shutdown)
		if err := srv.Start(); err != nil {
			log.Error().Err(err).Msg("Server stopped")
		}

		// Wait for shutdown to complete
		<-doneChan

		// Check if we should exit or restart
		select {
		case <-shutdownChan:
			log.Info().Msg("Server shutdown complete")
			return
		default:
			// Restart - reload config and continue loop
			log.Info().Msg("Restarting server...")
			time.Sleep(500 * time.Millisecond) // Brief pause before restart
		}
	}
}

func setupLogging(cfg *config.Config) {
	// Set time format
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Set log level
	switch cfg.Log.Level {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// Set output format
	if cfg.Log.Format == "console" {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	}

	// TODO: Add file output support with rotation
}
