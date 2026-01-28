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

	// Create and start server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Info().Msg("Received shutdown signal")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Error during shutdown")
		}
	}()

	// Start server
	if err := srv.Start(); err != nil {
		log.Fatal().Err(err).Msg("Server error")
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
