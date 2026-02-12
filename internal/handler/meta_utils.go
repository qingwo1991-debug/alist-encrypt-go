package handler

import (
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func getMinMetaSize(cfg *config.Config) int64 {
	if cfg == nil {
		return 0
	}
	return cfg.AlistServer.ProbeMinSizeBytes
}

func getAlistRequestTimeout(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	if cfg.AlistServer.RequestTimeoutSeconds <= 0 {
		return 0
	}
	return time.Duration(cfg.AlistServer.RequestTimeoutSeconds) * time.Second
}

func getRedirectMaxHops(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.AlistServer.RedirectMaxHops
}
