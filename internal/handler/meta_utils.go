package handler

import (
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func getMinMetaSize(cfg *config.Config) int64 {
	if cfg == nil {
		return 0
	}
	return cfg.AlistServerSnapshot().ProbeMinSizeBytes
}

func getAlistRequestTimeout(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	alist := cfg.AlistServerSnapshot()
	if alist.RequestTimeoutSeconds <= 0 {
		return 0
	}
	return time.Duration(alist.RequestTimeoutSeconds) * time.Second
}

func getRedirectMaxHops(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.AlistServerSnapshot().RedirectMaxHops
}

func getNegativeCacheTTL(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	alist := cfg.AlistServerSnapshot()
	if alist.NegativeCacheMinutes <= 0 {
		return 0
	}
	return time.Duration(alist.NegativeCacheMinutes) * time.Minute
}

func getStartupProbeDelay(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	alist := cfg.AlistServerSnapshot()
	if alist.StartupProbeDelaySeconds <= 0 {
		return 0
	}
	return time.Duration(alist.StartupProbeDelaySeconds) * time.Second
}

func getStartupProbeInterval(cfg *config.Config) time.Duration {
	if cfg == nil {
		return 0
	}
	alist := cfg.AlistServerSnapshot()
	if alist.StartupProbeIntervalMinutes <= 0 {
		return 0
	}
	return time.Duration(alist.StartupProbeIntervalMinutes) * time.Minute
}
