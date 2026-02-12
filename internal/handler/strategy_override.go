package handler

import (
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

func selectStrategyOverride(cfg *config.Config, displayPath string) (proxy.StreamStrategy, bool) {
	if cfg == nil || displayPath == "" {
		return "", false
	}
	overrides := cfg.AlistServer.StreamStrategyOverrides
	if len(overrides) == 0 {
		return "", false
	}
	for _, override := range overrides {
		if override.PathPrefix == "" || override.Strategy == "" {
			continue
		}
		if strings.HasPrefix(displayPath, override.PathPrefix) {
			switch strings.ToLower(strings.TrimSpace(override.Strategy)) {
			case "full":
				return proxy.StreamStrategyFull, true
			case "chunked":
				return proxy.StreamStrategyChunked, true
			case "range":
				return proxy.StreamStrategyRange, true
			}
		}
	}
	return "", false
}
