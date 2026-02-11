package handler

import "github.com/alist-encrypt-go/internal/config"

func getMinMetaSize(cfg *config.Config) int64 {
	if cfg == nil {
		return 0
	}
	return cfg.AlistServer.ProbeMinSizeBytes
}
