package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/ports"
)

type playbackTransportAdmission struct {
	epoch           uint64
	identity, scope string
	revision        uint64
}
type playbackTransportKey struct{}

func playbackRawURLMatches(files ports.FileRepository, cfg *config.Config, raw string, headers http.Header, info *dao.FileInfo) bool {
	if _, managed := files.(playbackCacheRepository); !managed {
		return true
	}
	if cfg != nil && cfg.AlistServerSnapshot().PlaybackProfile != config.PlaybackProfileTrustedLocal && info != nil && info.RawURLIdentity == "" {
		return true
	}
	return cfg != nil && info != nil && info.RawURLIdentity == playbackIdentity(cfg, cfg.GetAlistURL(), raw, nil, headers)
}

func fetchRawURL(ctx context.Context, origin, display, raw string, headers http.Header, files ports.FileRepository, ttl time.Duration) rawURLFetchResult {
	if files == nil {
		return rawURLFetchResult{}
	}
	repo, ok := files.(playbackCacheRepository)
	if !ok {
		return fetchRawURLUnshared(ctx, origin, display, raw, headers, files, ttl)
	}
	cfg := files.Config()
	revision := uint64(0)
	configOrigin := ""
	if cfg != nil {
		revision = cfg.RuntimeRevision()
		configOrigin = cfg.GetAlistURL()
	}
	scope := playbackScope(cfg, headers)
	identity := playbackIdentity(cfg, origin, raw, nil, headers)
	epoch := repo.PlaybackEpoch(display)
	fresh := func() (rawURLFetchResult, bool) {
		if ttl > 0 {
			if info, hit := files.Get(display); hit && info != nil && (info.RawURLIdentity == identity || (info.RawURLIdentity == "" && scope != "trusted_local")) && cachedRawURLFresh(info, ttl, scope) {
				return rawURLFetchResult{RawURL: info.RawURL, Size: info.CiphertextSize, Source: "cache"}, true
			}
		}
		return rawURLFetchResult{}, false
	}
	if r, hit := fresh(); hit {
		return r
	}
	key := fmt.Sprintf("transport:%s:%d:%d", identity, epoch, revision)
	headers = headers.Clone()
	v, err := repo.DoPlaybackLoad(ctx, key, func(work context.Context) (interface{}, error) {
		if r, hit := fresh(); hit {
			return r, nil
		}
		work = context.WithValue(work, playbackTransportKey{}, playbackTransportAdmission{epoch: epoch, identity: identity, scope: scope, revision: revision})
		result := fetchRawURLUnshared(work, origin, display, raw, headers, files, 0)
		if work.Err() != nil || repo.PlaybackEpoch(display) != epoch || cfg != nil && (cfg.RuntimeRevision() != revision || cfg.GetAlistURL() != configOrigin) {
			return rawURLFetchResult{FailureReason: "raw_url_invalidated"}, nil
		}
		return result, nil
	})
	if err != nil || v == nil {
		return rawURLFetchResult{FailureReason: "raw_url_load_canceled"}
	}
	return v.(rawURLFetchResult)
}
func cachePlaybackRawURL(ctx context.Context, files ports.FileRepository, display, raw, url string, size int64, headers http.Header) bool {
	if strings.TrimSpace(url) == "" {
		return false
	}
	admission, managed := ctx.Value(playbackTransportKey{}).(playbackTransportAdmission)
	scope := rawURLAuthScope(headers)
	info := &dao.FileInfo{Path: display, EncryptedPath: raw, RawURL: url, RawURLAuthScope: scope, UpstreamFetchedAt: time.Now()}
	// A locator response never establishes plaintext length or replaces confirmed geometry.
	if existing, ok := files.Get(display); !ok || existing == nil || existing.ContentVersion == 0 {
		info.CiphertextSize = size
	}
	if managed {
		cfg := files.Config()
		if ctx.Err() != nil || cfg != nil && cfg.RuntimeRevision() != admission.revision {
			return false
		}
		info.RawURLIdentity = admission.identity
		info.RawURLAuthScope = admission.scope
		return publishPlaybackTransport(files, info, admission.epoch)
	}
	return files.Set(info) == nil
}
