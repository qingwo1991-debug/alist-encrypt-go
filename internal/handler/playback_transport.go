package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

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
		if cfg != nil {
			published, err := cfg.PublishIfRevision(admission.revision, func() error {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !publishPlaybackTransport(files, info, admission.epoch) {
					return fmt.Errorf("transport publication invalidated")
				}
				return nil
			})
			return published && err == nil
		}
		return publishPlaybackTransport(files, info, admission.epoch)
	}
	return files.Set(info) == nil
}

const maxWebDAVRawWarmups = 4

// No backlog and no completed-failure cache: optional warmups cannot accumulate
// credentials or turn authentication/network failures into driver capability.
// Stop and request cancellation own the actual I/O, not just a shared-load waiter.
type webdavRawWarmups struct {
	mu      sync.Mutex
	pending map[string]context.CancelFunc
	stopped bool
	wg      sync.WaitGroup
}

func (s *webdavRawWarmups) stop() {
	s.mu.Lock()
	s.stopped = true
	for _, cancel := range s.pending {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (h *WebDAVHandler) enqueueRawURLWarmup(r *http.Request, display, raw string) bool {
	if h == nil || h.cfg == nil || h.fileDAO == nil || r == nil || r.Context().Err() != nil || strings.TrimSpace(display) == "" || strings.TrimSpace(raw) == "" {
		return false
	}
	// OpenList metadata auth accepts a JWT, not DAV Basic. Never manufacture a
	// JWT or borrow configured scan/admin credentials to warm another caller.
	if fields := strings.Fields(r.Header.Get("Authorization")); len(fields) > 0 && strings.EqualFold(fields[0], "Basic") {
		return false
	}
	repo, managed := h.fileDAO.(playbackCacheRepository)
	if !managed {
		// Background publication requires atomic epoch fencing.
		return false
	}
	origin, revision := h.cfg.GetAlistURL(), h.cfg.RuntimeRevision()
	epoch := repo.PlaybackEpoch(display)
	headers := make(http.Header)
	headers.Set("Authorization", r.Header.Get("Authorization"))
	headers.Set("Cookie", r.Header.Get("Cookie"))
	ttl := h.upstreamStalenessThreshold()
	if info, hit := h.fileDAO.Get(display); hit && playbackRawURLMatches(h.fileDAO, h.cfg, raw, headers, info) && cachedRawURLFresh(info, ttl, playbackScope(h.cfg, headers)) {
		return false
	}
	identity := playbackIdentity(h.cfg, origin, raw, nil, headers)
	// Trusted-local geometry may be shared, but pending credential-bearing work
	// must still be partitioned by explicit incoming Authorization AND Cookie.
	key := fmt.Sprintf("%s:%s:%s:%d:%d", identity, display, rawURLAuthScope(headers), epoch, revision)
	s := &h.rawWarmups
	s.mu.Lock()
	if s.stopped || len(s.pending) >= maxWebDAVRawWarmups || s.pending[key] != nil {
		s.mu.Unlock()
		return false
	}
	if s.pending == nil {
		s.pending = make(map[string]context.CancelFunc)
	}
	ctx, cancel := context.WithTimeout(r.Context(), finalRawURLResolveTimeout)
	s.pending[key] = cancel
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.pending, key)
			s.mu.Unlock()
		}()
		if ctx.Err() != nil || repo.PlaybackEpoch(display) != epoch || h.cfg.RuntimeRevision() != revision || h.cfg.GetAlistURL() != origin {
			return
		}
		ctx = context.WithValue(ctx, playbackTransportKey{}, playbackTransportAdmission{epoch: epoch, identity: identity, scope: playbackScope(h.cfg, headers), revision: revision})
		started := time.Now()
		// Own this bounded load directly: DoPlaybackLoad may release its waiter
		// before its I/O exits, which would make handler Stop unable to join it.
		result := fetchRawURLUnshared(ctx, origin, display, raw, headers, h.fileDAO, 0)
		// Do not log upstream messages, signed URLs, credentials or network errors.
		log.Debug().Str("category", "webdav_get").Str("phase", "raw_url_async").
			Str("source", result.Source).Int("status", result.StatusCode).
			Int("business_code", result.BusinessCode).Bool("raw_url_found", result.RawURL != "").
			Int64("duration_ms", time.Since(started).Milliseconds()).Msg("Optional raw URL warmup finished")
	}()
	return true
}
