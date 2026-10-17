package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/ports"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type playbackCacheRepository interface {
	PlaybackEpoch(string) uint64
	GetConfirmedPlayback(string) (*dao.FileInfo, bool)
	PublishConfirmedPlayback(*dao.FileInfo, uint64) bool
	PublishPlaybackInfo(*dao.FileInfo, uint64) bool
	DoPlaybackLoad(context.Context, string, func(context.Context) (interface{}, error)) (interface{}, error)
}

func playbackScope(cfg *config.Config, headers http.Header) string {
	if cfg != nil && cfg.AlistServerSnapshot().PlaybackProfile == config.PlaybackProfileTrustedLocal {
		return "trusted_local"
	}
	return rawURLAuthScope(headers)
}
func playbackIdentity(cfg *config.Config, origin, raw string, passwd *config.PasswdInfo, headers http.Header) string {
	rule := ""
	if passwd != nil {
		rule = filenameRuleScope(passwd)
	}
	profile := "standard"
	if cfg != nil {
		profile = cfg.AlistServerSnapshot().PlaybackProfile
	}
	sum := sha256.Sum256([]byte(origin + "\x00" + raw + "\x00" + rule + "\x00" + profile + "\x00" + playbackScope(cfg, headers)))
	return hex.EncodeToString(sum[:])
}
func managedPlaybackGeometry(req decryptPlaybackRequest) bool {
	_, ok := req.FileDAO.(playbackCacheRepository)
	return ok && req.Config != nil && req.Config.AlistServerSnapshot().PlaybackProfile == config.PlaybackProfileTrustedLocal && req.Request != nil && req.PasswdInfo != nil && req.FileItem.DisplayPath != "" && req.FileItem.EncryptedPath != ""
}
func confirmedPlaybackMeta(req decryptPlaybackRequest, headers http.Header, fallback int64) (encryption.ContentMeta, bool) {
	repo, ok := req.FileDAO.(playbackCacheRepository)
	if !ok || !managedPlaybackGeometry(req) {
		return inspectPlaybackContentMeta(req, headers, fallback)
	}
	origin, revision := req.Config.GetAlistURL(), req.Config.RuntimeRevision()
	identity := playbackIdentity(req.Config, origin, req.FileItem.EncryptedPath, req.PasswdInfo, headers)
	epoch := repo.PlaybackEpoch(req.FileItem.DisplayPath)
	if req.ExpectedGeometryEpoch != nil && *req.ExpectedGeometryEpoch != epoch || req.ExpectedConfigRevision != nil && *req.ExpectedConfigRevision != revision {
		return encryption.ContentMeta{}, false
	}
	if info, hit := repo.GetConfirmedPlayback(identity); hit {
		if meta, complete := cachedPlaybackMeta(info, req.PasswdInfo.EncType); complete {
			return meta, true
		}
	}
	key := fmt.Sprintf("geometry:%s:%d:%d", identity, epoch, revision)
	value, err := repo.DoPlaybackLoad(req.Request.Context(), key, func(ctx context.Context) (interface{}, error) {
		if info, hit := repo.GetConfirmedPlayback(identity); hit {
			if meta, complete := cachedPlaybackMeta(info, req.PasswdInfo.EncType); complete {
				return meta, nil
			}
		}
		owned := req
		owned.Request = req.Request.Clone(ctx)
		meta, confirmed := inspectPlaybackContentMeta(owned, headers, fallback)
		if !confirmed {
			return nil, fmt.Errorf("content inspection unconfirmed")
		}
		if ctx.Err() != nil || req.Config.RuntimeRevision() != revision || req.Config.GetAlistURL() != origin || repo.PlaybackEpoch(req.FileItem.DisplayPath) != epoch {
			return nil, fmt.Errorf("content inspection invalidated")
		}
		info := playbackMetaInfo(req, meta)
		info.GeometryIdentity, info.GeometryConfirmedAt = identity, time.Now()
		if _, complete := cachedPlaybackMeta(info, req.PasswdInfo.EncType); !complete {
			return nil, fmt.Errorf("content inspection incomplete")
		}
		if !repo.PublishConfirmedPlayback(info, epoch) {
			return nil, fmt.Errorf("content publication invalidated")
		}
		return meta, nil
	})
	if err != nil || value == nil {
		return encryption.ContentMeta{}, false
	}
	if req.Config.RuntimeRevision() != revision || repo.PlaybackEpoch(req.FileItem.DisplayPath) != epoch {
		return encryption.ContentMeta{}, false
	}
	meta, ok := value.(encryption.ContentMeta)
	return meta, ok
}
func playbackMetaInfo(req decryptPlaybackRequest, meta encryption.ContentMeta) *dao.FileInfo {
	return &dao.FileInfo{Path: req.FileItem.DisplayPath, EncryptedPath: req.FileItem.EncryptedPath, Name: req.FileItem.FileName, Size: meta.PlainSize, CiphertextSize: meta.TotalCiphertextSize(), ContentVersion: meta.Version, HeaderLen: meta.HeaderLen, NonceField: append([]byte(nil), meta.NonceField...), ChunkSize: meta.ChunkSize, KDFIterations: meta.KDFIterations}
}

// confirmPropfindGeometry joins playback's logical-object loader. A signed URL
// may work when DAV media GET is disabled even though DAV metadata is available.
func (h *WebDAVHandler) confirmPropfindGeometry(r *http.Request, display, raw string, rule *config.PasswdInfo, observed int64) {
	repo, ok := h.fileDAO.(playbackCacheRepository)
	if !ok || h.streamProxy == nil {
		return
	}
	epoch := repo.PlaybackEpoch(display)
	revision, origin := h.cfg.RuntimeRevision(), h.cfg.GetAlistURL()
	identity := playbackIdentity(h.cfg, h.cfg.GetAlistURL(), raw, rule, r.Header)
	var meta encryption.ContentMeta
	var confirmed bool
	if info, hit := repo.GetConfirmedPlayback(identity); hit {
		meta, confirmed = cachedPlaybackMeta(info, rule.EncType)
		if confirmed && observed > 0 && meta.TotalCiphertextSize() != observed {
			h.fileDAO.InvalidateDisplayPath(display)
			epoch = repo.PlaybackEpoch(display)
			confirmed = false
		}
	}
	if !confirmed {
		target := httputil.BuildTargetURLStripped(h.cfg.GetAlistURL(), "/dav"+raw)
		result := fetchRawURL(r.Context(), h.cfg.GetAlistURL(), display, raw, r.Header, h.fileDAO, h.upstreamStalenessThreshold())
		if result.RawURL != "" {
			target = result.RawURL
		}
		req := decryptPlaybackRequest{Request: r, Config: h.cfg, FileDAO: h.fileDAO, StreamProxy: h.streamProxy, PasswdInfo: rule, FileItem: FileItem{DisplayPath: display, EncryptedPath: raw}, TargetURL: target, ConsumerScenario: consumerScenarioWebDAV, ExpectedGeometryEpoch: &epoch, ExpectedConfigRevision: &revision}
		meta, confirmed = confirmedPlaybackMeta(req, r.Header, observed)
	}
	if !confirmed || r.Context().Err() != nil || h.cfg.RuntimeRevision() != revision || h.cfg.GetAlistURL() != origin {
		return
	}
	// LP0's XML rewrite keys by the exact raw href. Mirror only through the same
	// epoch fence; GET/HEAD keep the canonical confirmed record under display.
	mirror := &dao.FileInfo{Path: raw, EncryptedPath: raw, Size: meta.PlainSize, CiphertextSize: meta.TotalCiphertextSize(), ContentVersion: meta.Version, HeaderLen: meta.HeaderLen, NonceField: append([]byte(nil), meta.NonceField...), ChunkSize: meta.ChunkSize, KDFIterations: meta.KDFIterations, GeometryIdentity: identity, GeometryConfirmedAt: time.Now()}
	repo.PublishPlaybackInfo(mirror, epoch)
}

// No raw URL response size may overwrite confirmed plaintext/container geometry.
func publishPlaybackTransport(files ports.FileRepository, info *dao.FileInfo, epoch uint64) bool {
	if repo, ok := files.(playbackCacheRepository); ok {
		return repo.PublishPlaybackInfo(info, epoch)
	}
	return files.Set(info) == nil
}
