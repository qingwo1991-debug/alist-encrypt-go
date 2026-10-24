package handler

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/httputil"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// Size hydration is metadata-only, not playback warmup: one selected locator,
// bounded header/trailer reads, no decryption, KDF, range-capability test or
// FileSizeResolver. It shares the scheduler's queue/workers/provider slots and
// foreground pause. Request credentials live only in bounded queued/active work.
type propfindSizeAdmission struct {
	origin, identity string
	revision, epoch  uint64
	ciphertextSize   int64
}

// EnqueueObservedPropfindSize admits only an original upstream DAV transport
// length paired with this exact raw path, or that observation retained privately
// in a DAV snapshot. Generic display/plaintext sizes must never enter this API:
// a different observed ciphertext length revokes existing canonical proof.
func (ps *ProbeScheduler) EnqueueObservedPropfindSize(file FileItem, headers http.Header, observed int64, source string) {
	if ps == nil || !ps.enabled || ps.queue == nil {
		return
	}
	select {
	case <-ps.done():
		return
	default:
	}
	if ps.cfg == nil || ps.fileDAO == nil || ps.stream == nil || file.PasswdInfo == nil || !file.PasswdInfo.Enable || file.DisplayPath == "" || file.EncryptedPath == "" || observed <= 0 {
		return
	}
	// A caller without upstream credentials must not borrow service/scan auth.
	// Startup scans already supply their configured scan credential explicitly.
	if strings.TrimSpace(headers.Get("Authorization")) == "" && strings.TrimSpace(headers.Get("Cookie")) == "" {
		return
	}
	revision := ps.cfg.RuntimeRevision()
	alist := ps.cfg.AlistServerSnapshot()
	if !alist.EnableBackgroundProbe || alist.PlaybackProfile != config.PlaybackProfileTrustedLocal {
		return
	}
	rule := *file.PasswdInfo
	rule.EncPath = append([]string(nil), rule.EncPath...)
	ruleCurrent := false
	for i := range alist.PasswdList {
		if alist.PasswdList[i].Enable && filenameRuleScope(&alist.PasswdList[i]) == filenameRuleScope(&rule) {
			ruleCurrent = true
			break
		}
	}
	if !ruleCurrent || ps.cfg.RuntimeRevision() != revision {
		return
	}
	origin := config.BuildAlistURL(alist)
	identity := playbackIdentity(ps.cfg, origin, file.EncryptedPath, &rule, headers)
	changedCiphertext := false
	if confirmed, hit := ps.fileDAO.GetConfirmedPlayback(identity); hit && confirmed != nil {
		if confirmed.EncryptedPath == file.EncryptedPath && confirmed.CiphertextSize == observed {
			if _, complete := propfindSizeMeta(confirmed, rule.EncType); complete {
				return
			}
		} else if confirmed.CiphertextSize != observed {
			// A positively observed size change fences previous confirmations and
			// any in-flight publication before admitting replacement metadata.
			ps.fileDAO.InvalidateDisplayPath(file.DisplayPath)
			changedCiphertext = true
		}
	}
	file.PasswdInfo = &rule
	file.PropfindSize = observed // Always original transport size, never resolver plaintext.
	file.TargetURL = httputil.BuildTargetURLStripped(origin, "/dav"+file.EncryptedPath)
	admission := &propfindSizeAdmission{origin: origin, identity: identity, revision: revision, epoch: ps.fileDAO.PlaybackEpoch(file.DisplayPath), ciphertextSize: observed}
	key := probeCooldownKey(file)
	reserved, skip := ps.reserveProbe(key, changedCiphertext)
	if skip != "" {
		return
	}
	ps.queueMu.Lock()
	select {
	case <-ps.done():
		ps.queueMu.Unlock()
		ps.releaseProbeReservation(key, reserved, true)
		return
	default:
	}
	if len(ps.queue)+len(ps.waiting) >= cap(ps.queue) {
		ps.queueMu.Unlock()
		ps.releaseProbeReservation(key, reserved, true)
		atomic.AddUint64(&ps.droppedTotal, 1)
		return
	}
	ps.queue <- probeItem{file: file, authHeaders: headers.Clone(), source: normalizeProbeSource(source), queuedAt: time.Now(), sizeOnly: admission}
	atomic.AddUint64(&ps.filesDiscoveredTotal, 1)
	atomic.AddUint64(&ps.enqueuedTotal, 1)
	atomic.AddUint64(&ps.filesQueuedTotal, 1)
	ps.notifyDispatchLocked()
	ps.queueMu.Unlock()
}

func (ps *ProbeScheduler) propfindSizeAdmissionCurrent(item probeItem) bool {
	a := item.sizeOnly
	return a != nil && ps.cfg != nil && ps.fileDAO != nil && ps.cfg.RuntimeRevision() == a.revision && ps.cfg.GetAlistURL() == a.origin && ps.fileDAO.PlaybackEpoch(item.file.DisplayPath) == a.epoch
}

func (ps *ProbeScheduler) runPropfindSize(item probeItem, started time.Time) {
	state := probeExecutionResult{usedAuthMode: "request", sizeSource: "confirmed_container"}
	status := probeStatusFailed
	defer func() {
		if status == probeStatusSuccess {
			atomic.AddUint64(&ps.filesSucceededTotal, 1)
		} else {
			atomic.AddUint64(&ps.filesFailedTotal, 1)
		}
		// Confirmed hits are skipped before reservation. If proof expires or is
		// invalidated, permit replacement after a short bounded backoff instead
		// of suppressing missing metadata for the legacy day-long warmup TTL.
		ps.seenMu.Lock()
		ps.seen[probeCooldownKey(item.file)] = time.Now().Add(time.Minute - ps.cooldown)
		ps.seenMu.Unlock()
		ps.finishRecord(item, started, status, state)
	}()
	if !ps.propfindSizeAdmissionCurrent(item) || ps.stream == nil {
		state.failureReason = "size_probe_invalidated"
		return
	}
	a := item.sizeOnly
	if info, hit := ps.fileDAO.GetConfirmedPlayback(a.identity); hit && info != nil && info.EncryptedPath == item.file.EncryptedPath && info.CiphertextSize == a.ciphertextSize {
		if meta, complete := propfindSizeMeta(info, item.file.PasswdInfo.EncType); complete {
			state.resolvedSize, status = meta.PlainSize, probeStatusSuccess
			return
		}
	}
	ctx, cancel := context.WithTimeout(ps.probeContext(), 15*time.Second)
	defer cancel()
	// Resolve only with this item's supplied headers. No ensureAuth/login or
	// configured-credential fallbacks are admitted in the metadata-only path.
	locator := fetchRawURL(ctx, a.origin, item.file.DisplayPath, item.file.EncryptedPath, item.authHeaders, ps.fileDAO, 30*time.Minute)
	if ctx.Err() != nil || !ps.propfindSizeAdmissionCurrent(item) {
		state.failureReason = "size_probe_invalidated"
		return
	}
	target := item.file.TargetURL
	if locator.RawURL != "" {
		target = locator.RawURL
		state.rawURLFetched = true
		atomic.AddUint64(&ps.filesRawURLFetched, 1)
		if locator.Size > 0 && locator.Size != a.ciphertextSize {
			state.failureReason = "size_probe_ciphertext_changed"
			return
		}
	}
	probeHeaders := item.authHeaders
	upstreamURL, upstreamErr := url.Parse(a.origin)
	targetURL, targetErr := url.Parse(target)
	if upstreamErr != nil || targetErr != nil || !strings.EqualFold(upstreamURL.Scheme, targetURL.Scheme) || !strings.EqualFold(upstreamURL.Host, targetURL.Host) {
		// A signed CDN locator is its own credential. Never send the DAV/API
		// caller's Authorization, Cookie or provider headers to another origin.
		probeHeaders = make(http.Header)
	}
	result := ps.stream.InspectEncryptedContentResult(ctx, target, probeHeaders, item.file.PasswdInfo, a.ciphertextSize)
	if ctx.Err() != nil || !result.Confirmed || !ps.propfindSizeAdmissionCurrent(item) {
		state.failureReason = "size_probe_unconfirmed"
		return
	}
	info := playbackMetaInfo(decryptPlaybackRequest{FileItem: item.file}, result.Meta)
	info.GeometryIdentity, info.GeometryConfirmedAt = a.identity, time.Now()
	if info.CiphertextSize != a.ciphertextSize {
		state.failureReason = "size_probe_ciphertext_changed"
		return
	}
	if _, complete := propfindSizeMeta(info, item.file.PasswdInfo.EncType); !complete {
		state.failureReason = "size_probe_incomplete"
		return
	}
	// Serialize final local publication against configuration updates; DAO's
	// epoch fence independently covers mutations, refreshes and replacements.
	published, err := ps.cfg.PublishIfRevision(a.revision, func() error {
		if ctx.Err() != nil || !ps.fileDAO.PublishConfirmedPlayback(info, a.epoch) {
			return fmt.Errorf("size probe publication invalidated")
		}
		return nil
	})
	if !published || err != nil {
		state.failureReason = "size_probe_invalidated"
		return
	}
	state.resolvedSize, state.metaPersisted, status = info.Size, true, probeStatusSuccess
	atomic.AddUint64(&ps.filesMetaPersisted, 1)
}

// Validate actual persisted geometry, not a size-only listing or a fixed header
// subtraction. Unlike playback, metadata can represent a confirmed empty V1/V2.
func propfindSizeMeta(info *dao.FileInfo, encType string) (encryption.ContentMeta, bool) {
	if info == nil || info.IsDir || info.Size < 0 || info.CiphertextSize < 0 {
		return encryption.ContentMeta{}, false
	}
	meta := encryption.ContentMeta{EncType: encryption.EncType(encType), Version: info.ContentVersion, PlainSize: info.Size, CiphertextSize: info.CiphertextSize, HeaderLen: info.HeaderLen, NonceField: append([]byte(nil), info.NonceField...), ChunkSize: info.ChunkSize, KDFIterations: info.KDFIterations}
	switch meta.Version {
	case encryption.ContentVersionV1:
		return meta, encryption.IsRegistered(meta.EncType) && meta.PlainSize == meta.CiphertextSize && meta.HeaderLen == 0 && len(meta.NonceField) == 0 && meta.ChunkSize == 0 && meta.KDFIterations == 0
	case encryption.ContentVersionV2:
		if meta.HeaderLen != encryption.ContentHeaderSize() || len(meta.NonceField) != 16 || meta.ChunkSize != 0 || meta.KDFIterations != 0 || meta.PlainSize > math.MaxInt64-meta.HeaderLen || meta.CiphertextSize != meta.PlainSize+meta.HeaderLen {
			return encryption.ContentMeta{}, false
		}
		_, err := encryption.BuildV2Header(meta.EncType, meta.PlainSize, meta.NonceField)
		return meta, err == nil
	case encryption.ContentVersionV3:
		if meta.HeaderLen != encryption.V3HeaderSize || len(meta.NonceField) != 16 || meta.ChunkSize == 0 || meta.ChunkSize > 1<<30 || meta.KDFIterations == 0 || meta.KDFIterations > 10000000 || meta.CiphertextSize < meta.HeaderLen {
			return encryption.ContentMeta{}, false
		}
		chunks := meta.PlainSize / int64(meta.ChunkSize)
		if meta.PlainSize%int64(meta.ChunkSize) != 0 {
			chunks++
		}
		body, stride := meta.CiphertextSize-meta.HeaderLen, int64(meta.ChunkSize)+16
		// Streaming V3 may append its 16-byte EOF size trailer.
		valid := body%stride == 0 && body/stride == chunks
		valid = valid || body >= 16 && (body-16)%stride == 0 && (body-16)/stride == chunks
		return meta, valid
	default:
		return encryption.ContentMeta{}, false
	}
}
