package handler

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/encryption"
	"github.com/alist-encrypt-go/internal/httputil"
	"github.com/alist-encrypt-go/internal/proxy"
)

type decryptPlaybackRequest struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request

	Config           *config.Config
	Probe            *ProbeScheduler
	StreamProxy      *proxy.StreamProxy
	FileDAO          *dao.FileDAO
	SizeResolver     *FileSizeResolver
	StrategySel      *StrategySelector
	PasswdInfo       *config.PasswdInfo
	FileItem         FileItem
	TargetURL        string
	ProviderKey      string
	Path             string
	InitialSize      int64
	OverridePath     string
	CompatKey        string
	ConsumerScenario string
	FailureLogMsg    string
	LogCategory      string

	FinalPassthroughCount *uint64
	SizeConflictCount     *uint64
	FirstFrameCount       *uint64
	FirstFrameFallbacks   *uint64
	WarmupEnqueueCount    *uint64

	StatsRecorder StatsRecorder
}

// StatsRecorder 播放统计的记录接口。为 nil 时不记录（保持零开销）。
type StatsRecorder interface {
	RecordPlayback(ev PlaybackEvent)
	// RecordDeletion 记录一次文件删除。path 为展示路径（明文）。
	RecordDeletion(path string)
}

func executeDecryptPlayback(req decryptPlaybackRequest) {
	w := req.ResponseWriter
	r := req.Request
	alist := config.AlistServer{}
	if req.Config != nil {
		alist = req.Config.AlistServerSnapshot()
	}
	if req.StreamProxy != nil {
		release, ok := req.StreamProxy.AcquireStream()
		if !ok {
			status := http.StatusTooManyRequests
			if req.Config != nil && alist.StreamOverloadStatus == http.StatusServiceUnavailable {
				status = http.StatusServiceUnavailable
			}
			w.Header().Set("Retry-After", "2")
			RespondHTTPErrorWithStatus(w, "too many active streams", status)
			return
		}
		defer release()
	}
	fileSize := req.InitialSize
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}
	rawURLScope := rawURLAuthScope(authHeaders)

	metaLoaded := false
	if req.FileDAO != nil && req.FileItem.DisplayPath != "" {
		if info, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && info != nil && info.ContentVersion > 0 {
			if info.ContentVersion != encryption.ContentVersionV2 || len(info.NonceField) == 16 {
				meta := encryption.ContentMeta{
					EncType:        encryption.EncType(req.PasswdInfo.EncType),
					Version:        info.ContentVersion,
					HeaderLen:      info.HeaderLen,
					PlainSize:      info.Size,
					CiphertextSize: info.CiphertextSize,
					NonceField:     append([]byte(nil), info.NonceField...),
				}
				r = r.WithContext(proxy.WithContentMeta(r.Context(), meta))
				req.Request = r
				metaLoaded = true
				log.Info().
					Str("category", "playback").
					Str("consumer_scenario", req.ConsumerScenario).
					Str("path", req.Path).
					Int("content_version", info.ContentVersion).
					Int64("plain_size", info.Size).
					Int64("ciphertext_size", info.CiphertextSize).
					Int64("header_len", info.HeaderLen).
					Int("nonce_len", len(info.NonceField)).
					Msg("Loaded cached playback content meta")
			} else {
				log.Info().
					Str("category", "playback").
					Str("consumer_scenario", req.ConsumerScenario).
					Str("path", req.Path).
					Msg("Skipping cached V2 playback meta without nonce; forcing reprobe")
			}
		}
	}
	if !metaLoaded {
		if inspectedMeta, ok := inspectPlaybackContentMeta(req, authHeaders, fileSize); ok {
			r = r.WithContext(proxy.WithContentMeta(r.Context(), inspectedMeta))
			req.Request = r
			if inspectedMeta.PlainSize > 0 {
				fileSize = inspectedMeta.PlainSize
			}
			cachePlaybackContentMeta(req, inspectedMeta)
		}
	}

	if fileSize == 0 && req.SizeResolver != nil {
		fresh := req.SizeResolver.ResolveSingleFresh(r.Context(), req.FileItem, authHeaders)
		if fresh.Error == nil && fresh.Size > 0 {
			fileSize = fresh.Size
		}
	}

	if fileSize == 0 {
		if req.Config == nil || alist.SizeUnknownStrict {
			RespondHTTPErrorWithStatus(w, "Unable to determine encrypted file size", http.StatusBadGateway)
			return
		}
		if err := req.StreamProxy.ProxyRequest(w, r, req.TargetURL); err != nil {
			log.Error().Err(err).Str("path", req.Path).Msg(req.FailureLogMsg + " (size unknown passthrough)")
			RespondHTTPErrorWithStatus(w, "Proxy error", http.StatusBadGateway)
		}
		return
	}

	strategy := req.StreamProxy.SelectOptimalStrategy(req.TargetURL, req.CompatKey, r.Method, r.Header.Get("Range"))
	if override, ok := selectStrategyOverride(req.Config, req.OverridePath); ok {
		strategy = override
	}
	firstFrameHint := proxy.IsFirstFrameRangeHint(r.Method, r.Header.Get("Range"))
	initialPlaybackHint := proxy.IsInitialPlaybackHint(r.Method, r.Header.Get("Range"))
	if initialPlaybackHint && req.FirstFrameCount != nil {
		atomic.AddUint64(req.FirstFrameCount, 1)
	}
	lastUpstreamStatus := 0

	trySingle := func(size int64) (bool, string, error) {
		log.Info().
			Str("category", "playback").
			Str("consumer_scenario", req.ConsumerScenario).
			Str("path", req.Path).
			Str("target_url", req.TargetURL).
			Str("range", r.Header.Get("Range")).
			Str("strategy", string(strategy)).
			Int64("file_size", size).
			Bool("meta_loaded", metaLoaded).
			Bool("first_frame_hint", firstFrameHint).
			Bool("initial_playback_hint", initialPlaybackHint).
			Msg("Starting decrypt playback attempt")
		result := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
			w, r, req.TargetURL, req.PasswdInfo, size, strategy, req.CompatKey,
		)
		if result.StatusCode != 0 {
			lastUpstreamStatus = result.StatusCode
		}
		if playbackOutcomeServed(result) {
			req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, strategy)
			if req.StrategySel != nil && !result.NoLearning {
				req.StrategySel.RecordSuccess(req.ProviderKey, strategy)
			}
			if req.SizeResolver != nil && r.Method == http.MethodGet && !result.NoLearning {
				req.SizeResolver.RecordPlaybackSuccess(
					r.Context(), req.FileItem, size, result.StatusCode, result.ContentType, result.ETag,
				)
			}
			if req.Probe != nil {
				req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
			}
			maybeEnqueueFirstFrameWarmup(req, authHeaders, initialPlaybackHint, size, result.ExpectedBytes)
			if req.StatsRecorder != nil {
				req.StatsRecorder.RecordPlayback(PlaybackEvent{
					Path:         req.FileItem.DisplayPath,
					Provider:     req.ProviderKey,
					BytesServed:  result.BytesWritten,
					TotalBytes:   size,
					DurationSecs: result.WallDuration.Seconds(),
					PlayedAt:     time.Now(),
					Completed:    result.FailureReason == "" && result.BytesWritten >= result.ExpectedBytes,
					ContentType:  result.ContentType,
					RangeStart:   rangeStartFromHeader(r.Header.Get("Range")),
				})
			}
			return true, "", nil
		}

		reason := result.FailureReason
		if reason == "" && result.Err != nil {
			reason = "stream_error"
		}
		if reason == "" {
			reason = "unknown"
		}
		logDecryptFailure(req, strategy, reason, false)

		if req.StrategySel != nil && !result.NoLearning && result.Retryable && !result.ResponseStarted {
			req.StrategySel.RecordFailure(req.ProviderKey, strategy, reason)
		}

		if isWebDAVUpstreamFailure(reason) && !result.ResponseStarted {
			if fallbackTarget := webDAVInternalPlaybackTarget(req); fallbackTarget != "" && !strings.EqualFold(fallbackTarget, req.TargetURL) {
				fallbackFile := req.FileItem
				fallbackFile.TargetURL = fallbackTarget
				fallbackProvider := ProviderKey(fallbackTarget, req.FileItem.DisplayPath)
				fallback := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
					w, r, fallbackTarget, req.PasswdInfo, size, strategy, req.CompatKey,
				)
				if fallback.StatusCode != 0 {
					lastUpstreamStatus = fallback.StatusCode
				}
				if playbackOutcomeServed(fallback) {
					req.StreamProxy.RecordPlaybackHint(fallbackTarget, req.CompatKey, strategy)
					if req.StrategySel != nil && !fallback.NoLearning {
						req.StrategySel.RecordSuccess(fallbackProvider, strategy)
					}
					if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
						req.SizeResolver.RecordPlaybackSuccess(
							r.Context(), fallbackFile, size, fallback.StatusCode, fallback.ContentType, fallback.ETag,
						)
					}
					if req.Probe != nil {
						req.Probe.RecordConsumerHit(fallbackFile, req.ConsumerScenario)
					}
					maybeEnqueueFirstFrameWarmup(req, authHeaders, initialPlaybackHint, size, fallback.ExpectedBytes)
					return true, "", nil
				}
				if fallback.Err != nil {
					fallbackReason := fallback.FailureReason
					if fallbackReason == "" {
						fallbackReason = reason
					}
					return false, fallbackReason, fallback.Err
				}
				return false, reason, result.Err
			}
		}

		if reason == "range_unsupported" && !result.ResponseStarted && strategy == proxy.StreamStrategyRange {
			if req.FirstFrameFallbacks != nil {
				atomic.AddUint64(req.FirstFrameFallbacks, 1)
			}
			fallbackStrategy := proxy.StreamStrategyChunked
			fallback := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
				w, r, req.TargetURL, req.PasswdInfo, size, fallbackStrategy, req.CompatKey,
			)
			if fallback.StatusCode != 0 {
				lastUpstreamStatus = fallback.StatusCode
			}
			// Chunked 偏移太大时，二次回退到 Full 策略（下载整个文件再 seek）
			if fallback.Err != nil && fallback.FailureReason == "chunked_seek_too_large" {
				fallbackStrategy = proxy.StreamStrategyFull
				fallback = req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
					w, r, req.TargetURL, req.PasswdInfo, size, fallbackStrategy, req.CompatKey,
				)
				if fallback.StatusCode != 0 {
					lastUpstreamStatus = fallback.StatusCode
				}
			}
			if playbackOutcomeServed(fallback) {
				req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, fallbackStrategy)
				if req.StrategySel != nil && !fallback.NoLearning {
					req.StrategySel.RecordSuccess(req.ProviderKey, fallbackStrategy)
				}
				if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
					req.SizeResolver.RecordPlaybackSuccess(
						r.Context(), req.FileItem, size, fallback.StatusCode, fallback.ContentType, fallback.ETag,
					)
				}
				if req.Probe != nil {
					req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
				}
				maybeEnqueueFirstFrameWarmup(req, authHeaders, initialPlaybackHint, size, fallback.ExpectedBytes)
				return true, "", nil
			}
			if fallback.Err != nil {
				return false, "range_unsupported", fallback.Err
			}
			return false, "range_unsupported", result.Err
		}

		if reason == "range_unsatisfiable" && !result.ResponseStarted {
			fallback := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
				w, r, req.TargetURL, req.PasswdInfo, size, proxy.StreamStrategyFull, req.CompatKey,
			)
			if fallback.StatusCode != 0 {
				lastUpstreamStatus = fallback.StatusCode
			}
			if playbackOutcomeServed(fallback) {
				req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, proxy.StreamStrategyFull)
				if req.StrategySel != nil && !fallback.NoLearning {
					req.StrategySel.RecordSuccess(req.ProviderKey, proxy.StreamStrategyFull)
				}
				if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
					req.SizeResolver.RecordPlaybackSuccess(
						r.Context(), req.FileItem, size, fallback.StatusCode, fallback.ContentType, fallback.ETag,
					)
				}
				if req.Probe != nil {
					req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
				}
				maybeEnqueueFirstFrameWarmup(req, authHeaders, initialPlaybackHint, size, fallback.ExpectedBytes)
				return true, "", nil
			}
			if fallback.Err != nil {
				return false, "range_unsatisfiable", fallback.Err
			}
			return false, "range_unsatisfiable", result.Err
		}

		// 当策略直接选了 Chunked 但 seek 偏移超过 maxDiscard 时，回退到 Full 策略
		if reason == "chunked_seek_too_large" && !result.ResponseStarted && strategy == proxy.StreamStrategyChunked {
			fallback := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
				w, r, req.TargetURL, req.PasswdInfo, size, proxy.StreamStrategyFull, req.CompatKey,
			)
			if fallback.StatusCode != 0 {
				lastUpstreamStatus = fallback.StatusCode
			}
			if playbackOutcomeServed(fallback) {
				req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, proxy.StreamStrategyFull)
				if req.StrategySel != nil && !fallback.NoLearning {
					req.StrategySel.RecordSuccess(req.ProviderKey, proxy.StreamStrategyFull)
				}
				if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
					req.SizeResolver.RecordPlaybackSuccess(
						r.Context(), req.FileItem, size, fallback.StatusCode, fallback.ContentType, fallback.ETag,
					)
				}
				if req.Probe != nil {
					req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
				}
				maybeEnqueueFirstFrameWarmup(req, authHeaders, initialPlaybackHint, size, fallback.ExpectedBytes)
				return true, "", nil
			}
			if fallback.Err != nil {
				return false, "chunked_seek_too_large", fallback.Err
			}
			return false, "chunked_seek_too_large", result.Err
		}

		if result.Err != nil {
			return false, reason, result.Err
		}
		return false, reason, fmt.Errorf("strategy %s failed: %s", strategy, reason)
	}

	success, lastFailure, lastErr := trySingle(fileSize)
	if success {
		return
	}

	if shouldRetryFreshResolve(lastFailure, firstFrameHint, req.ConsumerScenario) {
		logDecryptFailure(req, strategy, lastFailure, true)
		retryWithFreshState := false
		if (req.ConsumerScenario == consumerScenarioRedirect || req.ConsumerScenario == consumerScenarioHTTP) &&
			req.FileDAO != nil && req.FileItem.DisplayPath != "" && req.Config != nil {
			authCopy := cloneHeader(authHeaders)
			probeFreshContent := true
			if cached, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && cached != nil {
				probeFreshContent = cached.ContentVersion <= 0 ||
					(cached.ContentVersion == encryption.ContentVersionV2 && len(cached.NonceField) != 16)
			}
			freshRaw := fetchRawURL(r.Context(), req.Config.GetAlistURL(), req.FileItem.DisplayPath, req.FileItem.EncryptedPath, authCopy, req.FileDAO, 0)
			if strings.TrimSpace(freshRaw.RawURL) != "" {
				retryWithFreshState = !strings.EqualFold(req.TargetURL, freshRaw.RawURL)
				req.TargetURL = freshRaw.RawURL
				req.FileItem.TargetURL = freshRaw.RawURL
				req.ProviderKey = ProviderKey(freshRaw.RawURL, req.FileItem.DisplayPath)

				// The expired URL may have prevented the initial V2 header probe.
				// Inspect the fresh URL without letting a legacy size-only cache entry
				// suppress detection, then attach the new nonce before retrying.
				if probeFreshContent {
					inspectReq := req
					inspectReq.FileDAO = nil
					if inspectedMeta, ok := inspectPlaybackContentMeta(inspectReq, authHeaders, freshRaw.Size); ok {
						r = r.WithContext(proxy.WithContentMeta(r.Context(), inspectedMeta))
						req.Request = r
						metaLoaded = true
						if inspectedMeta.PlainSize > 0 {
							fileSize = inspectedMeta.PlainSize
						}
						cachePlaybackContentMeta(req, inspectedMeta)
						retryWithFreshState = true
					}
				}
			}
			if freshRaw.Size > 0 {
				freshSize := freshRaw.Size
				// Metadata APIs normally report ciphertext size for V2. Preserve the
				// cached plaintext size/nonce that the decrypt stream requires.
				if cached, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && cached != nil &&
					cached.ContentVersion == encryption.ContentVersionV2 && cached.Size > 0 {
					freshSize = cached.Size
				}
				if freshSize != fileSize {
					retryWithFreshState = true
				}
				fileSize = freshSize
			}
		}
		if req.SizeResolver != nil {
			fresh := req.SizeResolver.ResolveSingleFresh(r.Context(), req.FileItem, authHeaders)
			if fresh.Error == nil && fresh.Size > 0 {
				retryWithFreshState = true
				if fileSize > 0 && fresh.Size != fileSize {
					req.SizeResolver.RecordMetaConflict(req.ProviderKey)
					if req.SizeConflictCount != nil {
						atomic.AddUint64(req.SizeConflictCount, 1)
					}
				}
				fileSize = fresh.Size
				if req.ConsumerScenario == consumerScenarioRedirect && req.FileDAO != nil && req.FileItem.DisplayPath != "" {
					if refreshed, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && refreshed != nil &&
						refreshed.RawURLAuthScope == rawURLScope && strings.TrimSpace(refreshed.RawURL) != "" {
						req.TargetURL = refreshed.RawURL
						req.FileItem.TargetURL = refreshed.RawURL
						req.ProviderKey = ProviderKey(refreshed.RawURL, req.FileItem.DisplayPath)
					}
				}
			}
		}
		if retryWithFreshState {
			success, lastFailure, lastErr = trySingle(fileSize)
			if success {
				return
			}
		}
	}

	if lastFailure == "range_unsatisfiable" {
		invalidatePlaybackState(req, lastFailure)
		RespondHTTPErrorWithStatus(w, "Range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if lastFailure == "upstream_4xx" && lastUpstreamStatus >= http.StatusBadRequest && lastUpstreamStatus < http.StatusInternalServerError {
		invalidatePlaybackState(req, lastFailure)
		RespondHTTPErrorWithStatus(w, "Upstream "+http.StatusText(lastUpstreamStatus), lastUpstreamStatus)
		return
	}
	if lastErr != nil {
		invalidatePlaybackState(req, lastFailure)
		log.Error().Err(lastErr).Str("path", req.Path).Str("failure", lastFailure).Msg(req.FailureLogMsg)
		RespondHTTPErrorWithStatus(w, "Decryption error: "+lastFailure, http.StatusBadGateway)
		return
	}
	invalidatePlaybackState(req, lastFailure)
	log.Error().Str("path", req.Path).Str("failure", lastFailure).Msg(req.FailureLogMsg)
	RespondHTTPErrorWithStatus(w, "Decryption failed: "+lastFailure, http.StatusBadGateway)
}

// playbackOutcomeServed treats a player cancel after response bytes were sent
// as a completed handoff. Seeking naturally cancels the previous HTTP request;
// attempting a fallback or appending an error response at that point only adds
// noise and can corrupt the already-started response.
func playbackOutcomeServed(result *proxy.StreamOutcome) bool {
	if result == nil {
		return false
	}
	if result.Err == nil && !result.Retryable && result.FailureReason == "" {
		return true
	}
	return result.ResponseStarted && result.BytesWritten > 0 && result.FailureReason == "client_disconnect"
}

func isWebDAVUpstreamFailure(reason string) bool {
	switch reason {
	case "upstream_4xx", "upstream_5xx":
		return true
	default:
		return false
	}
}

func webDAVInternalPlaybackTarget(req decryptPlaybackRequest) string {
	if req.ConsumerScenario != consumerScenarioWebDAV || req.Config == nil || strings.TrimSpace(req.FileItem.EncryptedPath) == "" {
		return ""
	}
	alistURL := strings.TrimSpace(req.Config.GetAlistURL())
	if alistURL == "" {
		return ""
	}
	return httputil.BuildTargetURLWithQuery(alistURL, "/dav"+req.FileItem.EncryptedPath, "")
}

func shouldRetryFreshResolve(failureReason string, firstFrameHint bool, consumerScenario string) bool {
	if consumerScenario == consumerScenarioRedirect {
		switch failureReason {
		case "range_unsatisfiable", "decrypt_validation_failed", "upstream_4xx", "upstream_5xx", "stream_error", "unknown", "":
			return true
		}
	}
	if consumerScenario == consumerScenarioHTTP && failureReason == "upstream_4xx" {
		return true
	}
	switch failureReason {
	case "range_unsatisfiable", "decrypt_validation_failed":
		return true
	case "", "unknown":
		return !firstFrameHint
	case "stream_error":
		return !firstFrameHint
	case "range_unsupported", "range_invalid", "chunked_seek_too_large":
		return false
	case "upstream_4xx", "upstream_5xx":
		return false
	case "timeout", "network_error", "client_disconnect":
		return consumerScenario == consumerScenarioRedirect && failureReason == "network_error"
	default:
		return !firstFrameHint
	}
}

func inspectPlaybackContentMeta(req decryptPlaybackRequest, authHeaders http.Header, fallbackSize int64) (encryption.ContentMeta, bool) {
	if req.StreamProxy == nil || req.PasswdInfo == nil || !req.PasswdInfo.Enable || strings.TrimSpace(req.TargetURL) == "" {
		return encryption.ContentMeta{}, false
	}
	switch req.ConsumerScenario {
	case consumerScenarioRedirect, consumerScenarioWebDAV, consumerScenarioHTTP:
	default:
		return encryption.ContentMeta{}, false
	}
	if shouldSkipHTTPContentMetaInspection(req, fallbackSize) {
		return encryption.ContentMeta{}, false
	}
	candidateURLs := make([]string, 0, 3)
	appendCandidate := func(candidateURL string) {
		candidateURL = strings.TrimSpace(candidateURL)
		if candidateURL == "" {
			return
		}
		candidateURLs = append(candidateURLs, candidateURL)
	}
	appendCandidate(req.TargetURL)
	if req.ConsumerScenario != consumerScenarioHTTP && req.Config != nil && req.FileItem.EncryptedPath != "" {
		alistURL := strings.TrimSpace(req.Config.GetAlistURL())
		if alistURL != "" {
			if req.ConsumerScenario == consumerScenarioWebDAV {
				appendCandidate(httputil.BuildTargetURLWithQuery(alistURL, "/dav"+req.FileItem.EncryptedPath, ""))
				appendCandidate(httputil.BuildTargetURLWithQuery(alistURL, "/d"+req.FileItem.EncryptedPath, ""))
			} else {
				appendCandidate(httputil.BuildTargetURLWithQuery(alistURL, "/d"+req.FileItem.EncryptedPath, ""))
				appendCandidate(httputil.BuildTargetURLWithQuery(alistURL, "/dav"+req.FileItem.EncryptedPath, ""))
			}
		}
	}
	authVariants := buildProbeAuthVariants(req.Config, authHeaders)
	seen := make(map[string]struct{}, len(candidateURLs))
	for _, candidateURL := range candidateURLs {
		candidateURL = strings.TrimSpace(candidateURL)
		if candidateURL == "" {
			continue
		}
		if _, ok := seen[candidateURL]; ok {
			continue
		}
		seen[candidateURL] = struct{}{}
		result := probeCandidateWithAuth(req.Config, candidateURL, authVariants, func(headers http.Header) proxy.ContentInspectionResult {
			return req.StreamProxy.InspectEncryptedContentResult(req.Request.Context(), candidateURL, headers, req.PasswdInfo, fallbackSize)
		})
		meta := result.Meta
		if meta.EncType == "" {
			meta.EncType = encryption.EncType(req.PasswdInfo.EncType)
		}
		if result.Confirmed {
			if meta.IsV2() && meta.PlainSize > 0 {
				log.Info().
					Str("category", "playback").
					Str("consumer_scenario", req.ConsumerScenario).
					Str("path", req.Path).
					Str("target_url", candidateURL).
					Int64("ciphertext_size", meta.CiphertextSize).
					Int64("plaintext_size", meta.PlainSize).
					Int64("header_len", meta.HeaderLen).
					Msg("Inspected V2 playback content meta")
			} else {
				log.Debug().
					Str("category", "playback").
					Str("consumer_scenario", req.ConsumerScenario).
					Str("path", req.Path).
					Str("target_url", candidateURL).
					Int64("ciphertext_size", meta.CiphertextSize).
					Msg("Confirmed V1 playback content meta")
			}
			return meta, true
		}
		log.Info().
			Str("category", "playback").
			Str("consumer_scenario", req.ConsumerScenario).
			Str("path", req.Path).
			Str("target_url", candidateURL).
			Int64("fallback_size", fallbackSize).
			Msg("Playback content meta inspection did not detect V2")
	}
	return encryption.ContentMeta{}, false
}

func shouldSkipHTTPContentMetaInspection(req decryptPlaybackRequest, fallbackSize int64) bool {
	if req.Request == nil || req.FileDAO == nil || req.FileItem.DisplayPath == "" {
		return false
	}
	// seek 请求（带 Range 但非首帧）：如果 FileDAO 已有该文件的缓存结论（首帧已检测过），
	// 跳过耗时的 V2 探测，避免每次快进都触发 2-3 秒延迟导致播放器超时断开。
	rangeHeader := req.Request.Header.Get("Range")
	if rangeHeader != "" && !proxy.IsFirstFrameRangeHint(req.Request.Method, rangeHeader) {
		info, ok := req.FileDAO.Get(req.FileItem.DisplayPath)
		if !ok || info == nil {
			return false
		}
		if fallbackSize > 0 && info.Size > 0 && info.Size != fallbackSize {
			return false
		}
		if info.ContentVersion == encryption.ContentVersionV2 && len(info.NonceField) != 16 {
			log.Info().
				Str("category", "playback").
				Str("consumer_scenario", req.ConsumerScenario).
				Str("path", req.Path).
				Str("range", rangeHeader).
				Int("content_version", info.ContentVersion).
				Int("nonce_len", len(info.NonceField)).
				Msg("Will probe V2 meta for seek because cached nonce is missing")
			return false
		}
		if info.ContentVersion <= 0 {
			log.Info().
				Str("category", "playback").
				Str("consumer_scenario", req.ConsumerScenario).
				Str("path", req.Path).
				Str("range", rangeHeader).
				Int64("cached_size", info.Size).
				Msg("Will probe playback meta for seek because cache has size only")
			return false
		}
		log.Info().
			Str("category", "playback").
			Str("consumer_scenario", req.ConsumerScenario).
			Str("path", req.Path).
			Str("range", rangeHeader).
			Int("content_version", info.ContentVersion).
			Int64("cached_size", info.Size).
			Msg("Skipping playback meta probe for seek with cached content meta")
		return true
	}
	// 首帧请求：保持原有逻辑，仅对 HTTP 场景且已有 V1 缓存结论时跳过
	if req.ConsumerScenario != consumerScenarioHTTP {
		return false
	}
	info, ok := req.FileDAO.Get(req.FileItem.DisplayPath)
	if !ok || info == nil || info.ContentVersion != 0 || info.RawURL == "" || info.Size <= 0 ||
		info.RawURLAuthScope != rawURLAuthScope(req.Request.Header) {
		return false
	}
	if fallbackSize > 0 && info.Size != fallbackSize {
		return false
	}
	return strings.TrimSpace(info.RawURL) == strings.TrimSpace(req.TargetURL)
}

func cachePlaybackContentMeta(req decryptPlaybackRequest, meta encryption.ContentMeta) {
	if req.FileDAO == nil || req.FileItem.DisplayPath == "" || !meta.IsV2() || meta.PlainSize <= 0 {
		return
	}
	authScope := "anon"
	if req.Request != nil {
		authScope = rawURLAuthScope(req.Request.Header)
	}
	info := &dao.FileInfo{
		Path:              req.FileItem.DisplayPath,
		EncryptedPath:     req.FileItem.EncryptedPath,
		Name:              req.FileItem.FileName,
		Size:              meta.PlainSize,
		CiphertextSize:    meta.TotalCiphertextSize(),
		ContentVersion:    meta.Version,
		HeaderLen:         meta.HeaderLen,
		NonceField:        append([]byte(nil), meta.NonceField...),
		RawURL:            req.TargetURL,
		RawURLAuthScope:   authScope,
		UpstreamFetchedAt: time.Now(),
	}
	if existing, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && existing != nil {
		if info.Name == "" {
			info.Name = existing.Name
		}
		if strings.TrimSpace(existing.RawURL) != "" && existing.RawURLAuthScope == authScope {
			info.RawURL = existing.RawURL
			info.RawURLAuthScope = existing.RawURLAuthScope
			if !existing.UpstreamFetchedAt.IsZero() {
				info.UpstreamFetchedAt = existing.UpstreamFetchedAt
			}
			info.Sign = existing.Sign
		}
		info.IsDir = existing.IsDir
	}
	_ = req.FileDAO.Set(info)
}

func logDecryptFailure(req decryptPlaybackRequest, strategy proxy.StreamStrategy, failureReason string, freshRetry bool) {
	category := strings.TrimSpace(req.LogCategory)
	if category == "" {
		category = "playback"
	}
	rangeHeader := ""
	if req.Request != nil {
		rangeHeader = req.Request.Header.Get("Range")
	}
	log.Info().
		Str("category", category).
		Str("path", req.Path).
		Str("display_path", req.FileItem.DisplayPath).
		Str("target_url", req.TargetURL).
		Str("range", rangeHeader).
		Str("strategy", string(strategy)).
		Str("failure_reason", failureReason).
		Bool("fresh_retry", freshRetry).
		Str("consumer_scenario", req.ConsumerScenario).
		Msg("Decrypt playback attempt failed")
}

func cloneHeader(src http.Header) http.Header {
	if len(src) == 0 {
		return make(http.Header)
	}
	dst := make(http.Header, len(src))
	for k, values := range src {
		copied := make([]string, len(values))
		copy(copied, values)
		dst[k] = copied
	}
	return dst
}

func maybeEnqueueFirstFrameWarmup(req decryptPlaybackRequest, authHeaders http.Header, firstFrameHint bool, size int64, expectedBytes int64) {
	if !firstFrameHint || req.Probe == nil || req.Request == nil || req.Request.Method != http.MethodGet {
		return
	}
	reportedSize := size
	if expectedBytes > reportedSize {
		reportedSize = expectedBytes
	}
	req.Probe.EnqueueWithSource(req.FileItem, authHeaders, reportedSize, probeSourceFirstFrame)
	if req.WarmupEnqueueCount != nil {
		atomic.AddUint64(req.WarmupEnqueueCount, 1)
	}
}

func invalidatePlaybackState(req decryptPlaybackRequest, reason string) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return
	}
	switch reason {
	case "client_disconnect", "network_error":
		return
	}
	if req.Probe != nil {
		req.Probe.InvalidateWarm(req.FileItem.DisplayPath, reason)
	}
	if req.FileDAO == nil {
		return
	}
	switch reason {
	case "upstream_4xx":
		authScope := "anon"
		if req.Request != nil {
			authScope = rawURLAuthScope(req.Request.Header)
		}
		req.FileDAO.InvalidateRawURLForScope(req.FileItem.DisplayPath, authScope)
	case "range_unsatisfiable", "decrypt_validation_failed", "timeout":
		req.FileDAO.InvalidateDisplayPath(req.FileItem.DisplayPath)
	}
}

// rangeStartFromHeader 解析 Range 头的起始位置（无 Range / 无法解析返回 0）。
func rangeStartFromHeader(header string) int64 {
	if header == "" {
		return 0
	}
	parsed, err := httputil.ParseRange(header, -1)
	if err != nil || parsed == nil || len(parsed.Ranges) == 0 {
		return 0
	}
	start := parsed.Ranges[0].Start
	if start < 0 {
		return 0
	}
	return start
}
