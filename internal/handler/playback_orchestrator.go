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
}

func executeDecryptPlayback(req decryptPlaybackRequest) {
	w := req.ResponseWriter
	r := req.Request
	fileSize := req.InitialSize
	authHeaders := make(http.Header)
	if auth := r.Header.Get("Authorization"); auth != "" {
		authHeaders.Set("Authorization", auth)
	}
	if cookie := r.Header.Get("Cookie"); cookie != "" {
		authHeaders.Set("Cookie", cookie)
	}

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
		if req.Config == nil || req.Config.AlistServer.SizeUnknownStrict {
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
	if firstFrameHint && req.FirstFrameCount != nil {
		atomic.AddUint64(req.FirstFrameCount, 1)
	}

	trySingle := func(size int64) (bool, string, error) {
		result := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
			w, r, req.TargetURL, req.PasswdInfo, size, strategy, req.CompatKey,
		)
		if result.Err == nil && !result.Retryable {
			req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, strategy)
			if req.StrategySel != nil && !result.NoLearning {
				req.StrategySel.RecordSuccess(req.ProviderKey, strategy)
			}
			if req.SizeResolver != nil && r.Method == http.MethodGet && !result.NoLearning {
				metaSize := size
				if result.ExpectedBytes > 0 {
					metaSize = result.ExpectedBytes
				}
				req.SizeResolver.RecordPlaybackSuccess(
					r.Context(), req.FileItem, metaSize, result.StatusCode, result.ContentType, result.ETag,
				)
			}
			if req.Probe != nil {
				req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
			}
			maybeEnqueueFirstFrameWarmup(req, authHeaders, firstFrameHint, size, result.ExpectedBytes)
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
				if fallback.Err == nil && !fallback.Retryable {
					req.StreamProxy.RecordPlaybackHint(fallbackTarget, req.CompatKey, strategy)
					if req.StrategySel != nil && !fallback.NoLearning {
						req.StrategySel.RecordSuccess(fallbackProvider, strategy)
					}
					if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
						metaSize := size
						if fallback.ExpectedBytes > 0 {
							metaSize = fallback.ExpectedBytes
						}
						req.SizeResolver.RecordPlaybackSuccess(
							r.Context(), fallbackFile, metaSize, fallback.StatusCode, fallback.ContentType, fallback.ETag,
						)
					}
					if req.Probe != nil {
						req.Probe.RecordConsumerHit(fallbackFile, req.ConsumerScenario)
					}
					maybeEnqueueFirstFrameWarmup(req, authHeaders, firstFrameHint, size, fallback.ExpectedBytes)
					return true, "", nil
				}
				if fallback.Err != nil {
					return false, reason, fallback.Err
				}
				return false, reason, result.Err
			}
		}

		if reason == "range_unsupported" && !result.ResponseStarted && firstFrameHint && strategy == proxy.StreamStrategyRange {
			if req.FirstFrameFallbacks != nil {
				atomic.AddUint64(req.FirstFrameFallbacks, 1)
			}
			fallback := req.StreamProxy.ProxyDownloadDecryptWithStrategyForStorage(
				w, r, req.TargetURL, req.PasswdInfo, size, proxy.StreamStrategyChunked, req.CompatKey,
			)
			if fallback.Err == nil && !fallback.Retryable {
				req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, proxy.StreamStrategyChunked)
				if req.StrategySel != nil && !fallback.NoLearning {
					req.StrategySel.RecordSuccess(req.ProviderKey, proxy.StreamStrategyChunked)
				}
				if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
					metaSize := size
					if fallback.ExpectedBytes > 0 {
						metaSize = fallback.ExpectedBytes
					}
					req.SizeResolver.RecordPlaybackSuccess(
						r.Context(), req.FileItem, metaSize, fallback.StatusCode, fallback.ContentType, fallback.ETag,
					)
				}
				if req.Probe != nil {
					req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
				}
				maybeEnqueueFirstFrameWarmup(req, authHeaders, firstFrameHint, size, fallback.ExpectedBytes)
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
			if fallback.Err == nil && !fallback.Retryable {
				req.StreamProxy.RecordPlaybackHint(req.TargetURL, req.CompatKey, proxy.StreamStrategyFull)
				if req.StrategySel != nil && !fallback.NoLearning {
					req.StrategySel.RecordSuccess(req.ProviderKey, proxy.StreamStrategyFull)
				}
				if req.SizeResolver != nil && r.Method == http.MethodGet && !fallback.NoLearning {
					metaSize := size
					if fallback.ExpectedBytes > 0 {
						metaSize = fallback.ExpectedBytes
					}
					req.SizeResolver.RecordPlaybackSuccess(
						r.Context(), req.FileItem, metaSize, fallback.StatusCode, fallback.ContentType, fallback.ETag,
					)
				}
				if req.Probe != nil {
					req.Probe.RecordConsumerHit(req.FileItem, req.ConsumerScenario)
				}
				maybeEnqueueFirstFrameWarmup(req, authHeaders, firstFrameHint, size, fallback.ExpectedBytes)
				return true, "", nil
			}
			if fallback.Err != nil {
				return false, "range_unsatisfiable", fallback.Err
			}
			return false, "range_unsatisfiable", result.Err
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
		if req.ConsumerScenario == consumerScenarioRedirect && req.FileDAO != nil && req.FileItem.DisplayPath != "" && req.Config != nil {
			authCopy := cloneHeader(authHeaders)
			freshRaw := fetchRawURL(r.Context(), req.Config.GetAlistURL(), req.FileItem.DisplayPath, req.FileItem.EncryptedPath, authCopy, req.FileDAO, 0)
			if strings.TrimSpace(freshRaw.RawURL) != "" {
				req.TargetURL = freshRaw.RawURL
				req.FileItem.TargetURL = freshRaw.RawURL
			}
			if freshRaw.Size > 0 {
				fileSize = freshRaw.Size
			}
		}
		if req.SizeResolver != nil {
			fresh := req.SizeResolver.ResolveSingleFresh(r.Context(), req.FileItem, authHeaders)
			if fresh.Error == nil && fresh.Size > 0 {
				if fileSize > 0 && fresh.Size != fileSize {
					req.SizeResolver.RecordMetaConflict(req.ProviderKey)
					if req.SizeConflictCount != nil {
						atomic.AddUint64(req.SizeConflictCount, 1)
					}
				}
				fileSize = fresh.Size
				if req.ConsumerScenario == consumerScenarioRedirect && req.FileDAO != nil && req.FileItem.DisplayPath != "" {
					if refreshed, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && refreshed != nil && strings.TrimSpace(refreshed.RawURL) != "" {
						req.TargetURL = refreshed.RawURL
						req.FileItem.TargetURL = refreshed.RawURL
					}
				}
				success, lastFailure, lastErr = trySingle(fileSize)
				if success {
					return
				}
			}
		}
	}

	if lastFailure == "range_unsatisfiable" {
		invalidatePlaybackState(req, lastFailure)
		RespondHTTPErrorWithStatus(w, "Range not satisfiable", http.StatusRequestedRangeNotSatisfiable)
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
	case consumerScenarioRedirect, consumerScenarioWebDAV:
	default:
		return encryption.ContentMeta{}, false
	}
	candidateURLs := make([]string, 0, 3)
	if req.Config != nil && req.FileItem.EncryptedPath != "" {
		alistURL := strings.TrimSpace(req.Config.GetAlistURL())
		if alistURL != "" {
			candidateURLs = append(candidateURLs,
				httputil.BuildTargetURLWithQuery(alistURL, "/d"+req.FileItem.EncryptedPath, ""),
				httputil.BuildTargetURLWithQuery(alistURL, "/dav"+req.FileItem.EncryptedPath, ""),
			)
		}
	}
	candidateURLs = append(candidateURLs, req.TargetURL)
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
		for _, headers := range authVariants {
			meta := req.StreamProxy.InspectEncryptedContent(req.Request.Context(), candidateURL, headers, req.PasswdInfo, fallbackSize)
			if meta.EncType == "" {
				meta.EncType = encryption.EncType(req.PasswdInfo.EncType)
			}
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
				return meta, true
			}
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

func cachePlaybackContentMeta(req decryptPlaybackRequest, meta encryption.ContentMeta) {
	if req.FileDAO == nil || req.FileItem.DisplayPath == "" || !meta.IsV2() || meta.PlainSize <= 0 {
		return
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
		UpstreamFetchedAt: time.Now(),
	}
	if existing, ok := req.FileDAO.Get(req.FileItem.DisplayPath); ok && existing != nil {
		if info.Name == "" {
			info.Name = existing.Name
		}
		if strings.TrimSpace(existing.RawURL) != "" {
			info.RawURL = existing.RawURL
		}
		if !existing.UpstreamFetchedAt.IsZero() {
			info.UpstreamFetchedAt = existing.UpstreamFetchedAt
		}
		info.Sign = existing.Sign
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
	if req.Probe != nil {
		req.Probe.InvalidateWarm(req.FileItem.DisplayPath, reason)
	}
	if req.FileDAO == nil {
		return
	}
	switch reason {
	case "range_unsatisfiable", "upstream_4xx", "decrypt_validation_failed", "timeout", "network_error", "stream_error":
		req.FileDAO.InvalidateDisplayPath(req.FileItem.DisplayPath)
	}
}
