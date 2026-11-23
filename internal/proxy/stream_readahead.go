package proxy

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// Playback readahead: when a client Range stream starts, a background task
// fetches the plaintext window right after it through the same decrypt+cache
// pipeline, populating the decrypted block cache so the player's next ranges
// are served from memory instead of waiting on upstream jitter. All files are
// treated equally; concurrency and the LRU cache bound the extra load.

const (
	readaheadLookaheadBytes   = 32 << 20 // 32 MiB of plaintext per active stream
	readaheadMinFileSize      = 64 << 20 // skip tiny files; readahead only pays off on video
	readaheadMaxConcurrent    = 4
	readaheadDedupBucketBytes = 4 << 20
	readaheadTimeout          = 3 * time.Minute
	// For open-ended ranges ("bytes=N-", or no Range) the active connection
	// already streams from N onwards, so the window starts this far ahead of
	// it to avoid racing the player's own upstream body.
	readaheadOpenRangeLeadBytes = 4 << 20
)

type streamReadaheadKey struct{}

type discardResponseWriter struct {
	header http.Header
}

func (d *discardResponseWriter) Header() http.Header {
	if d.header == nil {
		d.header = make(http.Header)
	}
	return d.header
}

func (d *discardResponseWriter) WriteHeader(int) {}

func (d *discardResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// readaheadWindow returns the plaintext interval to prefetch for an active
// range. A bounded range prefetches right after its end. An open-ended range
// ("bytes=N-" or no Range, which parse to End = EOF) is already streaming from
// N, so the window starts a fixed lead ahead of the live position instead of
// at End+1, which would always lie past EOF.
func readaheadWindow(plainSize, activeStart, activeEnd int64) (int64, int64, bool) {
	nextStart := activeEnd + 1
	if activeEnd >= plainSize-1 {
		nextStart = activeStart + readaheadOpenRangeLeadBytes
	}
	if nextStart < 0 || nextStart >= plainSize {
		return 0, 0, false
	}
	lookahead := int64(readaheadLookaheadBytes)
	if remaining := plainSize - nextStart; remaining < lookahead {
		lookahead = remaining
	}
	return nextStart, lookahead, lookahead > 0
}

// maybeReadahead spawns a background cache-warming fetch for the plaintext
// window following activeRange. It is a no-op for non-GET/range requests,
// V3 containers (separate cache path), readahead-spawned requests, and when
// the lookahead window is empty or the concurrency budget is exhausted.
func (s *StreamProxy) maybeReadahead(req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, activeRangeStart, activeRangeEnd int64, strategy StreamStrategy, compatStorageKey string) {
	if s == nil || s.blockCache == nil || req == nil {
		return
	}
	if req.Method != http.MethodGet || req.Context().Value(streamReadaheadKey{}) != nil {
		return
	}
	if strategy != StreamStrategyRange || meta.IsV3() {
		return
	}
	plainSize := fileSize
	if meta.PlainSize > 0 {
		plainSize = meta.PlainSize
	}
	if plainSize < readaheadMinFileSize {
		return
	}
	nextStart, lookahead, ok := readaheadWindow(plainSize, activeRangeStart, activeRangeEnd)
	if !ok {
		return
	}
	baseKey := s.decryptedCacheBaseKey(targetURL, passwdInfo, fileSize, meta, compatStorageKey)
	if baseKey == "" {
		return
	}
	dedupKey := fmt.Sprintf("%s@%d", baseKey, nextStart/readaheadDedupBucketBytes)
	if _, loaded := s.readaheadInflight.LoadOrStore(dedupKey, struct{}{}); loaded {
		return
	}
	if s.readaheadActive.Add(1) > readaheadMaxConcurrent {
		s.readaheadActive.Add(-1)
		s.readaheadInflight.Delete(dedupKey)
		return
	}
	go s.runReadahead(req, targetURL, passwdInfo, fileSize, strategy, compatStorageKey, baseKey, dedupKey, nextStart, lookahead)
}

func (s *StreamProxy) runReadahead(req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy, compatStorageKey, baseKey, dedupKey string, nextStart, lookahead int64) {
	defer func() {
		s.readaheadInflight.Delete(dedupKey)
		s.readaheadActive.Add(-1)
	}()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), readaheadTimeout)
	defer cancel()
	synth := req.Clone(ctx)
	synth = synth.WithContext(context.WithValue(ctx, streamReadaheadKey{}, true))
	synth.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", nextStart, nextStart+lookahead-1))
	s.ProxyDownloadDecryptReqWithStrategyForStorage(&discardResponseWriter{}, synth, targetURL, passwdInfo, fileSize, strategy, compatStorageKey)
	_ = baseKey
}
