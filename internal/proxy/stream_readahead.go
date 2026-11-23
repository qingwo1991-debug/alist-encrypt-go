package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/httputil"
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
	// On a playback start (range starting at 0) also warm the file tail:
	// MP4s with a trailing moov make the player read the end before the first
	// frame, costing an extra upstream round trip per start.
	readaheadTailBytes = 4 << 20
	// Readahead starts only after the live stream wrote its first body byte,
	// and then waits this long, so it never competes with the player's own
	// first-frame bytes on bandwidth-limited upstreams.
	readaheadStartDelay = 1500 * time.Millisecond
	// V3 records live in a small, short-TTL cache (64 MiB / 30 s); a smaller
	// window keeps warmed records from expiring or evicting live ones.
	readaheadV3LookaheadBytes = 8 << 20
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
	s.readahead(req, targetURL, passwdInfo, fileSize, meta, activeRangeStart, activeRangeEnd, strategy, compatStorageKey, true)
}

// scheduleReadahead is called once the live stream wrote its first body byte
// (first holds those bytes). It defers the readahead by readaheadStartDelay
// and skips the tail warm-up when the file is an MP4 with its moov up front.
func (s *StreamProxy) scheduleReadahead(req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, activeRangeStart, activeRangeEnd int64, strategy StreamStrategy, compatStorageKey string, first []byte) {
	if s == nil || s.blockCache == nil || req == nil || req.Context().Value(streamReadaheadKey{}) != nil {
		return
	}
	warmTail := activeRangeStart == 0 && !mp4MoovAtFront(first)
	go func() {
		t := time.NewTimer(readaheadStartDelay)
		defer t.Stop()
		// A finished bounded range also ends the wait: its follow-up request
		// is the one that benefits from the warmed window. An open-ended stream
		// that ends this early was abandoned (the player seeked away), so its
		// window is no longer wanted.
		select {
		case <-t.C:
		case <-req.Context().Done():
			plainSize := fileSize
			if meta.PlainSize > 0 {
				plainSize = meta.PlainSize
			}
			if activeRangeEnd >= plainSize-1 {
				return
			}
		}
		s.readahead(req, targetURL, passwdInfo, fileSize, meta, activeRangeStart, activeRangeEnd, strategy, compatStorageKey, warmTail)
	}()
}

// mp4MoovAtFront reports whether the first plaintext bytes are an MP4 whose
// moov box precedes mdat, in which case the tail holds no index to warm.
func mp4MoovAtFront(b []byte) bool {
	off := 0
	for i := 0; i < 16 && off+8 <= len(b); i++ {
		size := int64(b[off])<<24 | int64(b[off+1])<<16 | int64(b[off+2])<<8 | int64(b[off+3])
		typ := string(b[off+4 : off+8])
		if i == 0 && typ != "ftyp" {
			return false
		}
		switch typ {
		case "moov":
			return true
		case "mdat":
			return false
		}
		if size == 1 {
			if off+16 > len(b) {
				return false
			}
			size = 0
			for _, c := range b[off+8 : off+16] {
				size = size<<8 | int64(c)
			}
		}
		if size < 8 || size > int64(len(b)) {
			return false
		}
		off += int(size)
	}
	return false
}

func (s *StreamProxy) readahead(req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, activeRangeStart, activeRangeEnd int64, strategy StreamStrategy, compatStorageKey string, warmTail bool) {
	if s == nil || s.blockCache == nil || req == nil {
		return
	}
	if req.Method != http.MethodGet || req.Context().Value(streamReadaheadKey{}) != nil {
		return
	}
	if strategy != StreamStrategyRange {
		return
	}
	plainSize := fileSize
	if meta.PlainSize > 0 {
		plainSize = meta.PlainSize
	}
	if plainSize < readaheadMinFileSize {
		return
	}
	baseKey := s.decryptedCacheBaseKey(targetURL, passwdInfo, fileSize, meta, compatStorageKey)
	if baseKey == "" {
		return
	}
	if tailStart, tailLen, ok := readaheadTailWindow(plainSize, activeRangeStart); ok && warmTail {
		// Tail first: on a start the player needs it before the forward window.
		if cached := s.blockCache.getPrefix(baseKey, tailStart, tailLen); int64(len(cached)) < tailLen {
			s.spawnReadahead(req, targetURL, passwdInfo, fileSize, strategy, compatStorageKey, baseKey, tailStart, tailLen)
		}
	}
	if nextStart, lookahead, ok := readaheadWindow(plainSize, activeRangeStart, activeRangeEnd); ok {
		if meta.IsV3() && lookahead > readaheadV3LookaheadBytes {
			// V3 warms its record cache through the same synthetic Range path.
			lookahead = readaheadV3LookaheadBytes
		}
		s.spawnReadahead(req, targetURL, passwdInfo, fileSize, strategy, compatStorageKey, baseKey, nextStart, lookahead)
	}
}

// readaheadTailWindow returns the file tail to warm on a playback start.
func readaheadTailWindow(plainSize, activeStart int64) (int64, int64, bool) {
	if activeStart != 0 || plainSize <= readaheadOpenRangeLeadBytes+readaheadLookaheadBytes+readaheadTailBytes {
		// Not a start, or the forward window already reaches the tail.
		return 0, 0, false
	}
	return plainSize - readaheadTailBytes, readaheadTailBytes, true
}

func (s *StreamProxy) spawnReadahead(req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, strategy StreamStrategy, compatStorageKey, baseKey string, start, length int64) {
	dedupKey := fmt.Sprintf("%s@%d", baseKey, start/readaheadDedupBucketBytes)
	if _, loaded := s.readaheadInflight.LoadOrStore(dedupKey, struct{}{}); loaded {
		return
	}
	if s.readaheadActive.Add(1) > readaheadMaxConcurrent {
		s.readaheadActive.Add(-1)
		s.readaheadInflight.Delete(dedupKey)
		return
	}
	go s.runReadahead(req, targetURL, passwdInfo, fileSize, strategy, compatStorageKey, baseKey, dedupKey, start, length)
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

// readaheadAfterFirstByte returns the writer the live body should be copied
// into. On its first Write it schedules the playback readahead, handing over
// the first plaintext bytes so the tail warm-up can be skipped for MP4s whose
// moov sits at the front. Returns w unchanged when no readahead applies.
func (s *StreamProxy) readaheadAfterFirstByte(w http.ResponseWriter, req *http.Request, targetURL string, passwdInfo *config.PasswdInfo, fileSize int64, meta encryption.ContentMeta, activeRange, fullRequestedRange *httputil.Range, strategy StreamStrategy, compatStorageKey string) io.Writer {
	if s == nil || s.blockCache == nil || req == nil || req.Method != http.MethodGet {
		return w
	}
	start, end := int64(0), fileSize-1
	switch {
	case activeRange != nil:
		start, end = activeRange.Start, activeRange.End
	case fullRequestedRange == nil:
		// Range-less playback start: treat it as an open range from 0.
	default:
		return w
	}
	return &firstWriteHook{dst: w, fire: func(first []byte) {
		s.scheduleReadahead(req, targetURL, passwdInfo, fileSize, meta, start, end, strategy, compatStorageKey, first)
	}}
}

// firstWriteSniffBytes is how much of the body is collected before the
// readahead fires: enough for the MP4 box headers, and it skips tiny probe
// ranges (e.g. bytes=0-1) that never lead to playback.
const firstWriteSniffBytes = 512

type firstWriteHook struct {
	dst  io.Writer
	fire func([]byte)
	head []byte
	done bool
}

func (h *firstWriteHook) Write(b []byte) (int, error) {
	n, err := h.dst.Write(b)
	if !h.done && n > 0 {
		if need := firstWriteSniffBytes - len(h.head); need > 0 {
			if need > n {
				need = n
			}
			h.head = append(h.head, b[:need]...)
		}
		if len(h.head) >= firstWriteSniffBytes {
			h.done = true
			h.fire(h.head)
		}
	}
	return n, err
}
