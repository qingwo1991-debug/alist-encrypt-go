package proxy

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// StreamStrategy controls how range and streaming are handled.
type StreamStrategy string

const (
	StreamStrategyRange   StreamStrategy = "range"
	StreamStrategyChunked StreamStrategy = "chunked"
	StreamStrategyFull    StreamStrategy = "full"
)

type recentPlaybackHint struct {
	Strategy  StreamStrategy
	UpdatedAt time.Time
}

const firstFrameWindowBytes int64 = 2 * 1024 * 1024
const recentPlaybackHintTTL = 2 * time.Minute

// SelectOptimalStrategy picks the single best strategy based on cached range
// compatibility, playback hints, and the request shape (first-frame seek etc).
func (s *StreamProxy) SelectOptimalStrategy(targetURL, storageKey, method, rangeHeader string) StreamStrategy {
	profile := classifyRequestRange(method, rangeHeader)

	// Check recent playback hint first (fastest path)
	if hinted, ok := s.recentPlaybackStrategy(targetURL, storageKey, profile); ok {
		return hinted
	}

	if !profile.HasRange {
		if s.shouldSkipRange(targetURL, storageKey) {
			return StreamStrategyFull
		}
		return StreamStrategyRange
	}

	if s.shouldSkipRange(targetURL, storageKey) {
		if profile.IsFirstFrameHint {
			return StreamStrategyChunked
		}
		maxDiscard := s.chunkedSeekMaxDiscardBytes()
		if maxDiscard <= 0 || profile.Start <= maxDiscard {
			return StreamStrategyChunked
		}
		return StreamStrategyFull
	}

	return StreamStrategyRange
}

// IsFirstFrameRangeHint reports whether the request looks like a first-frame
// read, such as bytes=0- or a small bounded window starting at 0.
func IsFirstFrameRangeHint(method, rangeHeader string) bool {
	return classifyRequestRange(method, rangeHeader).IsFirstFrameHint
}

// RecordPlaybackHint records a successful playback strategy for quick reuse.
func (s *StreamProxy) RecordPlaybackHint(targetURL, storageKey string, strategy StreamStrategy) {
	key := s.hintKeyFor(targetURL, storageKey)
	s.playbackHintsMu.Lock()
	defer s.playbackHintsMu.Unlock()
	if s.playbackHints == nil {
		s.playbackHints = make(map[string]recentPlaybackHint)
	}
	s.playbackHints[key] = recentPlaybackHint{Strategy: strategy, UpdatedAt: time.Now()}
	atomic.AddUint64(&s.playbackHintHits, 1)
	switch strategy {
	case StreamStrategyRange:
		atomic.AddUint64(&s.rangeHintHits, 1)
	case StreamStrategyChunked:
		atomic.AddUint64(&s.chunkedHintHits, 1)
	case StreamStrategyFull:
		atomic.AddUint64(&s.fullHintHits, 1)
	}
}

func (s *StreamProxy) hintKeyFor(targetURL, storageKey string) string {
	return targetURL + "|" + storageKey
}

func (s *StreamProxy) recentPlaybackStrategy(targetURL, storageKey string, profile requestRangeProfile) (StreamStrategy, bool) {
	s.playbackHintsMu.RLock()
	if s.playbackHints == nil {
		s.playbackHintsMu.RUnlock()
		return "", false
	}
	key := s.hintKeyFor(targetURL, storageKey)
	hint, ok := s.playbackHints[key]
	if !ok {
		s.playbackHintsMu.RUnlock()
		return "", false
	}
	if time.Since(hint.UpdatedAt) > recentPlaybackHintTTL {
		s.playbackHintsMu.RUnlock()
		s.playbackHintsMu.Lock()
		delete(s.playbackHints, key)
		s.playbackHintsMu.Unlock()
		return "", false
	}
	strategy := hint.Strategy
	s.playbackHintsMu.RUnlock()
	if strategy == StreamStrategyRange {
		return strategy, true
	}
	if !profile.HasRange {
		return strategy, true
	}

	rangeSkipped := s.shouldSkipRange(targetURL, storageKey)
	switch strategy {
	case StreamStrategyChunked:
		if !rangeSkipped {
			return "", false
		}
		if profile.IsFirstFrameHint {
			return strategy, true
		}
		maxDiscard := s.chunkedSeekMaxDiscardBytes()
		if maxDiscard <= 0 || profile.Start <= maxDiscard {
			return strategy, true
		}
	case StreamStrategyFull:
		if !rangeSkipped {
			return "", false
		}
		if profile.IsFirstFrameHint {
			return "", false
		}
		maxDiscard := s.chunkedSeekMaxDiscardBytes()
		if maxDiscard > 0 && profile.Start <= maxDiscard {
			return "", false
		}
		return strategy, true
	}
	return "", false
}

// requestRangeProfile classifies a Range request.
type requestRangeProfile struct {
	HasRange         bool
	Start            int64
	End              int64
	HasExplicitEnd   bool
	EstimatedLength  int64
	IsFirstFrameHint bool
}

// classifyRequestRange parses Range header into a profile for strategy selection.
func classifyRequestRange(method, rangeHeader string) requestRangeProfile {
	if method == http.MethodHead {
		return requestRangeProfile{}
	}
	rangeHeader = strings.TrimSpace(rangeHeader)
	if rangeHeader == "" {
		return requestRangeProfile{}
	}
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return requestRangeProfile{}
	}
	rangeVal := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.SplitN(rangeVal, ",", 2)
	if len(parts) == 0 {
		return requestRangeProfile{}
	}
	rangeSpec := strings.TrimSpace(parts[0])
	kv := strings.SplitN(rangeSpec, "-", 2)
	if len(kv) != 2 {
		return requestRangeProfile{}
	}

	start, err := strconv.ParseInt(strings.TrimSpace(kv[0]), 10, 64)
	if err != nil || start < 0 {
		return requestRangeProfile{}
	}

	profile := requestRangeProfile{
		HasRange: true,
		Start:    start,
		End:      -1,
	}

	if endStr := strings.TrimSpace(kv[1]); endStr != "" {
		end, err := strconv.ParseInt(endStr, 10, 64)
		if err == nil && end >= start {
			profile.End = end
			profile.HasExplicitEnd = true
			profile.EstimatedLength = end - start + 1
		}
	}

	if start == 0 {
		if !profile.HasExplicitEnd {
			profile.IsFirstFrameHint = true
		} else if profile.EstimatedLength > 0 && profile.EstimatedLength <= firstFrameWindowBytes {
			profile.IsFirstFrameHint = true
		}
	}

	return profile
}
