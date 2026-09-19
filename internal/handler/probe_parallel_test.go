package handler

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/shared/encryptcore"
	"github.com/alist-encrypt-go/internal/proxy"
)

func testProbeAuthVariants() []http.Header {
	return []http.Header{{"Authorization": []string{"Bearer test-token"}}}
}

// TestProbeCandidateCandidatesPrimaryConfirmWinsFast verifies the PRIMARY
// candidate (index 0) is probed first and its confirmation short-circuits — NO
// fallback candidate is ever touched (preserving the one-round-trip common
// case).
func TestProbeCandidateCandidatesPrimaryConfirmWinsFast(t *testing.T) {
	var calls atomic.Int32
	result, candidate := probeCandidateCandidates(&config.Config{}, []string{
		"https://c0.example/v.mp4",
		"https://c1.example/v.mp4",
		"https://c2.example/v.mp4",
	}, testProbeAuthVariants(), func(candidateURL string, headers http.Header) proxy.ContentInspectionResult {
		calls.Add(1)
		return proxy.ContentInspectionResult{Confirmed: true, Meta: encryption.ContentMeta{Version: 2, HeaderLen: 32}}
	})
	if !result.Confirmed {
		t.Fatal("expected the primary to confirm")
	}
	if candidate != "https://c0.example/v.mp4" {
		t.Fatalf("expected candidate c0, got %q", candidate)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("fallback must NOT be probed when primary confirms; got %d calls", got)
	}
}

// TestProbeCandidateCandidatesFallbackParallelFirstConfirmedWins covers the
// failure path: primary fails, fallbacks run in parallel, and the first
// confirmed fallback wins (fast c2 beats the late c1).
func TestProbeCandidateCandidatesFallbackParallelFirstConfirmedWins(t *testing.T) {
	var calls atomic.Int32
	result, candidate := probeCandidateCandidates(&config.Config{}, []string{
		"https://c0.example/v.mp4", // primary: fails
		"https://c1.example/v.mp4", // slow confirm
		"https://c2.example/v.mp4", // fast confirm
	}, testProbeAuthVariants(), func(candidateURL string, headers http.Header) proxy.ContentInspectionResult {
		calls.Add(1)
		switch candidateURL {
		case "https://c1.example/v.mp4":
			time.Sleep(120 * time.Millisecond)
			return proxy.ContentInspectionResult{Confirmed: true, Meta: encryption.ContentMeta{Version: 2, HeaderLen: 32}}
		case "https://c2.example/v.mp4":
			return proxy.ContentInspectionResult{Confirmed: true, Meta: encryption.ContentMeta{Version: 2, HeaderLen: 16}}
		default:
			return proxy.ContentInspectionResult{Confirmed: false}
		}
	})
	if !result.Confirmed {
		t.Fatal("expected a fallback to confirm")
	}
	if candidate != "https://c2.example/v.mp4" {
		t.Fatalf("expected the fast-confirmed c2, got %q", candidate)
	}
	if result.Meta.HeaderLen != 16 {
		t.Fatalf("expected c2's meta header len 16, got %d", result.Meta.HeaderLen)
	}
	// primary + at least the fast fallback must have fired; the slow c1
	// goroutine may still be mid-flight when we return, so allow 2 or 3.
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected at least primary + fast fallback probes, got %d calls", got)
	}
}

// TestProbeCandidateCandidatesDedupeAndCap verifies empty candidates are dropped
// and duplicates are collapsed before probing.
func TestProbeCandidateCandidatesDedupeAndCap(t *testing.T) {
	seen := make(map[string]struct{})
	var mu sync.Mutex
	result, candidate := probeCandidateCandidates(&config.Config{}, []string{
		"",
		" https://dup.example/1 ",
		"https://dup.example/1",
		"https://a.example/1",
	}, testProbeAuthVariants(), func(candidateURL string, headers http.Header) proxy.ContentInspectionResult {
		mu.Lock()
		seen[candidateURL] = struct{}{}
		mu.Unlock()
		if candidateURL == "https://dup.example/1" {
			return proxy.ContentInspectionResult{Confirmed: true, Meta: encryption.ContentMeta{Version: 2, HeaderLen: 16}}
		}
		return proxy.ContentInspectionResult{Confirmed: false}
	})
	if !result.Confirmed || candidate != "https://dup.example/1" {
		t.Fatalf("expected dup.example confirmed with collapsed duplicate, got %q", candidate)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := seen["https://dup.example/1"]; !dup {
		t.Fatal("expected the trimmed duplicate to be probed")
	}
	if len(seen) != 1 {
		t.Fatalf("expected exactly one probe (dedupe), got %d: %v", len(seen), seen)
	}
}

// TestProbeCandidateCandidatesAmbiguousOrdering uses three explicit candidates
// and verifies that when the first (primary) is not confirmed, fallbacks (b,c)
// are attempted and the last probe's (unconfirmed) result basis is returned.
func TestProbeCandidateCandidatesNoConfirmFallsBackToPrimary(t *testing.T) {
	seen := make(map[string]struct{})
	var mu sync.Mutex
	result, candidate := probeCandidateCandidates(&config.Config{}, []string{
		"https://x.example/1",
		"https://y.example/1",
		"https://z.example/1",
	}, testProbeAuthVariants(), func(candidateURL string, headers http.Header) proxy.ContentInspectionResult {
		mu.Lock()
		seen[candidateURL] = struct{}{}
		mu.Unlock()
		return proxy.ContentInspectionResult{StatusCode: http.StatusNotFound}
	})
	if result.Confirmed || candidate == "" {
		t.Fatalf("expected unconfirmed with a candidate basis, got %+v/%q", result, candidate)
	}
	// candidate basis must be the primary (index 0)
	if candidate != "https://x.example/1" {
		t.Fatalf("expected primary x as basis, got %q", candidate)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("expected all 3 candidates probed, got %d: %v", len(seen), seen)
	}
}

// TestProbeCandidateCandidatesNilSafe verifies nil inspector / nil input returns
// a zero result without panicking.
func TestProbeCandidateCandidatesNilSafe(t *testing.T) {
	result, candidate := probeCandidateCandidates(&config.Config{}, nil, nil, nil)
	if result.Confirmed || candidate != "" {
		t.Fatalf("nil input should yield empty result, got %+v/%q", result, candidate)
	}
	result, candidate = probeCandidateCandidates(&config.Config{}, []string{" "}, nil, nil)
	if result.Confirmed || candidate != "" {
		t.Fatalf("empty candidate list should yield empty result, got %+v/%q", result, candidate)
	}
}
