package handler

import (
	"errors"
	"testing"

	"github.com/alist-encrypt-go/internal/proxy"
)

func TestShouldRetryFreshResolveForSizeRelatedFailures(t *testing.T) {
	cases := []string{
		"range_unsatisfiable",
		"decrypt_validation_failed",
	}
	for _, reason := range cases {
		if !shouldRetryFreshResolve(reason, false, "") {
			t.Fatalf("expected retry for %q", reason)
		}
		if !shouldRetryFreshResolve(reason, true, "") {
			t.Fatalf("expected retry for %q on first-frame request", reason)
		}
	}
}

func TestShouldRetryFreshResolveSkipsNonSizeFailuresOnFirstFrame(t *testing.T) {
	cases := []string{
		"range_unsupported",
		"chunked_seek_too_large",
		"upstream_4xx",
		"upstream_5xx",
		"timeout",
		"client_disconnect",
		"stream_error",
		"unknown",
	}
	for _, reason := range cases {
		if shouldRetryFreshResolve(reason, true, "") {
			t.Fatalf("expected no retry for %q on first-frame request", reason)
		}
	}
}

func TestShouldRetryFreshResolveAllowsUnknownForNonFirstFrame(t *testing.T) {
	cases := []string{
		"",
		"unknown",
		"stream_error",
		"custom_reason",
	}
	for _, reason := range cases {
		if !shouldRetryFreshResolve(reason, false, "") {
			t.Fatalf("expected retry for %q on non-first-frame request", reason)
		}
	}
}

func TestShouldRetryFreshResolveAllowsRedirectMetadataRecovery(t *testing.T) {
	cases := []string{"upstream_4xx", "upstream_5xx", "stream_error", "unknown", "", "network_error"}
	for _, reason := range cases {
		if !shouldRetryFreshResolve(reason, true, consumerScenarioRedirect) {
			t.Fatalf("expected redirect retry for %q", reason)
		}
	}
}

func TestShouldRetryFreshResolveRefreshesExpiredHTTPRawURL(t *testing.T) {
	if !shouldRetryFreshResolve("upstream_4xx", true, consumerScenarioHTTP) {
		t.Fatal("HTTP playback should refresh a signed raw URL after upstream 4xx")
	}
}

func TestPlaybackOutcomeServedAcceptsPlayerCancellationAfterBytes(t *testing.T) {
	result := &proxy.StreamOutcome{
		Err:             errors.New("context canceled"),
		FailureReason:   "client_disconnect",
		ResponseStarted: true,
		BytesWritten:    4096,
	}
	if !playbackOutcomeServed(result) {
		t.Fatal("expected cancellation after streamed bytes to count as served")
	}

	result.BytesWritten = 0
	if playbackOutcomeServed(result) {
		t.Fatal("cancellation before any bytes must remain a failure")
	}
}

func TestPlaybackOutcomeServedRejectsFailureReasonWithoutError(t *testing.T) {
	result := &proxy.StreamOutcome{FailureReason: "upstream_4xx", NoLearning: true}
	if playbackOutcomeServed(result) {
		t.Fatal("failure reason must not be counted as successful playback")
	}
}
