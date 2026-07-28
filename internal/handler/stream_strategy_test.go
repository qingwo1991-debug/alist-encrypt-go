package handler

import (
	"net/url"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

func TestProviderKeyPreservesIPv6Host(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "bracketed host with port", in: "https://[2001:db8::1]:8443/video", want: "[2001:db8::1]:8443"},
		{name: "legacy path suffix", in: "https://media.example/video", want: "media.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProviderKey(tt.in, "/ignored"); got != tt.want {
				t.Fatalf("ProviderKey(%q)=%q, want %q", tt.in, got, tt.want)
			}
		})
	}

	const ipv6Provider = "[2001:db8::1]:8443"
	if got := normalizeStrategyProviderKey(ipv6Provider + "::/movie.mkv"); got != ipv6Provider {
		t.Fatalf("normalize legacy IPv6 provider=%q, want %q", got, ipv6Provider)
	}
	if host := providerHostFromKey(ipv6Provider + "::/movie.mkv"); host != ipv6Provider {
		t.Fatalf("providerHostFromKey=%q, want %q", host, ipv6Provider)
	}
	if host, path := splitProvider(ipv6Provider + "::/movie.mkv"); host != ipv6Provider || path != "/movie.mkv" {
		t.Fatalf("splitProvider=(%q,%q), want (%q,%q)", host, path, ipv6Provider, "/movie.mkv")
	}

	parsed, err := url.Parse("https://[2001:db8::1]:8443/video")
	if err != nil || parsed.Host != ipv6Provider {
		t.Fatalf("invalid IPv6 test fixture: host=%q err=%v", parsed.Host, err)
	}
}

func TestIsNonStrategyFailureTimeout(t *testing.T) {
	if !isNonStrategyFailure("timeout") {
		t.Fatalf("expected timeout to be non-strategy failure")
	}
	if isNonStrategyFailure("html_response") {
		t.Fatalf("expected html_response to be strategy failure")
	}
}

func TestStrategySelectorStatsIncludesObservability(t *testing.T) {
	cfg := config.DefaultConfig()
	selector, err := NewStrategySelector(cfg, NewMemoryStrategyStore())
	if err != nil {
		t.Fatalf("failed to create selector: %v", err)
	}

	provider := "demo.example.com::/a/b.mp4"
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")

	stats := selector.Stats()
	reasons, ok := stats["reason_counts"].(map[string]uint64)
	if !ok {
		t.Fatalf("reason_counts type mismatch: %#v", stats["reason_counts"])
	}
	if reasons["range_unsupported"] == 0 {
		t.Fatalf("reason_counts missing range_unsupported: %#v", reasons)
	}

	providerStrategy, ok := stats["provider_strategy"].(map[string]string)
	if !ok {
		t.Fatalf("provider_strategy type mismatch: %#v", stats["provider_strategy"])
	}
	if _, ok := providerStrategy["demo.example.com"]; !ok {
		t.Fatalf("provider strategy missing provider host key: %#v", providerStrategy)
	}
}

func newStrategySelectorForTest(t *testing.T, failToDowngrade, successToRecover int) (*StrategySelector, *MemoryStrategyStore) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.AlistServer.StrategyFailToDowngrade = failToDowngrade
	cfg.AlistServer.StrategySuccessToRecover = successToRecover
	cfg.AlistServer.StrategyCooldownMinutes = 1
	store := NewMemoryStrategyStore()
	selector, err := NewStrategySelector(cfg, store)
	if err != nil {
		t.Fatalf("NewStrategySelector() error = %v", err)
	}
	return selector, store
}

func requireSelectedStrategy(t *testing.T, selector *StrategySelector, provider string, want proxy.StreamStrategy) {
	t.Helper()
	got := selector.Select(provider)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Select(%q) = %v, want [%s]", provider, got, want)
	}
}

func TestStrategySelectorFallbackSuccessDoesNotReplacePreferred(t *testing.T) {
	selector, store := newStrategySelectorForTest(t, 2, 3)
	const provider = "fallback.example"

	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyRange)
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")
	selector.RecordSuccess(provider, proxy.StreamStrategyChunked)

	state, ok := store.Get(provider)
	if !ok {
		t.Fatal("strategy state was not stored")
	}
	if state.Preferred != proxy.StreamStrategyRange {
		t.Fatalf("fallback success changed preferred to %s, want range", state.Preferred)
	}
	if state.CapabilityFailCount != 1 || state.Failures[proxy.StreamStrategyRange] != 1 {
		t.Fatalf("fallback success erased range failures: capability=%d failures=%v", state.CapabilityFailCount, state.Failures)
	}
	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyRange)

	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")
	state, _ = store.Get(provider)
	if state.Preferred != proxy.StreamStrategyChunked {
		t.Fatalf("retained failures did not downgrade at threshold: preferred=%s", state.Preferred)
	}
}

func TestStrategySelectorDowngradesOnlyAtFailureThreshold(t *testing.T) {
	selector, store := newStrategySelectorForTest(t, 2, 3)
	const provider = "threshold.example"

	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")
	state, _ := store.Get(provider)
	if state.Preferred != proxy.StreamStrategyRange {
		t.Fatalf("preferred after first failure = %s, want range", state.Preferred)
	}

	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")
	state, _ = store.Get(provider)
	if state.Preferred != proxy.StreamStrategyChunked {
		t.Fatalf("preferred at failure threshold = %s, want chunked", state.Preferred)
	}
	if !state.CooldownUntil.After(time.Now()) {
		t.Fatalf("downgrade did not start cooldown: %v", state.CooldownUntil)
	}
	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyChunked)
}

func TestStrategySelectorRecoversOneTierAfterSuccessThreshold(t *testing.T) {
	selector, store := newStrategySelectorForTest(t, 2, 3)
	const provider = "recovery.example"
	if err := store.Set(provider, &ProviderStrategyState{
		Provider:      provider,
		Preferred:     proxy.StreamStrategyFull,
		Failures:      make(map[proxy.StreamStrategy]int),
		CooldownUntil: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("seed strategy state: %v", err)
	}

	// Recovery from full must probe chunked, never jump directly to range.
	for success := 1; success <= 3; success++ {
		requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyChunked)
		selector.RecordSuccess(provider, proxy.StreamStrategyChunked)
		state, _ := store.Get(provider)
		if success < 3 {
			if state.Preferred != proxy.StreamStrategyFull || state.SuccessStreak != success {
				t.Fatalf("after %d recovery successes: preferred=%s streak=%d, want full/%d", success, state.Preferred, state.SuccessStreak, success)
			}
		} else if state.Preferred != proxy.StreamStrategyChunked || state.SuccessStreak != 0 {
			t.Fatalf("after recovery threshold: preferred=%s streak=%d, want chunked/0", state.Preferred, state.SuccessStreak)
		}
	}

	// Promoting one tier starts a fresh cooldown before probing range.
	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyChunked)
	state, _ := store.Get(provider)
	state.CooldownUntil = time.Now().Add(-time.Second)
	if err := store.Set(provider, state); err != nil {
		t.Fatalf("expire recovery cooldown: %v", err)
	}
	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyRange)
}

func TestStrategySelectorRecoveryFailureRestartsCooldown(t *testing.T) {
	selector, store := newStrategySelectorForTest(t, 2, 3)
	const provider = "recovery-failure.example"
	if err := store.Set(provider, &ProviderStrategyState{
		Provider:      provider,
		Preferred:     proxy.StreamStrategyChunked,
		Failures:      make(map[proxy.StreamStrategy]int),
		CooldownUntil: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("seed strategy state: %v", err)
	}

	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyRange)
	selector.RecordSuccess(provider, proxy.StreamStrategyRange)
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "range_unsupported")

	state, _ := store.Get(provider)
	if state.Preferred != proxy.StreamStrategyChunked || state.SuccessStreak != 0 {
		t.Fatalf("failed recovery changed state: preferred=%s streak=%d", state.Preferred, state.SuccessStreak)
	}
	if !state.CooldownUntil.After(time.Now()) {
		t.Fatalf("failed recovery did not restart cooldown: %v", state.CooldownUntil)
	}
	requireSelectedStrategy(t, selector, provider, proxy.StreamStrategyChunked)
}

func TestStrategySelectorRecoveryRequiresConsecutiveSuccesses(t *testing.T) {
	selector, store := newStrategySelectorForTest(t, 2, 2)
	const provider = "recovery-streak.example"
	if err := store.Set(provider, &ProviderStrategyState{
		Provider:      provider,
		Preferred:     proxy.StreamStrategyChunked,
		Failures:      make(map[proxy.StreamStrategy]int),
		CooldownUntil: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("seed strategy state: %v", err)
	}

	selector.RecordSuccess(provider, proxy.StreamStrategyRange)
	selector.RecordFailure(provider, proxy.StreamStrategyRange, "timeout")
	selector.RecordSuccess(provider, proxy.StreamStrategyRange)

	state, _ := store.Get(provider)
	if state.Preferred != proxy.StreamStrategyChunked || state.SuccessStreak != 1 {
		t.Fatalf("interrupted recovery was promoted: preferred=%s streak=%d, want chunked/1", state.Preferred, state.SuccessStreak)
	}
}
