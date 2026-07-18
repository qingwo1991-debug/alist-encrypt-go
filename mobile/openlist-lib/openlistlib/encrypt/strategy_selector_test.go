package encrypt

import (
	"testing"
	"time"
)

func newMobileStrategySelectorForTest(t *testing.T, failToDowngrade, successToRecover int) (*StrategySelector, *MemoryStrategyStore) {
	t.Helper()
	store := NewMemoryStrategyStore()
	selector, err := NewStrategySelector(failToDowngrade, successToRecover, time.Minute, store)
	if err != nil {
		t.Fatalf("NewStrategySelector() error = %v", err)
	}
	return selector, store
}

func requireMobileSelectedStrategy(t *testing.T, selector *StrategySelector, provider string, want StreamStrategy) {
	t.Helper()
	got := selector.Select(provider)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Select(%q) = %v, want [%s]", provider, got, want)
	}
}

func TestMobileStrategySelectorFallbackSuccessDoesNotReplacePreferred(t *testing.T) {
	selector, store := newMobileStrategySelectorForTest(t, 2, 3)
	const provider = "fallback.example"

	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyRange)
	selector.RecordFailure(provider, StreamStrategyRange, "range_unsupported")
	selector.RecordSuccess(provider, StreamStrategyChunked)

	state, ok := store.Get(provider)
	if !ok {
		t.Fatal("strategy state was not stored")
	}
	if state.Preferred != StreamStrategyRange {
		t.Fatalf("fallback success changed preferred to %s, want range", state.Preferred)
	}
	if state.CapabilityFailCount != 1 || state.Failures[StreamStrategyRange] != 1 {
		t.Fatalf("fallback success erased range failures: capability=%d failures=%v", state.CapabilityFailCount, state.Failures)
	}
	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyRange)

	selector.RecordFailure(provider, StreamStrategyRange, "range_unsupported")
	state, _ = store.Get(provider)
	if state.Preferred != StreamStrategyChunked {
		t.Fatalf("retained failures did not downgrade at threshold: preferred=%s", state.Preferred)
	}
}

func TestMobileStrategySelectorDowngradesOnlyAtFailureThreshold(t *testing.T) {
	selector, store := newMobileStrategySelectorForTest(t, 2, 3)
	const provider = "threshold.example"

	selector.RecordFailure(provider, StreamStrategyRange, "range_unsupported")
	state, _ := store.Get(provider)
	if state.Preferred != StreamStrategyRange {
		t.Fatalf("preferred after first failure = %s, want range", state.Preferred)
	}

	selector.RecordFailure(provider, StreamStrategyRange, "range_unsupported")
	state, _ = store.Get(provider)
	if state.Preferred != StreamStrategyChunked {
		t.Fatalf("preferred at failure threshold = %s, want chunked", state.Preferred)
	}
	if !state.CooldownUntil.After(time.Now()) {
		t.Fatalf("downgrade did not start cooldown: %v", state.CooldownUntil)
	}
	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyChunked)
}

func TestMobileStrategySelectorRecoversOneTierAfterSuccessThreshold(t *testing.T) {
	selector, store := newMobileStrategySelectorForTest(t, 2, 3)
	const provider = "recovery.example"
	if err := store.Set(provider, &ProviderStrategyState{
		Provider:      provider,
		Preferred:     StreamStrategyFull,
		Failures:      make(map[StreamStrategy]int),
		CooldownUntil: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("seed strategy state: %v", err)
	}

	for success := 1; success <= 3; success++ {
		requireMobileSelectedStrategy(t, selector, provider, StreamStrategyChunked)
		selector.RecordSuccess(provider, StreamStrategyChunked)
		state, _ := store.Get(provider)
		if success < 3 {
			if state.Preferred != StreamStrategyFull || state.SuccessStreak != success {
				t.Fatalf("after %d recovery successes: preferred=%s streak=%d, want full/%d", success, state.Preferred, state.SuccessStreak, success)
			}
		} else if state.Preferred != StreamStrategyChunked || state.SuccessStreak != 0 {
			t.Fatalf("after recovery threshold: preferred=%s streak=%d, want chunked/0", state.Preferred, state.SuccessStreak)
		}
	}

	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyChunked)
	state, _ := store.Get(provider)
	state.CooldownUntil = time.Now().Add(-time.Second)
	if err := store.Set(provider, state); err != nil {
		t.Fatalf("expire recovery cooldown: %v", err)
	}
	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyRange)
}

func TestMobileStrategySelectorRecoveryFailureRestartsCooldown(t *testing.T) {
	selector, store := newMobileStrategySelectorForTest(t, 2, 3)
	const provider = "recovery-failure.example"
	if err := store.Set(provider, &ProviderStrategyState{
		Provider:      provider,
		Preferred:     StreamStrategyChunked,
		Failures:      make(map[StreamStrategy]int),
		CooldownUntil: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("seed strategy state: %v", err)
	}

	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyRange)
	selector.RecordSuccess(provider, StreamStrategyRange)
	selector.RecordFailure(provider, StreamStrategyRange, "range_unsupported")

	state, _ := store.Get(provider)
	if state.Preferred != StreamStrategyChunked || state.SuccessStreak != 0 {
		t.Fatalf("failed recovery changed state: preferred=%s streak=%d", state.Preferred, state.SuccessStreak)
	}
	if !state.CooldownUntil.After(time.Now()) {
		t.Fatalf("failed recovery did not restart cooldown: %v", state.CooldownUntil)
	}
	requireMobileSelectedStrategy(t, selector, provider, StreamStrategyChunked)
}

func TestMobileStrategySelectorRecoveryRequiresConsecutiveSuccesses(t *testing.T) {
	selector, store := newMobileStrategySelectorForTest(t, 2, 2)
	const provider = "recovery-streak.example"
	if err := store.Set(provider, &ProviderStrategyState{
		Provider:      provider,
		Preferred:     StreamStrategyChunked,
		Failures:      make(map[StreamStrategy]int),
		CooldownUntil: time.Now().Add(-time.Second),
	}); err != nil {
		t.Fatalf("seed strategy state: %v", err)
	}

	selector.RecordSuccess(provider, StreamStrategyRange)
	selector.RecordFailure(provider, StreamStrategyRange, "timeout")
	selector.RecordSuccess(provider, StreamStrategyRange)

	state, _ := store.Get(provider)
	if state.Preferred != StreamStrategyChunked || state.SuccessStreak != 1 {
		t.Fatalf("interrupted recovery was promoted: preferred=%s streak=%d, want chunked/1", state.Preferred, state.SuccessStreak)
	}
}
