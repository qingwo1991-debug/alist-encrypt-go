package handler

import (
	"net/url"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

type ProviderStrategyState struct {
	Provider       string                       `json:"provider"`
	Preferred      proxy.StreamStrategy         `json:"preferred"`
	Failures       map[proxy.StreamStrategy]int `json:"failures"`
	SuccessStreak  int                          `json:"success_streak"`
	CooldownUntil  time.Time                    `json:"cooldown_until"`
	LastDowngrade  time.Time                    `json:"last_downgrade"`
	LastUpdate     time.Time                    `json:"last_update"`
	LastFailure    string                       `json:"last_failure"`
	LastStrategy   proxy.StreamStrategy         `json:"last_strategy"`
	TotalFailures  int                          `json:"total_failures"`
	TotalSuccesses int                          `json:"total_successes"`
}

type StrategySelectorConfig struct {
	FailToDowngrade   int
	SuccessToRecover  int
	Cooldown          time.Duration
	ProviderFallbacks []proxy.StreamStrategy
}

type StrategySelector struct {
	cfg   StrategySelectorConfig
	store StrategyStore
}

func NewStrategySelector(cfg *config.Config, store StrategyStore) (*StrategySelector, error) {
	if store == nil {
		store = NewMemoryStrategyStore()
	}

	selector := &StrategySelector{
		cfg: StrategySelectorConfig{
			FailToDowngrade:  cfg.AlistServer.StrategyFailToDowngrade,
			SuccessToRecover: cfg.AlistServer.StrategySuccessToRecover,
			Cooldown:         time.Duration(cfg.AlistServer.StrategyCooldownMinutes) * time.Minute,
			ProviderFallbacks: []proxy.StreamStrategy{
				proxy.StreamStrategyRange,
				proxy.StreamStrategyChunked,
				proxy.StreamStrategyFull,
			},
		},
		store: store,
	}
	selector.applyDefaults()
	return selector, nil
}

func (s *StrategySelector) applyDefaults() {
	if s.cfg.FailToDowngrade <= 0 {
		s.cfg.FailToDowngrade = 2
	}
	if s.cfg.SuccessToRecover <= 0 {
		s.cfg.SuccessToRecover = 5
	}
	if s.cfg.Cooldown <= 0 {
		s.cfg.Cooldown = 30 * time.Minute
	}
	if len(s.cfg.ProviderFallbacks) == 0 {
		s.cfg.ProviderFallbacks = []proxy.StreamStrategy{proxy.StreamStrategyRange, proxy.StreamStrategyChunked, proxy.StreamStrategyFull}
	}
}

func (s *StrategySelector) Stats() map[string]interface{} {
	states := s.store.List()
	return map[string]interface{}{
		"providers":          len(states),
		"fail_to_downgrade":  s.cfg.FailToDowngrade,
		"success_to_recover": s.cfg.SuccessToRecover,
		"cooldown_minutes":   int(s.cfg.Cooldown.Minutes()),
	}
}

func (s *StrategySelector) Select(provider string) []proxy.StreamStrategy {
	state := s.ensureState(provider)
	order := s.cfg.ProviderFallbacks

	preferred := state.Preferred
	if preferred == "" {
		preferred = order[0]
	}

	preferredIndex := indexOfStrategy(order, preferred)
	if preferredIndex == -1 {
		preferredIndex = 0
		preferred = order[0]
	}

	// Probe recovery: try higher priority after cooldown + success streak
	if preferredIndex > 0 && time.Now().After(state.CooldownUntil) && state.SuccessStreak >= s.cfg.SuccessToRecover {
		probe := order[preferredIndex-1]
		return dedupeStrategies(append([]proxy.StreamStrategy{probe}, order[preferredIndex:]...))
	}

	return dedupeStrategies(append([]proxy.StreamStrategy{preferred}, order[preferredIndex+1:]...))
}

func (s *StrategySelector) RecordSuccess(provider string, strategy proxy.StreamStrategy) {
	state := s.ensureState(provider)
	state.TotalSuccesses++
	state.SuccessStreak++
	state.LastStrategy = strategy
	state.LastFailure = ""

	order := s.cfg.ProviderFallbacks
	preferredIndex := indexOfStrategy(order, state.Preferred)
	strategyIndex := indexOfStrategy(order, strategy)

	if state.Preferred == "" {
		state.Preferred = strategy
	}

	// If probe succeeded, promote to higher priority
	if strategyIndex != -1 && preferredIndex != -1 && strategyIndex < preferredIndex {
		state.Preferred = strategy
		state.SuccessStreak = 1
		state.CooldownUntil = time.Time{}
	}

	_ = s.store.Set(provider, state)
}

func (s *StrategySelector) RecordFailure(provider string, strategy proxy.StreamStrategy, reason string) {
	state := s.ensureState(provider)
	state.TotalFailures++
	state.SuccessStreak = 0
	state.LastFailure = reason
	state.LastStrategy = strategy

	if isNonStrategyFailure(reason) {
		_ = s.store.Set(provider, state)
		return
	}

	if state.Failures == nil {
		state.Failures = make(map[proxy.StreamStrategy]int)
	}
	state.Failures[strategy]++

	order := s.cfg.ProviderFallbacks
	preferredIndex := indexOfStrategy(order, state.Preferred)

	if state.Preferred == "" {
		state.Preferred = order[0]
		preferredIndex = 0
	}

	if strategy == state.Preferred && state.Failures[strategy] >= s.cfg.FailToDowngrade {
		if preferredIndex >= 0 && preferredIndex+1 < len(order) {
			state.Preferred = order[preferredIndex+1]
			state.Failures[strategy] = 0
			state.LastDowngrade = time.Now()
			state.CooldownUntil = time.Now().Add(s.cfg.Cooldown)
		}
	}

	_ = s.store.Set(provider, state)
}

func isNonStrategyFailure(reason string) bool {
	switch reason {
	case "timeout", "network_error", "client_disconnect", "upstream_4xx", "upstream_5xx", "range_invalid":
		return true
	default:
		return false
	}
}

func (s *StrategySelector) ensureState(provider string) *ProviderStrategyState {
	if provider == "" {
		provider = "default"
	}
	if state, ok := s.store.Get(provider); ok {
		return state
	}
	state := &ProviderStrategyState{
		Provider:  provider,
		Preferred: "",
		Failures:  make(map[proxy.StreamStrategy]int),
	}
	_ = s.store.Set(provider, state)
	return state
}

func ProviderKey(targetURL string, davPath string) string {
	host := ""
	if parsed, err := url.Parse(targetURL); err == nil {
		host = parsed.Host
	}
	if host == "" {
		return davPath
	}
	return host + "::" + davPath
}

func indexOfStrategy(order []proxy.StreamStrategy, target proxy.StreamStrategy) int {
	for idx, item := range order {
		if item == target {
			return idx
		}
	}
	return -1
}

func dedupeStrategies(order []proxy.StreamStrategy) []proxy.StreamStrategy {
	seen := make(map[proxy.StreamStrategy]struct{})
	out := make([]proxy.StreamStrategy, 0, len(order))
	for _, item := range order {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
