package encrypt

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

)

type ProviderStrategyState struct {
	Provider       string                 `json:"provider"`
	Preferred      StreamStrategy         `json:"preferred"`
	Failures       map[StreamStrategy]int `json:"failures"`
	CapabilityFailCount int               `json:"capability_fail_count"`
	LastValidatedAt    time.Time          `json:"last_validated_at"`
	SuccessStreak  int                    `json:"success_streak"`
	CooldownUntil  time.Time              `json:"cooldown_until"`
	LastDowngrade  time.Time              `json:"last_downgrade"`
	LastUpdate     time.Time              `json:"last_update"`
	LastFailure    string                 `json:"last_failure"`
	LastStrategy   StreamStrategy         `json:"last_strategy"`
	TotalFailures  int                    `json:"total_failures"`
	TotalSuccesses int                    `json:"total_successes"`
}

type StrategySelectorConfig struct {
	FailToDowngrade   int
	SuccessToRecover  int
	Cooldown          time.Duration
	ProviderFallbacks []StreamStrategy
}

type StrategySelector struct {
	cfg   StrategySelectorConfig
	store StrategyStore

	obsMu           sync.Mutex
	reasonCounts    map[string]uint64
	recentEvents    []StrategyEvent
	maxRecentEvents int
}

type StrategyEvent struct {
	Time     time.Time      `json:"time"`
	Provider string         `json:"provider"`
	From     StreamStrategy `json:"from"`
	To       StreamStrategy `json:"to"`
	Reason   string         `json:"reason"`
}

type strategyStoreFile struct {
	Version   int                               `json:"version"`
	Providers map[string]*ProviderStrategyState `json:"providers"`
}

type StrategyStore interface {
	Get(provider string) (*ProviderStrategyState, bool)
	Set(provider string, state *ProviderStrategyState) error
	List() map[string]*ProviderStrategyState
}

type JSONStrategyStore struct {
	mu    sync.RWMutex
	path  string
	state map[string]*ProviderStrategyState
}

func NewJSONStrategyStore(path string) (*JSONStrategyStore, error) {
	if path == "" {
		return nil, fmt.Errorf("strategy store path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create strategy store dir: %w", err)
	}

	store := &JSONStrategyStore{
		path:  path,
		state: make(map[string]*ProviderStrategyState),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *JSONStrategyStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read strategy store: %w", err)
	}

	var file strategyStoreFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("decode strategy store: %w", err)
	}

	if file.Providers != nil {
		s.state = file.Providers
	}
	return nil
}

func (s *JSONStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.state[provider]
	if !ok {
		return nil, false
	}
	return cloneProviderState(state), true
}

func (s *JSONStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdate = time.Now()
	s.state[provider] = cloneProviderState(state)
	return s.saveLocked()
}

func (s *JSONStrategyStore) List() map[string]*ProviderStrategyState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]*ProviderStrategyState, len(s.state))
	for key, value := range s.state {
		out[key] = cloneProviderState(value)
	}
	return out
}

func (s *JSONStrategyStore) saveLocked() error {
	file := strategyStoreFile{
		Version:   1,
		Providers: s.state,
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("encode strategy store: %w", err)
	}

	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write strategy store: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("commit strategy store: %w", err)
	}
	return nil
}

type MemoryStrategyStore struct {
	mu    sync.RWMutex
	state map[string]*ProviderStrategyState
}

func NewMemoryStrategyStore() *MemoryStrategyStore {
	return &MemoryStrategyStore{state: make(map[string]*ProviderStrategyState)}
}

func (s *MemoryStrategyStore) Get(provider string) (*ProviderStrategyState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.state[provider]
	if !ok {
		return nil, false
	}
	return cloneProviderState(state), true
}

func (s *MemoryStrategyStore) Set(provider string, state *ProviderStrategyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	state.LastUpdate = time.Now()
	s.state[provider] = cloneProviderState(state)
	return nil
}

func (s *MemoryStrategyStore) List() map[string]*ProviderStrategyState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make(map[string]*ProviderStrategyState, len(s.state))
	for key, value := range s.state {
		out[key] = cloneProviderState(value)
	}
	return out
}

func cloneProviderState(state *ProviderStrategyState) *ProviderStrategyState {
	if state == nil {
		return nil
	}

	copyState := *state
	if state.Failures != nil {
		copyState.Failures = make(map[StreamStrategy]int, len(state.Failures))
		for key, value := range state.Failures {
			copyState.Failures[key] = value
		}
	}
	return &copyState
}

func NewStrategySelector(failToDowngrade int, successToRecover int, cooldown time.Duration, store StrategyStore) (*StrategySelector, error) {
	if store == nil {
		store = NewMemoryStrategyStore()
	}

	selector := &StrategySelector{
		cfg: StrategySelectorConfig{
			FailToDowngrade:  failToDowngrade,
			SuccessToRecover: successToRecover,
			Cooldown:         cooldown,
			ProviderFallbacks: []StreamStrategy{
				StreamStrategyRange,
				StreamStrategyChunked,
				StreamStrategyFull,
			},
		},
		store:           store,
		reasonCounts:    make(map[string]uint64),
		maxRecentEvents: 50,
	}
	selector.applyDefaults()
	return selector, nil
}

func (s *StrategySelector) applyDefaults() {
	if s.cfg.FailToDowngrade <= 0 {
		s.cfg.FailToDowngrade = 5
	}
	if s.cfg.SuccessToRecover <= 0 {
		s.cfg.SuccessToRecover = 5
	}
	if s.cfg.Cooldown <= 0 {
		s.cfg.Cooldown = 30 * time.Minute
	}
	if len(s.cfg.ProviderFallbacks) == 0 {
		s.cfg.ProviderFallbacks = []StreamStrategy{StreamStrategyRange, StreamStrategyChunked, StreamStrategyFull}
	}
}

func (s *StrategySelector) Stats() map[string]interface{} {
	states := s.store.List()
	providerStrategy := make(map[string]string, len(states))
	providers := make([]string, 0, len(states))
	for provider, state := range states {
		providers = append(providers, provider)
		if state != nil {
			providerStrategy[provider] = string(state.Preferred)
		}
	}
	sort.Strings(providers)

	s.obsMu.Lock()
	reasons := make(map[string]uint64, len(s.reasonCounts))
	for k, v := range s.reasonCounts {
		reasons[k] = v
	}
	events := make([]StrategyEvent, len(s.recentEvents))
	copy(events, s.recentEvents)
	s.obsMu.Unlock()

	return map[string]interface{}{
		"providers":          len(states),
		"fail_to_downgrade":  s.cfg.FailToDowngrade,
		"success_to_recover": s.cfg.SuccessToRecover,
		"cooldown_minutes":   int(s.cfg.Cooldown.Minutes()),
		"provider_order":     providers,
		"provider_strategy":  providerStrategy,
		"reason_counts":      reasons,
		"recent_events":      events,
	}
}

func (s *StrategySelector) Select(provider string) []StreamStrategy {
	provider = normalizeStrategyProviderKey(provider)
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

	return []StreamStrategy{preferred}
}

func (s *StrategySelector) RecordSuccess(provider string, strategy StreamStrategy) {
	provider = normalizeStrategyProviderKey(provider)
	state := s.ensureState(provider)
	state.TotalSuccesses++
	state.SuccessStreak++
	state.CapabilityFailCount = 0
	state.LastValidatedAt = time.Now()
	state.LastStrategy = strategy
	state.LastFailure = ""

	if state.Preferred == "" {
		state.Preferred = strategy
	}
	if state.Preferred != strategy {
		prev := state.Preferred
		state.Preferred = strategy
		state.SuccessStreak = 1
		state.CooldownUntil = time.Time{}
		s.appendEvent(provider, prev, strategy, "validated_success")
	}

	_ = s.store.Set(provider, state)
}

func (s *StrategySelector) RecordFailure(provider string, strategy StreamStrategy, reason string) {
	provider = normalizeStrategyProviderKey(provider)
	reason = normalizeFailureReason(reason)
	s.recordReason(reason)
	state := s.ensureState(provider)
	state.TotalFailures++
	state.SuccessStreak = 0
	state.LastFailure = reason
	state.LastStrategy = strategy

	if isNonStrategyFailure(reason) {
		state.LastValidatedAt = time.Now()
		_ = s.store.Set(provider, state)
		return
	}

	if state.Failures == nil {
		state.Failures = make(map[StreamStrategy]int)
	}
	state.Failures[strategy]++
	state.CapabilityFailCount++
	state.LastValidatedAt = time.Now()

	order := s.cfg.ProviderFallbacks
	preferredIndex := indexOfStrategy(order, state.Preferred)

	if state.Preferred == "" {
		state.Preferred = order[0]
		preferredIndex = 0
	}

	if strategy == state.Preferred && state.CapabilityFailCount >= s.cfg.FailToDowngrade {
		if preferredIndex >= 0 && preferredIndex+1 < len(order) {
			prev := state.Preferred
			state.Preferred = order[preferredIndex+1]
			state.Failures[strategy] = 0
			state.CapabilityFailCount = 0
			state.LastDowngrade = time.Now()
			state.CooldownUntil = time.Now().Add(s.cfg.Cooldown)
			s.appendEvent(provider, prev, state.Preferred, reason)
		}
	}

	_ = s.store.Set(provider, state)
}

func normalizeFailureReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "unknown"
	}
	return reason
}

func (s *StrategySelector) recordReason(reason string) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	s.reasonCounts[reason]++
}

func (s *StrategySelector) appendEvent(provider string, from, to StreamStrategy, reason string) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	s.recentEvents = append(s.recentEvents, StrategyEvent{
		Time:     time.Now(),
		Provider: provider,
		From:     from,
		To:       to,
		Reason:   reason,
	})
	if len(s.recentEvents) > s.maxRecentEvents {
		s.recentEvents = s.recentEvents[len(s.recentEvents)-s.maxRecentEvents:]
	}
}

func isNonStrategyFailure(reason string) bool {
	switch reason {
	case "timeout", "network_error", "client_disconnect", "upstream_4xx", "upstream_5xx", "range_invalid",
		"context_canceled", "broken_pipe", "connection_reset", "stream_error", "unknown", "raw_url_empty":
		return true
	default:
		return false
	}
}

func (s *StrategySelector) ensureState(provider string) *ProviderStrategyState {
	provider = normalizeStrategyProviderKey(provider)
	if state, ok := s.store.Get(provider); ok {
		return state
	}
	state := &ProviderStrategyState{
		Provider:  provider,
		Preferred: "",
		Failures:  make(map[StreamStrategy]int),
	}
	_ = s.store.Set(provider, state)
	return state
}

func ProviderKey(targetURL string, _ string) string {
	host := ""
	if parsed, err := url.Parse(targetURL); err == nil {
		host = parsed.Host
	}
	return normalizeStrategyProviderKey(host)
}

func normalizeStrategyProviderKey(provider string) string {
	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "default"
	}
	if idx := strings.Index(provider, "::"); idx >= 0 {
		provider = provider[:idx]
	}
	if provider == "" {
		return "default"
	}
	return provider
}

func indexOfStrategy(order []StreamStrategy, target StreamStrategy) int {
	for idx, item := range order {
		if item == target {
			return idx
		}
	}
	return -1
}

func dedupeStrategies(order []StreamStrategy) []StreamStrategy {
	seen := make(map[StreamStrategy]struct{})
	out := make([]StreamStrategy, 0, len(order))
	for _, item := range order {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

// StreamOutcome describes the streaming result for strategy selection.
type StreamOutcome struct {
	Err             error
	FailureReason   string
	Retryable       bool
	ResponseStarted bool
	StatusCode      int
}
