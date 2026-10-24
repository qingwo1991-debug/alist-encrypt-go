package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// CloudStorageConfig contains independently versioned, local cloud policies.
// Provider credentials and raw account identities must never be stored here.
type CloudStorageConfig struct {
	WopanAutomation WopanAutomationConfig `json:"wopan_automation"`
}

// WopanAutomationConfig is an explicit opt-in policy, not a runtime config fence.
// Bindings pin each selected storage to opaque SHA-256 identity/account hashes.
type WopanAutomationConfig struct {
	Enabled       bool                     `json:"enabled"`
	StorageIDs    []int                    `json:"storage_ids"`
	IntervalHours int                      `json:"interval_hours"`
	Username      string                   `json:"username"`
	Version       uint64                   `json:"version"`
	Bindings      []WopanAutomationBinding `json:"bindings"`
}

// WopanAutomationBinding contains no provider tokens or raw account IDs.
// Quarantined also serves as a durable pre-operation checkpoint: an unfinished
// destructive operation must remain quarantined across process restarts.
type WopanAutomationBinding struct {
	StorageID    int    `json:"storage_id"`
	IdentityHash string `json:"identity_hash"`
	AccountHash  string `json:"account_hash"`
	Quarantined  bool   `json:"quarantined"`
}

// ErrWopanAutomationVersionConflict reports a stale policy CAS generation.
var ErrWopanAutomationVersionConflict = errors.New("wopan automation version conflict")

func cloneCloudStorageConfig(src CloudStorageConfig) CloudStorageConfig {
	src.WopanAutomation.StorageIDs = append([]int(nil), src.WopanAutomation.StorageIDs...)
	src.WopanAutomation.Bindings = append([]WopanAutomationBinding(nil), src.WopanAutomation.Bindings...)
	return src
}

// CloudStorageSnapshot returns a deep copy, safe for callers to retain/mutate.
// Older local configurations without an interval retain the 24-hour default.
func (c *Config) CloudStorageSnapshot() CloudStorageConfig {
	if c == nil {
		return CloudStorageConfig{WopanAutomation: WopanAutomationConfig{IntervalHours: 24}}
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := cloneCloudStorageConfig(c.CloudStorage)
	if snapshot.WopanAutomation.IntervalHours == 0 {
		snapshot.WopanAutomation.IntervalHours = 24
	}
	return snapshot
}

func validWopanAutomationHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateWopanAutomation(policy WopanAutomationConfig) error {
	if policy.IntervalHours < 1 || policy.IntervalHours > 720 {
		return fmt.Errorf("wopan automation interval_hours must be between 1 and 720")
	}
	if len(policy.StorageIDs) > 20 || (policy.Enabled && len(policy.StorageIDs) == 0) {
		return fmt.Errorf("wopan automation requires 1 to 20 storage IDs when enabled")
	}
	if policy.Enabled && strings.TrimSpace(policy.Username) == "" {
		return fmt.Errorf("wopan automation username must not be empty when enabled")
	}
	ids := make(map[int]struct{}, len(policy.StorageIDs))
	for _, id := range policy.StorageIDs {
		if id <= 0 {
			return fmt.Errorf("wopan automation storage IDs must be positive")
		}
		if _, exists := ids[id]; exists {
			return fmt.Errorf("wopan automation storage IDs must be unique")
		}
		ids[id] = struct{}{}
	}
	if (policy.Enabled || len(policy.Bindings) != 0) && len(policy.Bindings) != len(policy.StorageIDs) {
		return fmt.Errorf("wopan automation bindings must exactly match storage IDs")
	}
	bound := make(map[int]struct{}, len(policy.Bindings))
	for _, binding := range policy.Bindings {
		if _, exists := ids[binding.StorageID]; !exists {
			return fmt.Errorf("wopan automation binding does not match a selected storage ID")
		}
		if _, exists := bound[binding.StorageID]; exists {
			return fmt.Errorf("wopan automation binding storage IDs must be unique")
		}
		if !validWopanAutomationHash(binding.IdentityHash) || !validWopanAutomationHash(binding.AccountHash) {
			return fmt.Errorf("wopan automation binding hashes must be opaque 64-character hex values")
		}
		bound[binding.StorageID] = struct{}{}
	}
	return nil
}

// UpdateWopanAutomation atomically persists a policy using compare-and-swap.
// Every save, including disabling/re-enabling, must supply the next version.
// Policy changes never advance the unrelated runtimeRevision publication fence.
func (c *Config) UpdateWopanAutomation(expectedVersion uint64, policy WopanAutomationConfig) error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if expectedVersion == ^uint64(0) || policy.Version != expectedVersion+1 {
		return fmt.Errorf("wopan automation policy version must equal expected version plus one")
	}
	if err := validateWopanAutomation(policy); err != nil {
		return err
	}
	candidate := cloneCloudStorageConfig(CloudStorageConfig{WopanAutomation: policy})
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.CloudStorage.WopanAutomation.Version != expectedVersion {
		return ErrWopanAutomationVersionConflict
	}
	old := c.CloudStorage
	c.CloudStorage = candidate
	if err := c.saveLocked(); err != nil {
		c.CloudStorage = old
		return err
	}
	return nil
}

// SetWopanAutomationCheckpoint persists all bindings of one account as a single
// transaction without changing the policy Version or runtimeRevision. Call with
// true BEFORE invoking a destructive provider operation. Clear with false only
// after confirmed success; a failed save rolls back so the quarantine remains.
func (c *Config) SetWopanAutomationCheckpoint(expectedVersion uint64, accountHash string, quarantined bool) error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if !validWopanAutomationHash(accountHash) {
		return fmt.Errorf("wopan automation account hash must be an opaque 64-character hex value")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.CloudStorage.WopanAutomation.Version != expectedVersion {
		return ErrWopanAutomationVersionConflict
	}
	candidate := cloneCloudStorageConfig(c.CloudStorage)
	matched := false
	for i := range candidate.WopanAutomation.Bindings {
		binding := &candidate.WopanAutomation.Bindings[i]
		if binding.AccountHash == accountHash {
			binding.Quarantined = quarantined
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("wopan automation account has no matching bindings")
	}
	old := c.CloudStorage
	c.CloudStorage = candidate
	if err := c.saveLocked(); err != nil {
		c.CloudStorage = old
		return err
	}
	return nil
}

// QuarantineWopanAutomation durably quarantines every binding of an account.
func (c *Config) QuarantineWopanAutomation(expectedVersion uint64, accountHash string) error {
	return c.SetWopanAutomationCheckpoint(expectedVersion, accountHash, true)
}
