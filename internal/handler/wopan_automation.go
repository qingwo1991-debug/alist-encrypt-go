package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

const wopanAutomationPhrase = "自动清空所选账号全部回收站"

type wopanAutomationResult struct {
	StorageID int    `json:"storage_id"`
	Status    string `json:"status"`
	Code      string `json:"code,omitempty"`
}

type wopanAutomationState struct {
	once             sync.Once
	wake             chan struct{}
	done             chan struct{}
	running          bool
	persistenceFault bool
	cancel           context.CancelFunc
	lastRun          string
	results          []wopanAutomationResult
	// wait is injectable for deterministic scheduler tests. A timer is stopped
	// on both policy changes and shutdown; no OS service or browser session exists.
	wait func(time.Duration) (<-chan time.Time, func())
}

type wopanAutomationRequest struct {
	Enabled            bool   `json:"enabled"`
	StorageIDs         []int  `json:"storage_ids"`
	IntervalHours      int    `json:"interval_hours"`
	ConfirmationPhrase string `json:"confirmation_phrase"`
}

func (h *WopanAdminHandler) automationViewLocked() map[string]interface{} {
	p := h.cfg.CloudStorageSnapshot().WopanAutomation
	ids := append([]int{}, p.StorageIDs...)
	results := append([]wopanAutomationResult{}, h.automation.results...)
	// Durable pending/unknown checkpoints remain visible after a process restart.
	for _, b := range p.Bindings {
		if !b.Quarantined {
			continue
		}
		found := false
		for i := range results {
			if results[i].StorageID == b.StorageID {
				results[i].Status, results[i].Code = "blocked", "clear_outcome_unknown"
				found = true
			}
		}
		if !found {
			results = append(results, wopanAutomationResult{b.StorageID, "blocked", "clear_outcome_unknown"})
		}
	}
	view := map[string]interface{}{"enabled": p.Enabled, "storage_ids": ids, "interval_hours": p.IntervalHours, "running": h.automation.running}
	if h.automation.persistenceFault {
		for _, id := range p.StorageIDs {
			results = append(results, wopanAutomationResult{id, "blocked", "automation_persistence_failed"})
		}
	}
	if h.automation.lastRun != "" {
		view["last_run"] = h.automation.lastRun
	}
	if len(results) > 0 {
		view["last_results"] = results
	}
	return view
}

func (h *WopanAdminHandler) GetAutomation(w http.ResponseWriter, r *http.Request) {
	wopanPrivate(w)
	if _, err := h.localAdmin(r); err != nil {
		h.fail(w, err)
		return
	}
	h.mu.Lock()
	view := h.automationViewLocked()
	h.mu.Unlock()
	RespondSuccess(w, view)
}

func (h *WopanAdminHandler) SaveAutomation(w http.ResponseWriter, r *http.Request) {
	wopanPrivate(w)
	local, err := h.localAdmin(r)
	if err == nil {
		err = wopanCSRF(r)
	}
	var input wopanAutomationRequest
	if err == nil {
		err = wopanRequest(r, &input, "enabled", "storage_ids", "interval_hours", "confirmation_phrase")
	}
	if err == nil {
		seen := map[int]bool{}
		if input.IntervalHours < 1 || input.IntervalHours > 720 || len(input.StorageIDs) > 20 || (input.Enabled && len(input.StorageIDs) == 0) {
			err = wopanError(http.StatusBadRequest, "invalid_automation_policy")
		}
		for _, id := range input.StorageIDs {
			if id <= 0 || seen[id] {
				err = wopanError(http.StatusBadRequest, "invalid_automation_policy")
			}
			seen[id] = true
		}
	}
	if err == nil && input.Enabled && input.ConfirmationPhrase != wopanAutomationPhrase {
		err = wopanError(http.StatusBadRequest, "confirmation_phrase_mismatch")
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	previous := h.cfg.CloudStorageSnapshot().WopanAutomation
	policy := config.WopanAutomationConfig{Enabled: input.Enabled, StorageIDs: input.StorageIDs, IntervalHours: input.IntervalHours, Username: local.username, Version: previous.Version + 1}
	var session wopanUpstreamSession
	if input.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		session, err = h.snapshot()
		if err == nil {
			err = h.upstreamAdmin(ctx, &session, local)
		}
		for _, id := range input.StorageIDs {
			if err != nil {
				break
			}
			var binding config.WopanAutomationBinding
			binding, _, err = h.automationBinding(ctx, session, id)
			if err == nil {
				policy.Bindings = append(policy.Bindings, binding)
			}
		}
		if err == nil && !h.unchanged(session) {
			err = wopanError(http.StatusConflict, "configuration_changed")
		}
	}
	if err == nil {
		_, err = h.localAdmin(r)
	}
	if err != nil {
		h.fail(w, err)
		return
	}
	// Serialize policy publication with the final pre-provider gate. Enabling or
	// reconfirming while an older round runs is rejected, never silently rearmed.
	h.mu.Lock()
	if input.Enabled && (h.automation.running || len(h.inflight) > 0) {
		h.mu.Unlock()
		h.fail(w, wopanError(http.StatusConflict, "automation_running"))
		return
	}
	if input.Enabled && !h.unchanged(session) {
		h.mu.Unlock()
		h.fail(w, wopanError(http.StatusConflict, "configuration_changed"))
		return
	}
	// Even a failed disable save stops this process's current network work.
	if !input.Enabled && h.automation.cancel != nil {
		h.automation.cancel()
	}
	err = h.cfg.UpdateWopanAutomation(previous.Version, policy)
	if err != nil {
		h.automation.persistenceFault = true
		if h.automation.cancel != nil {
			h.automation.cancel()
		}
		h.mu.Unlock()
		code, status := "automation_save_failed", http.StatusInternalServerError
		if errors.Is(err, config.ErrWopanAutomationVersionConflict) {
			code, status = "policy_changed", http.StatusConflict
		}
		h.fail(w, wopanError(status, code))
		return
	}
	if h.automation.cancel != nil {
		h.automation.cancel()
	}
	if input.Enabled {
		h.automation.persistenceFault = false
	}
	h.automation.results = nil
	h.automation.lastRun = ""
	if h.automation.wake != nil {
		select {
		case h.automation.wake <- struct{}{}:
		default:
		}
	}
	view := h.automationViewLocked()
	// A successful disable prevents future submissions and cancels network work
	// best-effort. A request already sent to WoPan cannot be revoked.
	h.mu.Unlock()
	RespondSuccess(w, view)
}

// The entire storage record is intentionally hashed: token rotation also holds
// the policy for explicit re-confirmation instead of weakening account binding.
func (h *WopanAdminHandler) automationBinding(ctx context.Context, s wopanUpstreamSession, id int) (config.WopanAutomationBinding, wopanAddition, error) {
	b := config.WopanAutomationBinding{StorageID: id}
	value, err := h.storage(ctx, s, id)
	if err != nil {
		return b, wopanAddition{}, err
	}
	addition, err := wopanPersonal(value)
	if err != nil {
		return b, addition, err
	}
	account, err := h.provider.Account(ctx, addition.AccessToken)
	if err != nil {
		return b, addition, err
	}
	if account.ID == "" {
		return b, addition, wopanError(http.StatusBadGateway, "provider_invalid_response")
	}
	accountKey := sha256.Sum256([]byte(account.ID)) // same private key as manual ClearRecycle
	b.AccountHash = hex.EncodeToString(accountKey[:])
	encoded, _ := json.Marshal(struct {
		Origin      string
		ConfigHash  [32]byte
		StorageHash [32]byte
		Account     string
	}{s.origin, s.configHash, wopanStorageHash(value), account.ID})
	identity := sha256.Sum256(encoded)
	b.IdentityHash = hex.EncodeToString(identity[:])
	return b, addition, nil
}

// StartAutomation is called only by Server.Start, never route registration or
// handler construction. One instance owns exactly one serial lifecycle worker.
func (h *WopanAdminHandler) StartAutomation(ctx context.Context) {
	h.automation.once.Do(func() {
		h.mu.Lock()
		h.automation.wake = make(chan struct{}, 1)
		h.automation.done = make(chan struct{})
		wait := h.automation.wait
		if wait == nil {
			wait = func(d time.Duration) (<-chan time.Time, func()) {
				timer := time.NewTimer(d)
				return timer.C, func() { timer.Stop() }
			}
		}
		h.mu.Unlock()
		go func() {
			defer close(h.automation.done)
			for {
				p := h.cfg.CloudStorageSnapshot().WopanAutomation
				interval := p.IntervalHours
				if interval < 1 || interval > 720 {
					interval = 24
				}
				ticks, stop := wait(time.Duration(interval) * time.Hour)
				select {
				case <-ctx.Done():
					stop()
					return
				case <-h.automation.wake:
					stop()
					continue
				case <-ticks:
					stop()
				}
				if ctx.Err() != nil {
					return
				}
				// Every startup and every successful policy save waits a FULL interval.
				// A stale timer may never run a newly published version early.
				if current := h.cfg.CloudStorageSnapshot().WopanAutomation; current.Version != p.Version || !current.Enabled {
					continue
				}
				h.runAutomationOnce(ctx, p.Version)
			}
		}()
	})
}

func (h *WopanAdminHandler) WaitAutomation(ctx context.Context) error {
	h.mu.Lock()
	done := h.automation.done
	h.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func automationCode(err error) string {
	var known *wopanAdminError
	if errors.As(err, &known) {
		return known.code
	}
	return "provider_unavailable"
}

func (h *WopanAdminHandler) automationUser(username string) bool {
	if username == "" || h.userDAO == nil {
		return false
	}
	user, err := h.userDAO.Get(username)
	return err == nil && user != nil && user.Username == username
}

// runAutomationOnce is deliberately private. Tests inject fake providers and
// call it without exporting any administrator-bypass HTTP execution endpoint.
func (h *WopanAdminHandler) runAutomationOnce(parent context.Context, version uint64) {
	h.mu.Lock()
	policy := h.cfg.CloudStorageSnapshot().WopanAutomation
	if parent.Err() != nil || !policy.Enabled || policy.Version != version || h.automation.running || h.automation.persistenceFault {
		h.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	h.automation.running = true
	h.automation.cancel = cancel
	h.mu.Unlock()
	results := make([]wopanAutomationResult, 0, len(policy.StorageIDs))
	defer func() {
		cancel()
		h.mu.Lock()
		h.automation.running = false
		h.automation.cancel = nil
		if h.cfg.CloudStorageSnapshot().WopanAutomation.Version == version {
			h.automation.lastRun = h.now().UTC().Format(time.RFC3339)
			h.automation.results = results
		}
		h.mu.Unlock()
	}()
	session, err := h.snapshot()
	if !h.automationUser(policy.Username) {
		err = wopanError(http.StatusForbidden, "local_admin_required")
	}
	if err == nil {
		err = h.upstreamAdmin(ctx, &session, wopanLocalAdmin{username: policy.Username})
	}
	seen := map[string]wopanAutomationResult{}
	for _, id := range policy.StorageIDs {
		result := wopanAutomationResult{StorageID: id, Status: "failed"}
		if err != nil {
			result.Code = automationCode(err)
			results = append(results, result)
			continue
		}
		if ctx.Err() != nil {
			result.Code = "operation_cancelled"
			results = append(results, result)
			continue
		}
		expected := config.WopanAutomationBinding{}
		for _, b := range policy.Bindings {
			if b.StorageID == id {
				expected = b
				break
			}
		}
		if expected.Quarantined {
			result.Status, result.Code = "blocked", "clear_outcome_unknown"
			results = append(results, result)
			continue
		}
		opCtx, opCancel := context.WithTimeout(ctx, wopanOperationTimeout)
		binding, addition, resolveErr := h.automationBinding(opCtx, session, id)
		if resolveErr == nil && (expected.IdentityHash == "" || binding.IdentityHash != expected.IdentityHash || binding.AccountHash != expected.AccountHash) {
			resolveErr = wopanError(http.StatusConflict, "binding_changed_reconfirm")
		}
		if resolveErr != nil {
			switch automationCode(resolveErr) {
			case "binding_changed_reconfirm", "storage_not_wopan", "storage_unavailable", "family_not_supported", "storage_credentials_unavailable":
				// Once a dangerous identity/scope change is observed, reverting
				// upstream values cannot silently restore consent. Hold the OLD
				// confirmed account, never any newly observed unconfirmed account.
				if expected.AccountHash != "" {
					h.mu.Lock()
					if checkpointErr := h.cfg.SetWopanAutomationCheckpoint(version, expected.AccountHash, true); checkpointErr != nil {
						h.automation.persistenceFault = true
					}
					h.mu.Unlock()
				}
			}
		}
		if resolveErr == nil {
			if prior, ok := seen[binding.AccountHash]; ok {
				result.Status, result.Code = prior.Status, prior.Code
				if prior.Status == "accepted" {
					result.Status, result.Code = "skipped", "account_deduplicated"
				}
				opCancel()
				results = append(results, result)
				continue
			}
			resolveErr = h.automationClear(opCtx, session, policy, binding, addition)
		}
		opCancel()
		if resolveErr != nil {
			result.Code = automationCode(resolveErr)
			if result.Code == "clear_outcome_unknown" {
				result.Status = "blocked"
			}
		} else {
			result.Status = "accepted"
		}
		if binding.AccountHash != "" {
			seen[binding.AccountHash] = result
		}
		results = append(results, result)
	}
}

// manualAutomationCheckpoint shares the automatic account journal without
// changing the existing two-stage manual confirmation authorization.
func (h *WopanAdminHandler) manualAutomationCheckpoint(key [32]byte) (func() error, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.cfg.CloudStorageSnapshot().WopanAutomation
	accountHash := hex.EncodeToString(key[:])
	matched := false
	for _, b := range p.Bindings {
		if b.AccountHash == accountHash {
			matched = true
		}
	}
	if !matched {
		return func() error { return nil }, nil
	}
	if err := h.cfg.SetWopanAutomationCheckpoint(p.Version, accountHash, true); err != nil {
		h.automation.persistenceFault = true
		return nil, wopanError(http.StatusInternalServerError, "automation_checkpoint_failed")
	}
	return func() error {
		// A manual success must never clear an already unknown automatic checkpoint.
		for _, b := range p.Bindings {
			if b.AccountHash == accountHash && b.Quarantined {
				return nil
			}
		}
		if err := h.cfg.SetWopanAutomationCheckpoint(p.Version, accountHash, false); err != nil {
			h.mu.Lock()
			h.automation.persistenceFault = true
			h.mu.Unlock()
			return err
		}
		return nil
	}, nil
}

func (h *WopanAdminHandler) automationClear(ctx context.Context, s wopanUpstreamSession, p config.WopanAutomationConfig, b config.WopanAutomationBinding, a wopanAddition) error {
	var key [32]byte
	decoded, err := hex.DecodeString(b.AccountHash)
	if err != nil || len(decoded) != len(key) {
		return wopanError(http.StatusConflict, "binding_changed_reconfirm")
	}
	copy(key[:], decoded)
	h.mu.Lock()
	current := h.cfg.CloudStorageSnapshot().WopanAutomation
	if h.automation.persistenceFault || ctx.Err() != nil || !current.Enabled || current.Version != p.Version || !h.unchanged(s) || !h.automationUser(p.Username) {
		h.mu.Unlock()
		return wopanError(http.StatusConflict, "policy_changed")
	}
	for _, entry := range current.Bindings {
		if entry.AccountHash == b.AccountHash && entry.Quarantined {
			h.mu.Unlock()
			return wopanError(http.StatusConflict, "clear_outcome_unknown")
		}
	}
	if h.inflight[key] || len(h.inflight) >= wopanStateLimit {
		h.mu.Unlock()
		return wopanError(http.StatusConflict, "clear_in_progress")
	}
	// Write-ahead checkpoint: a crash, timeout or post-success disk failure leaves
	// all mounts of this account quarantined across restart, never blindly retried.
	if err = h.cfg.SetWopanAutomationCheckpoint(p.Version, b.AccountHash, true); err != nil {
		h.automation.persistenceFault = true
		h.mu.Unlock()
		return wopanError(http.StatusInternalServerError, "automation_checkpoint_failed")
	}
	h.inflight[key] = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); delete(h.inflight, key); h.mu.Unlock() }()
	// Disable cancels ctx; no network submission occurs if cancellation won this
	// gate. Already submitted provider requests are inherently irreversible.
	h.mu.Lock()
	current = h.cfg.CloudStorageSnapshot().WopanAutomation
	allowed := ctx.Err() == nil && current.Enabled && current.Version == p.Version && !h.automation.persistenceFault && h.unchanged(s) && h.automationUser(p.Username)
	h.mu.Unlock()
	if !allowed {
		return wopanError(http.StatusConflict, "clear_outcome_unknown")
	}
	if err = h.provider.EmptyRecycle(ctx, a.AccessToken); err != nil {
		return wopanError(http.StatusBadGateway, "clear_outcome_unknown")
	}
	if err = h.cfg.SetWopanAutomationCheckpoint(p.Version, b.AccountHash, false); err != nil {
		h.mu.Lock()
		h.automation.persistenceFault = true
		h.mu.Unlock()
		return wopanError(http.StatusInternalServerError, "clear_outcome_unknown")
	}
	return nil
}
