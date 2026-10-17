// Package recovery loads an offline recovery marker. It does not install fences,
// acquire service ownership, perform restores, or authorize reconciliation.
package recovery

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const SidecarName = "recovery-state.json"

var ErrRequired = errors.New("recovery_reconciliation_required")

// State is immutable after Load. A missing marker permits legacy startup; any
// present marker fences writes. There is deliberately no approved/clear state.
// Absence detection against a restored DB generation requires the future offline
// restore protocol; deleting this file outside that protocol is not safe.
type State struct {
	required bool
	stage    string
	reason   string
}

func (s *State) Required() bool { return s != nil && s.required }
func (s *State) Status() Status {
	if !s.Required() {
		return Status{Stage: "normal"}
	}
	return Status{Required: true, Stage: s.stage, Reason: s.reason}
}

type Status struct {
	Required bool   `json:"required"`
	Stage    string `json:"stage"`
	Reason   string `json:"reason,omitempty"`
}

type marker struct {
	Version      int    `json:"version"`
	Stage        string `json:"stage"`
	OperationID  string `json:"operation_id"`
	BundleSHA256 string `json:"bundle_sha256"`
	Generation   uint64 `json:"generation"`
}

// Load never writes or repairs state. Invalid/unreadable/unknown markers remain
// fenced while allowing authenticated status and ordinary reads to be served.
// Lstat rejects symlinks and non-regular files. The service directory must remain
// operator-owned; this is not protection against an operator replacing files.
func Load(dir string) *State {
	p := filepath.Join(dir, SidecarName)
	info, err := os.Lstat(p)
	if os.IsNotExist(err) {
		return &State{}
	}
	bad := &State{true, "invalid", "invalid_recovery_state"}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return bad
	}
	f, err := os.Open(p)
	if err != nil {
		return bad
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) > 4096 {
		return bad
	}
	var m marker
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
		return bad
	}
	hash, err := hex.DecodeString(m.BundleSHA256)
	if m.Version != 1 || m.Generation == 0 || len(m.OperationID) == 0 || len(m.OperationID) > 128 || err != nil || len(hash) != 32 {
		return bad
	}
	for _, c := range m.OperationID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return bad
		}
	}
	switch m.Stage {
	case "prepared", "restoring", "reconciliation-required":
		return &State{true, m.Stage, ErrRequired.Error()}
	default:
		return bad
	}
}
