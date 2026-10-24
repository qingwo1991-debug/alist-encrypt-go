package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func testWopanAutomationPolicy() WopanAutomationConfig {
	return WopanAutomationConfig{
		Enabled: true, StorageIDs: []int{1, 2, 3}, IntervalHours: 24, Username: "operator", Version: 1,
		Bindings: []WopanAutomationBinding{
			{StorageID: 1, IdentityHash: strings.Repeat("a", 64), AccountHash: strings.Repeat("b", 64)},
			{StorageID: 2, IdentityHash: strings.Repeat("c", 64), AccountHash: strings.Repeat("b", 64)},
			{StorageID: 3, IdentityHash: strings.Repeat("d", 64), AccountHash: strings.Repeat("e", 64)},
		},
	}
}

func TestCloudStorageSnapshotDefaultsAndDeepCopy(t *testing.T) {
	for _, cfg := range []*Config{nil, {}, DefaultConfig()} {
		snapshot := cfg.CloudStorageSnapshot()
		if snapshot.WopanAutomation.Enabled || snapshot.WopanAutomation.IntervalHours != 24 {
			t.Fatalf("unsafe/missing default: %#v", snapshot)
		}
	}
	cfg := LoadFromBaseDir(t.TempDir())
	policy := testWopanAutomationPolicy()
	if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
		t.Fatal(err)
	}
	want := cfg.CloudStorageSnapshot()
	policy.StorageIDs[0] = 99
	policy.Bindings[0].IdentityHash = "caller-mutated"
	snapshot := cfg.CloudStorageSnapshot()
	snapshot.WopanAutomation.StorageIDs[0] = 100
	snapshot.WopanAutomation.Bindings[0].AccountHash = "snapshot-mutated"
	cfg.mu.RLock()
	internal := cfg.snapshotLocked()
	cfg.mu.RUnlock()
	internal.CloudStorage.WopanAutomation.Bindings[0].Quarantined = true
	internal.CloudStorage.WopanAutomation.StorageIDs[0] = 101
	if got := cfg.CloudStorageSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("retained caller/snapshot memory: got %#v want %#v", got, want)
	}
}

func TestWopanAutomationPersistenceAndIndependentVersion(t *testing.T) {
	baseDir := t.TempDir()
	cfg := LoadFromBaseDir(baseDir)
	revision := cfg.RuntimeRevision()
	policy := testWopanAutomationPolicy()
	if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
		t.Fatal(err)
	}
	if cfg.RuntimeRevision() != revision {
		t.Fatal("policy save advanced unrelated runtime revision")
	}
	if err := cfg.QuarantineWopanAutomation(1, policy.Bindings[0].AccountHash); err != nil {
		t.Fatal(err)
	}
	want := cfg.CloudStorageSnapshot()
	if !want.WopanAutomation.Bindings[0].Quarantined || !want.WopanAutomation.Bindings[1].Quarantined || want.WopanAutomation.Bindings[2].Quarantined {
		t.Fatalf("quarantine did not match all and only account bindings: %#v", want)
	}
	if cfg.RuntimeRevision() != revision || want.WopanAutomation.Version != 1 {
		t.Fatal("quarantine changed policy/runtime version")
	}
	if err := cfg.ReplaceFromJSON([]byte(`{"port":5345}`)); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if got := LoadFromBaseDir(baseDir).CloudStorageSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("generic save/load lost policy/checkpoint: got %#v want %#v", got, want)
	}
	data, err := os.ReadFile(filepath.Join(baseDir, "conf", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted struct {
		CloudStorage CloudStorageConfig `json:"cloudStorage"`
	}
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(persisted.CloudStorage, want) {
		t.Fatalf("disk snapshot omitted policy fields: %s", data)
	}
	if err := cfg.SetWopanAutomationCheckpoint(1, policy.Bindings[0].AccountHash, false); err != nil {
		t.Fatal(err)
	}
	cleared := LoadFromBaseDir(baseDir).CloudStorageSnapshot()
	if cleared.WopanAutomation.Bindings[0].Quarantined || cleared.WopanAutomation.Bindings[1].Quarantined {
		t.Fatal("successful checkpoint clear was not durable")
	}
	if cleared.WopanAutomation.Version != 1 || cfg.RuntimeRevision() != revision+1 {
		t.Fatal("checkpoint clear changed versions")
	}
}

func TestWopanAutomationCAS(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	policy := testWopanAutomationPolicy()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- cfg.UpdateWopanAutomation(0, policy)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	succeeded, conflicted := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
		} else if errors.Is(err, ErrWopanAutomationVersionConflict) {
			conflicted++
		} else {
			t.Fatal(err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("CAS results: %d successful, %d conflicted", succeeded, conflicted)
	}
	if err := cfg.UpdateWopanAutomation(1, policy); err == nil {
		t.Fatal("accepted same-version policy save")
	}
	if err := cfg.QuarantineWopanAutomation(0, policy.Bindings[0].AccountHash); !errors.Is(err, ErrWopanAutomationVersionConflict) {
		t.Fatalf("stale checkpoint error = %v", err)
	}
	policy.Version = 2
	policy.Enabled = false
	policy.Bindings = nil // Disabling may discard bindings, retaining selected IDs.
	if err := cfg.UpdateWopanAutomation(1, policy); err != nil {
		t.Fatalf("disabled policy with empty bindings rejected: %v", err)
	}
	policy.Version = 0
	if err := cfg.UpdateWopanAutomation(^uint64(0), policy); err == nil {
		t.Fatal("accepted overflowing policy version")
	}
}

func TestWopanAutomationValidation(t *testing.T) {
	cases := map[string]func(*WopanAutomationConfig){
		"no IDs":               func(p *WopanAutomationConfig) { p.StorageIDs = nil; p.Bindings = nil },
		"too many IDs":         func(p *WopanAutomationConfig) { p.StorageIDs = make([]int, 21) },
		"nonpositive ID":       func(p *WopanAutomationConfig) { p.StorageIDs[0] = 0 },
		"duplicate ID":         func(p *WopanAutomationConfig) { p.StorageIDs[1] = 1 },
		"low interval":         func(p *WopanAutomationConfig) { p.IntervalHours = 0 },
		"high interval":        func(p *WopanAutomationConfig) { p.IntervalHours = 721 },
		"empty username":       func(p *WopanAutomationConfig) { p.Username = " \t" },
		"missing binding":      func(p *WopanAutomationConfig) { p.Bindings = p.Bindings[:2] },
		"extra binding":        func(p *WopanAutomationConfig) { p.Bindings = append(p.Bindings, p.Bindings[0]) },
		"mismatched binding":   func(p *WopanAutomationConfig) { p.Bindings[0].StorageID = 4 },
		"duplicate binding":    func(p *WopanAutomationConfig) { p.Bindings[1].StorageID = 1 },
		"raw identity":         func(p *WopanAutomationConfig) { p.Bindings[0].IdentityHash = "raw-provider-identity" },
		"short account hash":   func(p *WopanAutomationConfig) { p.Bindings[1].AccountHash = strings.Repeat("a", 63) },
		"nonhex hash":          func(p *WopanAutomationConfig) { p.Bindings[2].IdentityHash = strings.Repeat("z", 64) },
		"disabled bad binding": func(p *WopanAutomationConfig) { p.Enabled = false; p.Bindings[0].AccountHash = "raw-account" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.configPath = filepath.Join(t.TempDir(), "config.json")
			before := cfg.CloudStorageSnapshot()
			policy := testWopanAutomationPolicy()
			mutate(&policy)
			if err := cfg.UpdateWopanAutomation(0, policy); err == nil {
				t.Fatal("invalid policy accepted")
			}
			if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) || cfg.RuntimeRevision() != 0 {
				t.Fatal("invalid update changed live state")
			}
		})
	}
}

func TestWopanAutomationFailedSavesRollback(t *testing.T) {
	baseDir := t.TempDir()
	cfg := LoadFromBaseDir(baseDir)
	policy := testWopanAutomationPolicy()
	if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
		t.Fatal(err)
	}
	path := cfg.configPath
	beforeDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before := cfg.CloudStorageSnapshot()
	revision := cfg.RuntimeRevision()
	cfg.configPath = t.TempDir() // Atomic rename cannot replace a directory.
	policy.Version = 2
	policy.Username = "must-not-stick"
	if err := cfg.UpdateWopanAutomation(1, policy); err == nil {
		t.Fatal("policy save unexpectedly succeeded")
	}
	if err := cfg.QuarantineWopanAutomation(1, policy.Bindings[0].AccountHash); err == nil {
		t.Fatal("checkpoint save unexpectedly succeeded")
	}
	if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) || cfg.RuntimeRevision() != revision {
		t.Fatal("failed save changed live state")
	}
	afterDisk, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(beforeDisk, afterDisk) {
		t.Fatal("failed save changed disk state", err)
	}
	cfg.configPath = path
	if err := cfg.QuarantineWopanAutomation(1, policy.Bindings[0].AccountHash); err != nil {
		t.Fatal(err)
	}
	quarantined := cfg.CloudStorageSnapshot()
	cfg.configPath = t.TempDir()
	if err := cfg.SetWopanAutomationCheckpoint(1, policy.Bindings[0].AccountHash, false); err == nil {
		t.Fatal("checkpoint clear unexpectedly succeeded")
	}
	if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), quarantined) {
		t.Fatal("failed checkpoint clear lost in-memory quarantine")
	}
	if !reflect.DeepEqual(LoadFromBaseDir(baseDir).CloudStorageSnapshot(), quarantined) {
		t.Fatal("failed checkpoint clear lost durable quarantine")
	}
	if err := cfg.SetWopanAutomationCheckpoint(1, strings.Repeat("f", 64), true); err == nil {
		t.Fatal("unmatched account checkpoint accepted")
	}
}

func TestWopanAutomationGenericSaveRollbackPreservesQuarantine(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	policy := testWopanAutomationPolicy()
	if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
		t.Fatal(err)
	}
	if err := cfg.QuarantineWopanAutomation(1, policy.Bindings[0].AccountHash); err != nil {
		t.Fatal(err)
	}
	before := cfg.CloudStorageSnapshot()
	revision := cfg.RuntimeRevision()
	cfg.configPath = t.TempDir()
	if err := cfg.ReplaceFromJSON([]byte(`{"port":5345}`)); err == nil {
		t.Fatal("generic save unexpectedly succeeded")
	}
	if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) || cfg.RuntimeRevision() != revision || cfg.Port != 5344 {
		t.Fatal("generic save rollback changed policy/checkpoint/runtime state")
	}
	cfg.mu.Lock()
	snapshot := cfg.snapshotLocked()
	cfg.assignSnapshotLocked(snapshot)
	cfg.mu.Unlock()
	snapshot.CloudStorage.WopanAutomation.StorageIDs[0] = 99
	snapshot.CloudStorage.WopanAutomation.Bindings[0].Quarantined = false
	if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) {
		t.Fatal("assigned config retained snapshot-owned cloud policy slices")
	}
}

func TestPublicJSONSnapshotOmitsCloudPolicyAndRoundTrips(t *testing.T) {
	baseDir := t.TempDir()
	cfg := LoadFromBaseDir(baseDir)
	policy := testWopanAutomationPolicy()
	if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
		t.Fatal(err)
	}
	publicJSON, err := cfg.MarshalJSONSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(publicJSON, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["cloudStorage"]; exists {
		t.Fatalf("public generic JSON exposed cloud policy: %s", publicJSON)
	}
	if bytes.Contains(publicJSON, []byte(policy.Bindings[0].IdentityHash)) || bytes.Contains(publicJSON, []byte(policy.Bindings[0].AccountHash)) {
		t.Fatal("public generic JSON exposed policy bindings")
	}
	// A checkpoint newer than the public snapshot must survive its roundtrip.
	if err := cfg.QuarantineWopanAutomation(1, policy.Bindings[0].AccountHash); err != nil {
		t.Fatal(err)
	}
	want := cfg.CloudStorageSnapshot()
	if err := cfg.ReplaceFromJSON(publicJSON); err != nil {
		t.Fatalf("public generic JSON roundtrip failed: %v", err)
	}
	if got := LoadFromBaseDir(baseDir).CloudStorageSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("public roundtrip lost newer cloud checkpoint: got %#v want %#v", got, want)
	}
	fields["jwt_secret"] = json.RawMessage(`""`)
	invalidJSON, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ReplaceFromJSON(invalidJSON); err == nil || !strings.Contains(err.Error(), "jwt_secret") {
		t.Fatalf("full generic snapshot did not reach JWT validation: %v", err)
	}
}

func TestWopanAutomationAlistManagementChangesDurablyHoldConsent(t *testing.T) {
	for _, generic := range []bool{false, true} {
		name := "UpdateAlistServer"
		if generic {
			name = "ReplaceFromJSON"
		}
		t.Run(name, func(t *testing.T) {
			baseDir := t.TempDir()
			cfg := LoadFromBaseDir(baseDir)
			// Start with normalized snapshots to test actual value changes only.
			original := cfg.AlistServerSnapshot()
			if err := cfg.UpdateAlistServer(original); err != nil {
				t.Fatal(err)
			}
			original = cfg.AlistServerSnapshot()
			policy := testWopanAutomationPolicy()
			if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
				t.Fatal(err)
			}
			update := func(server AlistServer) error {
				if !generic {
					return cfg.UpdateAlistServer(server)
				}
				payload, err := json.Marshal(struct {
					AlistServer AlistServer `json:"alistServer"`
				}{AlistServer: server})
				if err != nil {
					return err
				}
				return cfg.ReplaceFromJSON(payload)
			}
			if err := update(original); err != nil {
				t.Fatal(err)
			}
			for _, binding := range cfg.CloudStorageSnapshot().WopanAutomation.Bindings {
				if binding.Quarantined {
					t.Fatal("same-value update unnecessarily held consent")
				}
			}
			changed := original
			changed.ServerHost = "changed.example"
			before := cfg.CloudStorageSnapshot()
			beforeRevision := cfg.RuntimeRevision()
			path := cfg.configPath
			cfg.configPath = t.TempDir()
			if err := update(changed); err == nil {
				t.Fatal("management save unexpectedly succeeded")
			}
			if !reflect.DeepEqual(cfg.AlistServerSnapshot(), original) || !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) || cfg.RuntimeRevision() != beforeRevision {
				t.Fatal("failed management save did not roll back context and consent")
			}
			cfg.configPath = path
			if err := update(changed); err != nil {
				t.Fatal(err)
			}
			if err := update(original); err != nil {
				t.Fatal(err)
			}
			got := LoadFromBaseDir(baseDir).CloudStorageSnapshot().WopanAutomation
			if got.Version != policy.Version {
				t.Fatal("context hold advanced independent policy version")
			}
			for _, binding := range got.Bindings {
				if !binding.Quarantined {
					t.Fatal("A -> B -> A resurrected prior consent")
				}
			}
		})
	}
}

func TestWopanAutomationCheckpointClearRequiresRuntimeRevision(t *testing.T) {
	baseDir := t.TempDir()
	cfg := LoadFromBaseDir(baseDir)
	policy := testWopanAutomationPolicy()
	if err := cfg.UpdateWopanAutomation(0, policy); err != nil {
		t.Fatal(err)
	}
	revision := cfg.RuntimeRevision()
	if err := cfg.QuarantineWopanAutomation(1, policy.Bindings[0].AccountHash); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ReplaceFromJSON([]byte(`{"port":5345}`)); err != nil {
		t.Fatal(err)
	}
	before := cfg.CloudStorageSnapshot()
	if err := cfg.ClearWopanAutomationCheckpoint(1, policy.Bindings[0].AccountHash, revision); !errors.Is(err, ErrWopanAutomationVersionConflict) {
		t.Fatalf("stale runtime clear error=%v", err)
	}
	if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) || !reflect.DeepEqual(LoadFromBaseDir(baseDir).CloudStorageSnapshot(), before) {
		t.Fatal("stale runtime clear lost durable quarantine")
	}
	if err := cfg.ClearWopanAutomationCheckpoint(1, policy.Bindings[0].AccountHash, cfg.RuntimeRevision()); err != nil {
		t.Fatal(err)
	}
	for _, binding := range cfg.CloudStorageSnapshot().WopanAutomation.Bindings {
		if binding.AccountHash == policy.Bindings[0].AccountHash && binding.Quarantined {
			t.Fatal("current runtime clear did not clear checkpoint")
		}
	}
}

func TestWopanAutomationDurabilityPlatformGuard(t *testing.T) {
	cases := []struct {
		name   string
		policy WopanAutomationConfig
		strict bool
	}{
		{name: "ordinary defaults", policy: WopanAutomationConfig{IntervalHours: 24}},
		{name: "enabled", policy: WopanAutomationConfig{Enabled: true}, strict: true},
		{name: "disabled quarantined", policy: WopanAutomationConfig{Bindings: []WopanAutomationBinding{{Quarantined: true}}}, strict: true},
		{name: "disabled clean binding", policy: WopanAutomationConfig{Bindings: []WopanAutomationBinding{{}}}},
		{name: "disabled later quarantined binding", policy: WopanAutomationConfig{Bindings: []WopanAutomationBinding{{}, {Quarantined: true}}}, strict: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			strict := wopanAutomationDurabilityRequired(CloudStorageConfig{WopanAutomation: tc.policy})
			if strict != tc.strict {
				t.Fatalf("strict=%v, want %v", strict, tc.strict)
			}
			if err := validateWopanAutomationDurability("windows", strict); (err != nil) != strict {
				t.Fatalf("Windows guard error=%v strict=%v", err, strict)
			}
			for _, goos := range []string{"linux", "darwin", "android"} {
				if err := validateWopanAutomationDurability(goos, strict); err != nil {
					t.Fatalf("%s unexpectedly rejected: %v", goos, err)
				}
			}
		})
	}
	// Explicit checkpoint writes must always request strict durability, even
	// when a disabled policy's final clean binding would not request it itself.
	if err := validateWopanAutomationDurability("windows", true); err == nil {
		t.Fatal("strict checkpoint durability accepted on Windows")
	}
}

func TestReplaceFromJSONRejectsCloudStorage(t *testing.T) {
	cfg := LoadFromBaseDir(t.TempDir())
	if err := cfg.UpdateWopanAutomation(0, testWopanAutomationPolicy()); err != nil {
		t.Fatal(err)
	}
	before := cfg.CloudStorageSnapshot()
	revision := cfg.RuntimeRevision()
	for _, payload := range []string{
		`{"cloudStorage":null}`,
		`{"cloudStorage":{}}`,
		`{"cloudStorage":{"wopan_automation":{"enabled":true}}}`,
		`{"CloudStorage":{}}`,
		`{"CLOUDSTORAGE":{}}`,
		`{"cloud\u0053torage":{}}`,
		`{"port":5345,"cloudStorage":null,"cloudStorage":{}}`,
	} {
		if err := cfg.ReplaceFromJSON([]byte(payload)); err == nil || !strings.Contains(err.Error(), "cloudStorage") {
			t.Fatalf("payload %s error = %v", payload, err)
		}
		if !reflect.DeepEqual(cfg.CloudStorageSnapshot(), before) || cfg.RuntimeRevision() != revision || cfg.Port != 5344 {
			t.Fatalf("rejected payload changed state: %s", payload)
		}
	}
}
