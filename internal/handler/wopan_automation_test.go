package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
)

func automationFixture(t *testing.T) *wopanFixture {
	t.Helper()
	f := newWopanFixture(t)
	// Every policy/journal file lives in a disposable project-test directory, not
	// the default app config location and never a real account's configuration.
	cfg := config.LoadFromBaseDir(t.TempDir())
	cfg.AlistServer = f.cfg.AlistServerSnapshot()
	cfg.JWTSecret = f.cfg.JWTSecret
	f.cfg = cfg
	f.h.cfg = cfg
	return f
}

func automationBody(enabled bool, ids []int) string {
	payload, _ := json.Marshal(map[string]interface{}{"enabled": enabled, "storage_ids": ids, "interval_hours": 24, "confirmation_phrase": wopanAutomationPhrase})
	return string(payload)
}
func enableAutomation(t *testing.T, f *wopanFixture, ids ...int) uint64 {
	t.Helper()
	rr := f.request(http.MethodPost, "/enc-api/wopan/automation", f.jwt, automationBody(true, ids), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", rr.Code, rr.Body.String())
	}
	return f.cfg.CloudStorageSnapshot().WopanAutomation.Version
}
func automationResults(f *wopanFixture) []wopanAutomationResult {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	return append([]wopanAutomationResult(nil), f.h.automation.results...)
}

func TestWopanAutomationDefaultStrictRequestsAndNoImmediateClear(t *testing.T) {
	f := automationFixture(t)
	rr := f.request(http.MethodGet, "/enc-api/wopan/automation", f.jwt, "", nil)
	data := wopanResponseData(t, rr)
	if string(data["enabled"]) != "false" || string(data["interval_hours"]) != "24" || string(data["storage_ids"]) != "[]" {
		t.Fatalf("defaults=%s", rr.Body.String())
	}
	bodies := []string{
		`{"enabled":true,"storage_ids":[27],"interval_hours":24,"confirmation_phrase":"wrong"}`,
		`{"enabled":true,"storage_ids":[27,27],"interval_hours":24,"confirmation_phrase":"` + wopanAutomationPhrase + `"}`,
		`{"enabled":true,"storage_ids":[],"interval_hours":24,"confirmation_phrase":"` + wopanAutomationPhrase + `"}`,
		`{"enabled":false,"storage_ids":[0],"interval_hours":24,"confirmation_phrase":""}`,
		`{"enabled":false,"storage_ids":[],"interval_hours":0,"confirmation_phrase":""}`,
		`{"enabled":false,"storage_ids":[],"interval_hours":721,"confirmation_phrase":""}`,
		`{"enabled":false,"storage_ids":[],"interval_hours":1.5,"confirmation_phrase":""}`,
		`{"enabled":false,"storage_ids":[],"interval_hours":24,"confirmation_phrase":"","extra":1}`,
		`{"enabled":false,"enabled":true,"storage_ids":[],"interval_hours":24,"confirmation_phrase":""}`,
		`{"enabled":false,"storage_ids":null,"interval_hours":24,"confirmation_phrase":""}`,
		`{"enabled":false,"storage_ids":[],"interval_hours":24}`,
	}
	for _, body := range bodies {
		rr = f.request(http.MethodPost, "/enc-api/wopan/automation", f.jwt, body, nil)
		if rr.Code < 400 {
			t.Fatalf("accepted malformed policy %s", body)
		}
	}
	if f.upstream.requestCount() != 0 {
		t.Fatal("invalid or GET policy contacted upstream")
	}
	f.h.runAutomationOnce(context.Background(), 0)
	if f.upstream.requestCount() != 0 {
		t.Fatal("disabled worker contacted upstream")
	}
	enableAutomation(t, f, 27)
	_, _, clears := f.provider.counts()
	if clears != 0 {
		t.Fatal("saving policy performed immediate clear")
	}
	rr = f.request(http.MethodGet, "/enc-api/wopan/automation", f.jwt, "", nil)
	for _, secret := range []string{wopanTestID, wopanTestAccess, wopanTestRefresh, wopanTestScan, "identity_hash", "account_hash", "username", "bindings"} {
		if strings.Contains(rr.Body.String(), secret) {
			t.Fatalf("policy leaked %s", secret)
		}
	}
}

func TestWopanAutomationDedupAndIndependentFailures(t *testing.T) {
	f := automationFixture(t)
	f.upstream.change(func() { f.upstream.storages[28] = wopanMockStorage(28); f.upstream.storages[29] = wopanMockStorage(29) })
	version := enableAutomation(t, f, 27, 28, 29)
	f.upstream.change(func() { v := f.upstream.storages[29]; v.Disabled = true; f.upstream.storages[29] = v })
	f.h.runAutomationOnce(context.Background(), version)
	_, _, clears := f.provider.counts()
	if clears != 1 {
		t.Fatalf("dedup clear calls=%d", clears)
	}
	results := automationResults(f)
	if len(results) != 3 || results[0].Status != "accepted" || results[1].Code != "account_deduplicated" || results[2].Code != "storage_unavailable" {
		t.Fatalf("results=%+v", results)
	}
	// The later observed disabled alias holds the entire shared account for
	// explicit confirmation, even though an earlier valid mount was accepted.
	for _, b := range f.cfg.CloudStorageSnapshot().WopanAutomation.Bindings {
		if !b.Quarantined {
			t.Fatal("disabled alias did not quarantine shared account")
		}
	}
}

func TestWopanAutomationUnknownIsDurablyQuarantined(t *testing.T) {
	f := automationFixture(t)
	f.upstream.change(func() { f.upstream.storages[28] = wopanMockStorage(28) })
	version := enableAutomation(t, f, 27, 28)
	f.provider.mu.Lock()
	f.provider.clearErr = errors.New("sensitive transport url token")
	f.provider.mu.Unlock()
	f.h.runAutomationOnce(context.Background(), version)
	f.h.runAutomationOnce(context.Background(), version)
	_, _, clears := f.provider.counts()
	if clears != 1 {
		t.Fatalf("unknown automatically retried %d", clears)
	}
	p := f.cfg.CloudStorageSnapshot().WopanAutomation
	if !p.Bindings[0].Quarantined || automationResults(f)[0].Code != "clear_outcome_unknown" {
		t.Fatal("unknown not quarantined")
	}
	for _, b := range p.Bindings {
		if !b.Quarantined {
			t.Fatal("account alias escaped quarantine")
		}
	}
	// Simulate restart from the actual persisted configuration, never management
	// JSON (which deliberately excludes this private automatic policy).
	base := t.TempDir()
	reloaded := config.LoadFromBaseDir(base)
	reloaded.AlistServer = f.cfg.AlistServerSnapshot()
	copyPolicy := p
	copyPolicy.Version = 1
	if err := reloaded.UpdateWopanAutomation(0, copyPolicy); err != nil {
		t.Fatal(err)
	}
	reloaded = config.LoadFromBaseDir(base)
	f.cfg, f.h.cfg = reloaded, reloaded
	f.h.runAutomationOnce(context.Background(), 1)
	_, _, clears = f.provider.counts()
	if clears != 1 {
		t.Fatal("restart retried quarantined account alias")
	}
	if len(reloaded.CloudStorageSnapshot().WopanAutomation.Bindings) != 2 {
		t.Fatal("restart lost account aliases")
	}
	f.provider.mu.Lock()
	f.provider.clearErr = nil
	f.provider.mu.Unlock()
	version = enableAutomation(t, f, 27)
	f.h.runAutomationOnce(context.Background(), version)
	_, _, clears = f.provider.counts()
	if clears != 2 {
		t.Fatal("explicit confirmation did not rearm")
	}
}

func TestWopanAutomationFailsClosedOnBindingAdminAndConfigChanges(t *testing.T) {
	for _, kind := range []string{"account", "token", "driver", "family", "mount", "root", "upstream-admin", "local-user", "config"} {
		t.Run(kind, func(t *testing.T) {
			f := automationFixture(t)
			version := enableAutomation(t, f, 27)
			switch kind {
			case "account":
				f.provider.mu.Lock()
				f.provider.accountID = "replacement-private-account"
				f.provider.mu.Unlock()
			case "upstream-admin":
				f.upstream.change(func() { f.upstream.role = 0 })
			case "local-user":
				if err := f.users.Delete("admin"); err != nil {
					t.Fatal(err)
				}
			case "config":
				s := f.cfg.AlistServerSnapshot()
				s.Describe = "changed"
				if err := f.cfg.UpdateAlistServer(s); err != nil {
					t.Fatal(err)
				}
			default:
				f.upstream.change(func() {
					v := f.upstream.storages[27]
					switch kind {
					case "token":
						v.Addition = wopanMockAddition("rotated-private-access-1234567890", "")
					case "driver":
						v.Driver = "Other"
					case "family":
						v.Addition = wopanMockAddition(wopanTestAccess, "family")
					case "mount":
						v.MountPath = "/replacement"
					case "root":
						v.Addition = strings.Replace(v.Addition, `"root_folder_id":"0"`, `"root_folder_id":"different"`, 1)
					}
					f.upstream.storages[27] = v
				})
			}
			f.h.runAutomationOnce(context.Background(), version)
			_, _, clears := f.provider.counts()
			if clears != 0 {
				t.Fatalf("%s changed but cleared", kind)
			}
		})
	}
}

func TestWopanAutomationDisableCancelsAndSharesManualInflight(t *testing.T) {
	f := automationFixture(t)
	version := enableAutomation(t, f, 27)
	key := sha256.Sum256([]byte(wopanTestID))
	f.h.mu.Lock()
	f.h.inflight[key] = true
	f.h.mu.Unlock()
	f.h.runAutomationOnce(context.Background(), version)
	if automationResults(f)[0].Code != "clear_in_progress" {
		t.Fatal("did not share manual inflight")
	}
	f.h.mu.Lock()
	delete(f.h.inflight, key)
	f.h.mu.Unlock()
	f.provider.clearStarted = make(chan struct{})
	f.provider.clearFinish = make(chan struct{})
	done := make(chan struct{})
	go func() { defer close(done); f.h.runAutomationOnce(context.Background(), version) }()
	select {
	case <-f.provider.clearStarted:
	case <-time.After(time.Second):
		t.Fatal("fake clear not entered")
	}
	rr := f.request(http.MethodPost, "/enc-api/wopan/automation", f.jwt, automationBody(true, []int{27}), nil)
	if rr.Code != http.StatusConflict {
		t.Fatal("rearmed running policy")
	}
	rr = f.request(http.MethodPost, "/enc-api/wopan/automation", f.jwt, automationBody(false, []int{}), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("disable=%s", rr.Body.String())
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("disable did not cancel network context")
	}
	f.h.runAutomationOnce(context.Background(), f.cfg.CloudStorageSnapshot().WopanAutomation.Version)
	_, _, clears := f.provider.counts()
	if clears != 1 {
		t.Fatalf("disabled attempted new clear %d", clears)
	}
}

func TestWopanAutomationSchedulerWaitsFullIntervalAndShutdown(t *testing.T) {
	f := automationFixture(t)
	enableAutomation(t, f, 27)
	type tick struct {
		duration time.Duration
		ch       chan time.Time
	}
	waits := make(chan tick, 10)
	f.h.automation.wait = func(d time.Duration) (<-chan time.Time, func()) {
		c := make(chan time.Time, 1)
		waits <- tick{d, c}
		return c, func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.h.StartAutomation(ctx)
	f.h.StartAutomation(ctx) // exactly one worker
	first := <-waits
	if first.duration != 24*time.Hour {
		t.Fatalf("initial delay=%s", first.duration)
	}
	_, _, clears := f.provider.counts()
	if clears != 0 {
		t.Fatal("startup cleared without first interval")
	}
	enableAutomation(t, f, 27)
	next := <-waits
	first.ch <- time.Now() // obsolete timer cannot trigger a newly saved policy
	_, _, clears = f.provider.counts()
	if clears != 0 {
		t.Fatal("save immediately cleared")
	}
	next.ch <- time.Now()
	<-waits // iteration completed and next full interval armed
	_, _, clears = f.provider.counts()
	if clears != 1 {
		t.Fatalf("timer iteration calls=%d", clears)
	}
	cancel()
	deadline, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.h.WaitAutomation(deadline); err != nil {
		t.Fatal(err)
	}
}

func TestWopanAutomationCheckpointFailureNeverSubmits(t *testing.T) {
	f := automationFixture(t)
	version := enableAutomation(t, f, 27)
	// Replace only the test config's conf directory with a regular file. The
	// atomic checkpoint must fail before any fake destructive provider call.
	base := t.TempDir()
	cfg := config.LoadFromBaseDir(base)
	cfg.AlistServer = f.cfg.AlistServerSnapshot()
	p := f.cfg.CloudStorageSnapshot().WopanAutomation
	p.Version = 1
	if err := cfg.UpdateWopanAutomation(0, p); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(base, "conf"), filepath.Join(base, "saved-conf")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "conf"), []byte("block test persistence"), 0600); err != nil {
		t.Fatal(err)
	}
	f.cfg, f.h.cfg = cfg, cfg
	f.h.runAutomationOnce(context.Background(), version)
	_, _, clears := f.provider.counts()
	if clears != 0 {
		t.Fatal("clear submitted without durable checkpoint")
	}
	if got := automationResults(f); len(got) != 1 || got[0].Code != "automation_checkpoint_failed" {
		t.Fatalf("results=%+v", got)
	}
}

func TestWopanAutomationMutationCSRFAndAuthentication(t *testing.T) {
	f := automationFixture(t)
	for _, headers := range []map[string]string{{"Origin": "https://attacker.invalid"}, {"Sec-Fetch-Site": "cross-site"}, {"Content-Type": "text/plain"}} {
		rr := f.request(http.MethodPost, "/enc-api/wopan/automation", f.jwt, automationBody(true, []int{27}), headers)
		if rr.Code < 400 {
			t.Fatal("unsafe mutation accepted")
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rr := f.request(method, "/enc-api/wopan/automation", "", automationBody(true, []int{27}), nil)
		if rr.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated policy access")
		}
	}
	if f.upstream.requestCount() != 0 {
		t.Fatal("rejected mutation contacted upstream")
	}
}
