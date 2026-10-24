package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Security-review regression: all upstream/provider calls use httptest mocks.
// An API-observed credential ABA must invalidate prior automation consent.
func TestWopanAutomationReviewRuntimeCredentialABARequiresReconfirmation(t *testing.T) {
	f := automationFixture(t)
	version := enableAutomation(t, f, 27)
	original := f.cfg.AlistServerSnapshot()
	changed := original
	changed.ScanAuthHeader = "replacement-mock-admin-token-1234567890"
	if err := f.cfg.UpdateAlistServer(changed); err != nil {
		t.Fatal(err)
	}
	if err := f.cfg.UpdateAlistServer(original); err != nil {
		t.Fatal(err)
	}
	f.h.runAutomationOnce(context.Background(), version)
	_, _, clears := f.provider.counts()
	if clears != 0 {
		t.Fatalf("runtime credential ABA silently rearmed prior policy: mock clear calls=%d, results=%+v", clears, automationResults(f))
	}
}

func TestWopanAutomationReviewManualCompletionMustNotEraseObservedBindingHold(t *testing.T) {
	f := automationFixture(t)
	f.upstream.change(func() { f.upstream.storages[28] = wopanMockStorage(28) })
	version := enableAutomation(t, f, 28, 27)
	prepared := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, nil)
	if prepared.Code != http.StatusOK {
		t.Fatal(prepared.Body.String())
	}
	var token string
	if err := json.Unmarshal(wopanResponseData(t, prepared)["confirmation_token"], &token); err != nil {
		t.Fatal(err)
	}
	f.upstream.change(func() {
		changed := f.upstream.storages[28]
		changed.MountPath = "/replacement"
		f.upstream.storages[28] = changed
	})
	autoRead, releaseAuto := make(chan struct{}), make(chan struct{})
	var accounts atomic.Int32
	f.provider.mu.Lock()
	f.provider.accountHook = func() {
		if accounts.Add(1) == 1 {
			close(autoRead)
			<-releaseAuto
		}
	}
	f.provider.clearStarted, f.provider.clearFinish = make(chan struct{}), make(chan struct{})
	started, finish := f.provider.clearStarted, f.provider.clearFinish
	f.provider.mu.Unlock()
	autoDone := make(chan struct{})
	go func() { defer close(autoDone); f.h.runAutomationOnce(context.Background(), version) }()
	select {
	case <-autoRead:
	case <-time.After(time.Second):
		t.Fatal("automatic mock read not entered")
	}
	manualDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		body, _ := json.Marshal(map[string]interface{}{"storage_id": 27, "confirmation_token": token, "confirmation_phrase": wopanConfirmationPhrase})
		manualDone <- f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, string(body), nil)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(releaseAuto)
		t.Fatal("manual mock clear not entered")
	}
	close(releaseAuto)
	select {
	case <-autoDone:
	case <-time.After(time.Second):
		close(finish)
		t.Fatal("automatic validation did not finish")
	}
	// The automatic validation has now observed changed mount 28 and durably
	// quarantined the OLD account while the manual operation on alias 27 runs.
	close(finish)
	select {
	case response := <-manualDone:
		if response.Code != http.StatusOK {
			t.Fatal(response.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("manual mock clear did not finish")
	}
	for _, binding := range f.cfg.CloudStorageSnapshot().WopanAutomation.Bindings {
		if !binding.Quarantined {
			t.Fatalf("manual success erased independently observed binding hold for alias %d; results=%+v", binding.StorageID, automationResults(f))
		}
	}
}
