package handler

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

type lifecycleAliasRepo struct {
	mu               sync.Mutex
	puts, afterClose int
	closed           bool
}

func (r *lifecycleAliasRepo) PutVerifiedMediaAlias(storage.VerifiedMediaAlias) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.puts++
	if r.closed {
		r.afterClose++
	}
	return nil
}
func (*lifecycleAliasRepo) GetVerifiedMediaAlias(string, string, string, string, int64) (storage.VerifiedMediaAlias, bool, error) {
	return storage.VerifiedMediaAlias{}, false, nil
}
func (*lifecycleAliasRepo) GetVerifiedMediaAliasByDisplay(string, string, string, string, int64) (storage.VerifiedMediaAlias, bool, error) {
	return storage.VerifiedMediaAlias{}, false, nil
}

type lifecycleInspectorFunc func(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error)

func (f lifecycleInspectorFunc) InspectDecryptedMediaPrefix(c context.Context, u string, h http.Header, p *config.PasswdInfo, s int64) (proxy.MediaIdentityResult, error) {
	return f(c, u, h, p, s)
}
func lifecycleResult() proxy.MediaIdentityResult {
	return proxy.MediaIdentityResult{Reusable: true, MIME: "video/mp4", Ext: ".mp4"}
}
func awaitLifecycle(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle event timed out")
	}
}
func launchLifecycle(h *WebDAVHandler, repo mediaAliasRepository, inspector mediaPrefixInspector, raw string) <-chan struct{} {
	done := make(chan struct{})
	r := httptest.NewRequest("PROPFIND", "http://proxy/dav/156联通云盘/encrypt/", nil)
	ep, _ := h.passwdDAO.FindByPath(raw)
	go func() {
		defer close(done)
		h.resolveMediaRecovery(context.Background(), r, repo, inspector, ep, raw, filenameRequestScope(r), filenameRuleScope(ep), 132)
	}()
	return done
}
func assertLifecycleDrained(t *testing.T, h *WebDAVHandler, repo *lifecycleAliasRepo) {
	t.Helper()
	h.mediaRecovery.mu.Lock()
	defer h.mediaRecovery.mu.Unlock()
	if len(h.mediaRecovery.flights) != 0 || len(h.mediaRecovery.sem) != 0 {
		t.Fatal("owned work not drained")
	}
	if len(h.mediaRecovery.failures) != 0 {
		t.Fatal("shutdown/stale configuration poisoned negative cache")
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.puts != 0 || repo.afterClose != 0 {
		t.Fatalf("unexpected publications: %d, after close: %d", repo.puts, repo.afterClose)
	}
}

func TestMediaRecoveryStopTransportAndQueued(t *testing.T) {
	for _, phase := range []string{"headers", "body"} {
		t.Run(phase, func(t *testing.T) {
			h, _, _ := newWebDAVSnapshotTestHandler(t)
			repo := &lifecycleAliasRepo{}
			started := make(chan struct{}, 3)
			exited := make(chan struct{}, 3)
			var inspectorCalls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "body" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				started <- struct{}{}
				<-r.Context().Done()
				exited <- struct{}{}
			}))
			defer upstream.Close()
			defer h.Stop()
			inspector := lifecycleInspectorFunc(func(ctx context.Context, _ string, _ http.Header, _ *config.PasswdInfo, _ int64) (proxy.MediaIdentityResult, error) {
				inspectorCalls.Add(1)
				req, _ := http.NewRequestWithContext(ctx, "GET", upstream.URL, nil)
				resp, err := upstream.Client().Do(req)
				if err != nil {
					return proxy.MediaIdentityResult{}, err
				}
				defer resp.Body.Close()
				_, err = io.ReadAll(resp.Body)
				return lifecycleResult(), err
			})
			first := launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/first.bin")
			awaitLifecycle(t, started)
			// P6 admits one running operation and two pending flights. The first
			// transport cannot finish until Stop cancels its context, so neither
			// pending flight can enter the inspector before the admission fence.
			second := launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/second.bin")
			queued := launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/queued.bin")
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				h.mediaRecovery.mu.Lock()
				n := len(h.mediaRecovery.flights)
				h.mediaRecovery.mu.Unlock()
				if n == 3 {
					break
				}
				select {
				case <-ticker.C:
				case <-deadline.C:
					t.Fatal("queued flight not admitted")
				}
			}
			h.mediaRecovery.mu.Lock()
			running, capacity := len(h.mediaRecovery.sem), cap(h.mediaRecovery.sem)
			h.mediaRecovery.mu.Unlock()
			if running != 1 || capacity != 1 || inspectorCalls.Load() != 1 {
				t.Fatalf("expected one running + two pending: running=%d capacity=%d calls=%d", running, capacity, inspectorCalls.Load())
			}
			// A fourth distinct flight must be refused without starting I/O.
			awaitLifecycle(t, launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/over-budget.bin"))
			if inspectorCalls.Load() != 1 {
				t.Fatal("over-budget flight entered inspector")
			}
			stopped := make(chan struct{})
			go func() { h.Stop(); close(stopped) }()
			awaitLifecycle(t, stopped)
			awaitLifecycle(t, first)
			awaitLifecycle(t, second)
			awaitLifecycle(t, queued)
			awaitLifecycle(t, exited)
			if inspectorCalls.Load() != 1 {
				t.Fatal("pending flight started I/O during Stop")
			}
			select {
			case <-started:
				t.Fatal("queued transport unexpectedly started")
			default:
			}
			repo.mu.Lock()
			repo.closed = true
			repo.mu.Unlock()
			h.Stop()
			awaitLifecycle(t, launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/after.bin"))
			assertLifecycleDrained(t, h, repo)
		})
	}
}

func TestMediaRecoveryStopJoinsCancellationIgnoringInspector(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	repo := &lifecycleAliasRepo{}
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	inspector := lifecycleInspectorFunc(func(ctx context.Context, _ string, _ http.Header, _ *config.PasswdInfo, _ int64) (proxy.MediaIdentityResult, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return lifecycleResult(), nil
	})
	done := launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/ignore.bin")
	awaitLifecycle(t, started)
	stopped := make(chan struct{})
	go func() { h.Stop(); close(stopped) }()
	awaitLifecycle(t, canceled)
	select {
	case <-stopped:
		t.Fatal("Stop did not join actual worker")
	default:
	}
	close(release)
	awaitLifecycle(t, stopped)
	awaitLifecycle(t, done)
	repo.mu.Lock()
	repo.closed = true
	repo.mu.Unlock()
	h.Stop()
	assertLifecycleDrained(t, h, repo)
}

func TestMediaRecoveryStopBeforeAdmissionAndConcurrentRepeat(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.Stop() }()
	}
	wg.Wait()
	repo := &lifecycleAliasRepo{}
	inspector := lifecycleInspectorFunc(func(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error) {
		t.Error("post Stop inspector called")
		return lifecycleResult(), nil
	})
	awaitLifecycle(t, launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/new.bin"))
	assertLifecycleDrained(t, h, repo)
	constructed := NewWebDAVHandler(h.cfg, nil, h.fileDAO, h.passwdDAO, nil, nil, nil)
	constructed.Stop()
	constructed.Stop()
	assertLifecycleDrained(t, constructed, repo)
	var nilHandler *WebDAVHandler
	nilHandler.Stop()
}

func TestMediaRecoveryPreservesBoundedNegativeCooldown(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	defer h.Stop()
	h.mediaRecovery.initLocked()
	for i := 0; i < 2048; i++ {
		h.mediaRecovery.failures[fmt.Sprint(i)] = time.Now().Add(5 * time.Minute)
	}
	repo := &lifecycleAliasRepo{}
	inspector := lifecycleInspectorFunc(func(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error) {
		return proxy.MediaIdentityResult{}, nil // Existing unknown-format contract.
	})
	raw := "/156联通云盘/encrypt/unknown.bin"
	awaitLifecycle(t, launchLifecycle(h, repo, inspector, raw))
	ep, _ := h.passwdDAO.FindByPath(raw)
	r := httptest.NewRequest("PROPFIND", "http://proxy/dav/", nil)
	if !h.mediaRecoveryCoolingDown(raw, filenameRequestScope(r), filenameRuleScope(ep), 132) {
		t.Fatal("unknown format lost cooldown")
	}
	h.mediaRecovery.mu.Lock()
	defer h.mediaRecovery.mu.Unlock()
	if len(h.mediaRecovery.failures) != 1 {
		t.Fatalf("negative cache is not bounded: %d", len(h.mediaRecovery.failures))
	}
}

func TestMediaRecoveryRejectsOldRuleBeforeAdmission(t *testing.T) {
	t.Setenv("ALIST_ENCRYPT_BASE_DIR", t.TempDir())
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	defer h.Stop()
	raw := "/156联通云盘/encrypt/stale.bin"
	old, _ := h.passwdDAO.FindByPath(raw)
	rule := filenameRuleScope(old)
	changed := h.cfg.AlistServerSnapshot()
	changed.PasswdList[0].Password = "new-rule-secret"
	if err := h.cfg.UpdateAlistServer(changed); err != nil {
		t.Fatal(err)
	}
	repo := &lifecycleAliasRepo{}
	inspector := lifecycleInspectorFunc(func(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error) {
		t.Error("stale pre-admission rule reached inspector")
		return lifecycleResult(), nil
	})
	r := httptest.NewRequest("PROPFIND", "http://proxy/dav/", nil)
	_, ok := h.resolveMediaRecovery(context.Background(), r, repo, inspector, old, raw, filenameRequestScope(r), rule, 132)
	if ok {
		t.Fatal("stale pre-admission rule published")
	}
	h.Stop()
	assertLifecycleDrained(t, h, repo)
}

func TestMediaRecoveryRejectsReconfiguredFlight(t *testing.T) {
	for _, change := range []string{"origin", "rule", "mount", "aba"} {
		t.Run(change, func(t *testing.T) {
			t.Setenv("ALIST_ENCRYPT_BASE_DIR", t.TempDir())
			h, _, _ := newWebDAVSnapshotTestHandler(t)
			h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/156联通云盘": 100}
			repo := &lifecycleAliasRepo{}
			started, release := make(chan struct{}), make(chan struct{})
			inspector := lifecycleInspectorFunc(func(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error) {
				close(started)
				<-release
				return lifecycleResult(), nil
			})
			done := launchLifecycle(h, repo, inspector, "/156联通云盘/encrypt/old.bin")
			awaitLifecycle(t, started)
			original := h.cfg.AlistServerSnapshot()
			changed := h.cfg.AlistServerSnapshot()
			switch change {
			case "origin", "aba":
				changed.ServerPort++
			case "rule":
				changed.PasswdList[0].Password = "changed-secret"
			case "mount":
				changed.FilenameWriteLimits = nil
			}
			if err := h.cfg.UpdateAlistServer(changed); err != nil {
				t.Fatal(fmt.Errorf("reconfigure: %w", err))
			}
			if change == "aba" {
				if err := h.cfg.UpdateAlistServer(original); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			awaitLifecycle(t, done)
			h.Stop()
			assertLifecycleDrained(t, h, repo)
		})
	}
}
