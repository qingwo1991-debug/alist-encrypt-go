package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
)

func TestMediaRecoveryCooldownClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		err    error
		want   time.Duration
	}{
		{"unknown", 0, nil, 5 * time.Minute},
		{"transport", 0, errors.New("network unavailable"), 15 * time.Second},
		{"unauthorized", http.StatusUnauthorized, errors.New("denied"), 0},
		{"forbidden", http.StatusForbidden, errors.New("denied"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newWebDAVSnapshotTestHandler(t)
			defer h.Stop()
			repo := &lifecycleAliasRepo{}
			inspector := lifecycleInspectorFunc(func(context.Context, string, http.Header, *config.PasswdInfo, int64) (proxy.MediaIdentityResult, error) {
				return proxy.MediaIdentityResult{UpstreamStatus: tc.status}, tc.err
			})
			raw := "/156联通云盘/encrypt/cooldown.bin"
			before := time.Now()
			awaitLifecycle(t, launchLifecycle(h, repo, inspector, raw))
			ep, _ := h.passwdDAO.FindByPath(raw)
			r := httptest.NewRequest("PROPFIND", "http://proxy/dav/", nil)
			key := filenameScopeDigest(h.cfg.GetAlistURL(), raw, filenameRequestScope(r), filenameRuleScope(ep), "132")
			h.mediaRecovery.mu.Lock()
			until, present := h.mediaRecovery.failures[key]
			h.mediaRecovery.mu.Unlock()
			if tc.want == 0 {
				if present {
					t.Fatal("auth refusal poisoned format cache")
				}
				return
			}
			if !present || until.Before(before.Add(tc.want)) || until.After(time.Now().Add(tc.want)) {
				t.Fatalf("unexpected cooldown: %v present=%v", until, present)
			}
		})
	}
}
