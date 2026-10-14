package handler

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

type recoveryInspectorMock struct {
	ports.Streamer
	calls   atomic.Int32
	result  proxy.MediaIdentityResult
	started chan struct{}
	gate    chan struct{}
	once    sync.Once
}

func (m *recoveryInspectorMock) InspectDecryptedMediaPrefix(ctx context.Context, target string, headers http.Header, ep *config.PasswdInfo, size int64) (proxy.MediaIdentityResult, error) {
	m.calls.Add(1)
	if headers.Get("Authorization") != "Basic test" {
		return proxy.MediaIdentityResult{}, fmt.Errorf("missing auth")
	}
	if m.started != nil {
		m.once.Do(func() { close(m.started) })
	}
	if m.gate != nil {
		select {
		case <-m.gate:
		case <-ctx.Done():
			return proxy.MediaIdentityResult{}, ctx.Err()
		}
	}
	return m.result, nil
}
func recoveryXML(raw string, size int64) []byte {
	return []byte(fmt.Sprintf(`<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav%s</D:href><D:propstat><D:prop><D:displayname>orig_%s</D:displayname><D:getcontentlength>%d</D:getcontentlength><D:getcontenttype>application/octet-stream</D:getcontenttype><D:resourcetype/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`, raw, strings.TrimPrefix(raw, "/156联通云盘/encrypt/"), size))
}
func TestMediaNameRecoveryPersistentScopedAliasAndSnapshot(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/156联通云盘": 100}
	meta := encryption.ContentMeta{EncType: encryption.EncTypeAESCTR, Version: encryption.ContentVersionV2, HeaderLen: 32, PlainSize: 100, CiphertextSize: 132, NonceField: bytes.Repeat([]byte{7}, 16)}
	mock := &recoveryInspectorMock{result: proxy.MediaIdentityResult{Meta: meta, Ext: ".mp4", MIME: "video/mp4", Reusable: true}}
	h.streamProxy = mock
	raw := "/156联通云盘/encrypt/" + strings.Repeat("x", 96) + ".bin"
	r := httptest.NewRequest("PROPFIND", "http://proxy/dav/156联通云盘/encrypt/", nil)
	r.Header.Set("Authorization", "Basic test")
	body := recoveryXML(raw, 132)
	recovered := h.recoverMediaNames(r, body, false)
	if !bytes.Contains(recovered, []byte(".mp4")) || !bytes.Contains(recovered, []byte("video/mp4")) || !bytes.Contains(recovered, []byte(">100<")) {
		t.Fatalf("recovery output=%s", recovered)
	}
	if mock.calls.Load() != 1 {
		t.Fatal("cold probe count", mock.calls.Load())
	}
	snapshot := recoveryXML("/156联通云盘/encrypt/orig_"+strings.Repeat("x", 96)+".bin", 100)
	if got := h.recoverMediaNames(r, snapshot, true); !bytes.Contains(got, []byte(".mp4")) {
		t.Fatalf("snapshot=%s", got)
	}
	if mock.calls.Load() != 1 {
		t.Fatal("hot snapshot probed")
	}
	alias := "/156联通云盘/encrypt/orig_" + strings.Repeat("x", 96) + ".mp4"
	// New DAO has no old path cache; persistent reverse lookup restores it.
	existing := h.fileDAO.(*dao.FileDAO)
	_ = existing
	repo := h.fileDAO.(mediaAliasRepository)
	ep, _ := h.passwdDAO.FindByPath(raw)
	rec, ok, err := repo.GetVerifiedMediaAliasByDisplay(h.cfg.GetAlistURL(), alias, filenameRequestScope(r), filenameRuleScope(ep), 0)
	if err != nil || !ok || rec.EncryptedPath != raw {
		t.Fatalf("reverse lookup ok=%v err=%v", ok, err)
	}
	if _, ok := h.restoreVerifiedAliasMapping(r, alias); !ok {
		t.Fatal("restore failed")
	}
	if got, _ := h.resolveRealPathForRequest(r, alias, ep); got != raw {
		t.Fatalf("request alias mapped %q", got)
	}
	if _, ok := h.fileDAO.GetEncPath(alias); ok {
		t.Fatal("scoped alias leaked into global path cache")
	}
	other := r.Clone(context.Background())
	other.Header = r.Header.Clone()
	other.Header.Set("Authorization", "Basic other")
	if _, ok := h.restoreVerifiedAliasMapping(other, alias); ok {
		t.Fatal("cross auth alias reused")
	}
	blocked := httptest.NewRequest(http.MethodGet, "http://proxy/dav"+alias, nil)
	blocked.Header.Set("Authorization", "Basic other")
	denied := httptest.NewRecorder()
	h.Handle(denied, blocked)
	if denied.Code != http.StatusNotFound {
		t.Fatalf("stale cross-auth global mapping status=%d", denied.Code)
	}
	mock.result.Reusable = false
	if out := h.recoverMediaNames(other, body, false); bytes.Contains(out, []byte(".mp4")) {
		t.Fatal("cross auth listing reused")
	}
}

func TestMediaNameRecoverySingleflightCancellation(t *testing.T) {
	h, _, _ := newWebDAVSnapshotTestHandler(t)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/156联通云盘": 100}
	mock := &recoveryInspectorMock{started: make(chan struct{}), gate: make(chan struct{}), result: proxy.MediaIdentityResult{Meta: encryption.ContentMeta{EncType: encryption.EncTypeAESCTR, Version: 2, HeaderLen: 32, PlainSize: 100, CiphertextSize: 132, NonceField: bytes.Repeat([]byte{1}, 16)}, Ext: ".mp4", MIME: "video/mp4", Reusable: true}}
	h.streamProxy = mock
	r := httptest.NewRequest("PROPFIND", "http://proxy/dav/156联通云盘/encrypt/", nil)
	r.Header.Set("Authorization", "Basic test")
	raw := "/156联通云盘/encrypt/" + strings.Repeat("z", 96) + ".bin"
	ep, _ := h.passwdDAO.FindByPath(raw)
	repo := h.fileDAO.(mediaAliasRepository)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan bool, 1)
	go func() {
		_, ok := h.resolveMediaRecovery(ctx, r, repo, mock, ep, raw, filenameRequestScope(r), filenameRuleScope(ep), 132)
		first <- ok
	}()
	<-mock.started
	cancel()
	if <-first {
		t.Fatal("canceled waiter succeeded")
	}
	result := make(chan bool, 1)
	go func() {
		_, ok := h.resolveMediaRecovery(context.Background(), r, repo, mock, ep, raw, filenameRequestScope(r), filenameRuleScope(ep), 132)
		result <- ok
	}()
	close(mock.gate)
	if !<-result {
		t.Fatal("owned worker canceled")
	}
	if mock.calls.Load() != 1 {
		t.Fatal("parallel calls", mock.calls.Load())
	}
}

func TestMediaAliasResponseDoesNotDisguiseAuthorizationError(t *testing.T) {
	for _, status := range []int{200, 206, 401, 403, 502} {
		rr := httptest.NewRecorder()
		w := &mediaAliasResponseWriter{ResponseWriter: rr, mime: "video/mp4", display: "/enc/orig_x.mp4"}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		if (status >= 200 && status < 300) != (rr.Header().Get("Content-Type") == "video/mp4") {
			t.Fatalf("status %d type %s", status, rr.Header().Get("Content-Type"))
		}
	}
}
