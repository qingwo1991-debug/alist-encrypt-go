package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
)

// TestEnqueueProbeFromSnapshotWaringsVideos verifies the directory snapshot
// fast-path enqueues content-meta probes for its encrypted videos. Before this
// fix, snapshot-served directories never triggered probes, so the first click
// on every video paid for a cold ContentMeta probe (~300-900ms) while the bolt
// cache stayed at ContentVersion=0.
func TestEnqueueProbeFromSnapshotWaringsVideos(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.EnableBackgroundProbe = true
	cfg.AlistServer.PasswdList = []config.PasswdInfo{{
		Password: "testpass", EncType: "aesctr", Enable: true, EncName: true,
		EncPath: []string{"/vip/*"},
	}}

	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	fileDAO := dao.NewFileDAO(store, cfg)
	passwdDAO := dao.NewPasswdDAO(store, cfg)
	streamProxy := proxy.NewStreamProxy(cfg)
	proxyHandler := NewProxyHandler(cfg, streamProxy, fileDAO, passwdDAO, nil, nil)
	ps := NewProbeScheduler(cfg, fileDAO, nil, streamProxy, store)
	h := NewAlistHandler(cfg, streamProxy, fileDAO, passwdDAO, proxyHandler, nil, ps)

	payload := map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"content": []map[string]interface{}{
				{"name": "dir1", "is_dir": true, "size": float64(0)},
				{"name": "movie_001.mp4", "is_dir": false, "size": float64(200 * 1024 * 1024)},
				{"name": "notes.txt", "is_dir": false, "size": float64(100 * 1024 * 1024)},
			},
		},
	}
	raw, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/fs/list", nil)
	h.enqueueProbeFromSnapshot(req, "/vip", raw)

	// Wait briefly for the async worker to enqueue.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint64(&ps.enqueuedTotal) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := atomic.LoadUint64(&ps.enqueuedTotal); got == 0 {
		t.Fatalf("expected at least one probe enqueued from snapshot, got 0")
	}
}
