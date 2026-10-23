package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func newPropfindSizeScheduler(t *testing.T, origin string, capacity int) (*ProbeScheduler, FileItem) {
	t.Helper()
	h, files, rule := newCanonicalPropfindFixture(t)
	parsed, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	alist := h.cfg.AlistServerSnapshot()
	alist.ServerHost, alist.HTTPS = parsed.Hostname(), false
	alist.ServerPort, _ = strconv.Atoi(parsed.Port())
	alist.EnableBackgroundProbe, alist.ScanVideoOnly = true, true
	alist.ProbeMinSizeBytes = 100 << 20
	alist.PasswdList = []config.PasswdInfo{*rule}
	if err := h.cfg.UpdateAlistServer(alist); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ps := &ProbeScheduler{cfg: h.cfg, fileDAO: files, stream: proxy.NewStreamProxy(h.cfg), enabled: true, ctx: ctx, cancel: cancel, queue: make(chan probeItem, capacity), providerLimit: 2, providerSem: make(map[string]chan struct{}), cooldown: 24 * time.Hour}
	ps.SetForegroundTracker(NewForegroundTracker(func() bool { return true }))
	t.Cleanup(ps.Stop)
	return ps, FileItem{DisplayPath: "/encrypt/subtitle.srt", EncryptedPath: "/encrypt/raw.bin", FileName: "subtitle.srt", TargetURL: origin + "/dav/encrypt/raw.bin", PasswdInfo: rule}
}

func TestPropfindSizeOnlyBoundedHeaderAndNoPlaybackWarmup(t *testing.T) {
	for _, version := range []int{encryption.ContentVersionV1, encryption.ContentVersionV2, encryption.ContentVersionV3} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			var body []byte
			switch version {
			case encryption.ContentVersionV1:
				body = bytes.Repeat([]byte{0x77}, 4096)
			case encryption.ContentVersionV2:
				header, err := encryption.BuildV2Header(encryption.EncTypeAESCTR, 4096, bytes.Repeat([]byte{7}, 16))
				if err != nil {
					t.Fatal(err)
				}
				body = append(header, make([]byte, 4096)...)
			case encryption.ContentVersionV3:
				header, err := encryption.NewV3Header(4096, bytes.Repeat([]byte{7}, 16), 73, 1234)
				if err != nil {
					t.Fatal(err)
				}
				body = append(header, make([]byte, int(encryption.V3CiphertextSize(4096, 73))-len(header))...)
			}
			var api, media atomic.Int32
			var origin string
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Basic caller" {
					t.Errorf("request credential not preserved")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				switch r.URL.Path {
				case "/api/fs/get":
					api.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": origin + "/media", "size": len(body)}})
				case "/media":
					media.Add(1)
					if r.Method != http.MethodGet || (r.Header.Get("Range") != "bytes=0-31" && r.Header.Get("Range") != "bytes=32-47") {
						t.Errorf("unexpected non-header request %s Range=%q", r.Method, r.Header.Get("Range"))
					}
					http.ServeContent(w, r, "container.bin", time.Time{}, bytes.NewReader(body))
				default:
					t.Errorf("unexpected resolver/login/range warmup path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer upstream.Close()
			origin = upstream.URL
			ps, file := newPropfindSizeScheduler(t, origin, 4)
			headers := http.Header{"Authorization": []string{"Basic caller"}}
			ps.EnqueueWithSource(file, headers, int64(len(body)), probeSourcePropfind)
			if len(ps.queue) != 1 {
				t.Fatal("small subtitle excluded by legacy video/size/foreground filters")
			}
			headers.Set("Authorization", "Basic mutated")
			file.PasswdInfo.Password = "mutated-after-admission"
			item := <-ps.queue
			if item.authHeaders.Get("Authorization") != "Basic caller" || item.file.PasswdInfo.Password == file.PasswdInfo.Password {
				t.Fatal("admission retained mutable request state")
			}
			ps.runItem(item)
			info, hit := ps.fileDAO.GetConfirmedPlayback(item.sizeOnly.identity)
			if !hit || info.Size != 4096 || info.ContentVersion != version || info.CiphertextSize != int64(len(body)) {
				t.Fatalf("confirmed metadata=%+v hit=%v", info, hit)
			}
			wantMedia := int32(1)
			if version == encryption.ContentVersionV3 {
				wantMedia = 2
			}
			if api.Load() != 1 || media.Load() != wantMedia || atomic.LoadUint64(&ps.filesRangeProbed) != 0 {
				t.Fatalf("api=%d header=%d rangeWarmup=%d", api.Load(), media.Load(), ps.filesRangeProbed)
			}
			file.PasswdInfo = item.file.PasswdInfo
			ps.EnqueueWithSource(file, item.authHeaders, int64(len(body)), probeSourcePropfind)
			if len(ps.queue) != 0 {
				t.Fatal("already-confirmed metadata queued again")
			}
		})
	}
}

func TestPropfindSizeOnlyAdmissionBoundedAndCredentialScoped(t *testing.T) {
	ps, file := newPropfindSizeScheduler(t, "http://127.0.0.1:5244", 2)
	ps.EnqueueWithSource(file, nil, 4096, probeSourcePropfind)
	ps.EnqueueWithSource(file, http.Header{"Authorization": []string{"Basic caller"}}, -1, probeSourcePropfind)
	if len(ps.queue) != 0 {
		t.Fatal("missing auth/ciphertext observation admitted")
	}
	auth := http.Header{"Authorization": []string{"Basic caller"}}
	ps.EnqueueWithSource(file, auth, 4096, probeSourcePropfind)
	ps.EnqueueWithSource(file, auth, 4096, probeSourcePropfind)
	other := file
	other.DisplayPath, other.EncryptedPath = "/encrypt/other.srt", "/encrypt/other.bin"
	ps.EnqueueWithSource(other, auth, 4096, probeSourcePropfind)
	third := file
	third.DisplayPath, third.EncryptedPath = "/encrypt/third.srt", "/encrypt/third.bin"
	ps.EnqueueWithSource(third, auth, 4096, probeSourcePropfind)
	if len(ps.queue) != 2 || atomic.LoadUint64(&ps.droppedTotal) != 1 {
		t.Fatalf("queue=%d dropped=%d", len(ps.queue), ps.droppedTotal)
	}
	ps.Stop()
	if len(ps.queue) != 0 || len(ps.pending) != 0 {
		t.Fatal("shutdown retained queued credentials/reservations")
	}
}

func TestPropfindSizeOnlyConfigAndEpochFenceBeforeNetwork(t *testing.T) {
	for _, fence := range []string{"config", "epoch"} {
		t.Run(fence, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(500) }))
			defer upstream.Close()
			ps, file := newPropfindSizeScheduler(t, upstream.URL, 2)
			ps.EnqueueWithSource(file, http.Header{"Authorization": []string{"Basic caller"}}, 4096, probeSourcePropfind)
			item := <-ps.queue
			if fence == "config" {
				alist := ps.cfg.AlistServerSnapshot()
				alist.PasswdList[0].Password = "changed"
				if err := ps.cfg.UpdateAlistServer(alist); err != nil {
					t.Fatal(err)
				}
			} else {
				ps.fileDAO.InvalidateDisplayPath(file.DisplayPath)
			}
			ps.runItem(item)
			if hits.Load() != 0 {
				t.Fatal("invalidated admission performed network work")
			}
			if _, hit := ps.fileDAO.GetConfirmedPlayback(item.sizeOnly.identity); hit {
				t.Fatal("invalidated admission published proof")
			}
		})
	}
}

func TestPropfindSizeOnlyStopCancelsActualHeaderRead(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	var origin string
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fs/get" {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]interface{}{"raw_url": origin + "/media", "size": 4096}})
			return
		}
		close(entered)
		<-r.Context().Done()
		close(exited)
	}))
	defer upstream.Close()
	origin = upstream.URL
	ps, file := newPropfindSizeScheduler(t, origin, 2)
	ps.EnqueueWithSource(file, http.Header{"Authorization": []string{"Basic caller"}}, 4096, probeSourcePropfind)
	ps.workerWG.Add(1)
	go func() { defer ps.workerWG.Done(); ps.worker() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("header read did not start")
	}
	ps.Stop()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("actual header transport outlived scheduler stop")
	}
	identity := playbackIdentity(ps.cfg, ps.cfg.GetAlistURL(), file.EncryptedPath, file.PasswdInfo, nil)
	if _, hit := ps.fileDAO.GetConfirmedPlayback(identity); hit {
		t.Fatal("canceled work published")
	}
}
