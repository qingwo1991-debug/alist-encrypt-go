package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func malformedSnapshotPayloads() map[string]string {
	return map[string]string{
		"null_body": `null`, "missing_code": `{"data":{"content":[]}}`,
		"failed_code":     `{"code":500,"data":{"content":[]}}`,
		"string_code":     `{"code":"200","data":{"content":[]}}`,
		"empty_name":      `{"code":200,"data":{"content":[{"name":"","path":"/limited/encrypt/a","is_dir":false}]}}`,
		"mixed_bad_child": `{"code":200,"data":{"content":[{"name":"a","path":"/limited/encrypt/a","is_dir":true},null]}}`,
		"missing_data":    `{"code":200}`, "null_data": `{"code":200,"data":null}`,
		"array_data": `{"code":200,"data":[]}`, "scalar_data": `{"code":200,"data":1}`,
		"missing_content": `{"code":200,"data":{}}`, "null_content": `{"code":200,"data":{"content":null}}`,
		"object_content": `{"code":200,"data":{"content":{}}}`, "scalar_content": `{"code":200,"data":{"content":"unknown"}}`,
		"null_child":   `{"code":200,"data":{"content":[null]}}`,
		"scalar_child": `{"code":200,"data":{"content":[42]}}`,
		"missing_name": `{"code":200,"data":{"content":[{"path":"/limited/encrypt/a","is_dir":false}]}}`,
		"invalid_name": `{"code":200,"data":{"content":[{"name":4,"path":"/limited/encrypt/a","is_dir":false}]}}`,
		"missing_kind": `{"code":200,"data":{"content":[{"name":"a","path":"/limited/encrypt/a"}]}}`,
		"invalid_kind": `{"code":200,"data":{"content":[{"name":"a","path":"/limited/encrypt/a","is_dir":"false"}]}}`,
	}
}

func TestSnapshotShapeRejectsUnknownInsteadOfEmpty(t *testing.T) {
	for name, payload := range malformedSnapshotPayloads() {
		t.Run(name, func(t *testing.T) {
			snap := &DirListSnapshot{DisplayPath: "/limited/encrypt", SourceMode: dirSyncModeReq, PayloadJSON: []byte(payload)}
			if ok, reason := validateSnapshotForDir(snap.DisplayPath, snap); ok {
				t.Fatalf("malformed snapshot accepted as complete listing: %s; reason=%q", payload, reason)
			}
		})
	}
}

func TestSnapshotShapeAllowsExplicitEmptyAndFilteredTotal(t *testing.T) {
	for _, payload := range []string{
		`{"code":200,"data":{"content":[],"total":0}}`,
		`{"code":200,"data":{"content":[]}}`,
		`{"code":200,"data":{"content":[],"total":99}}`, // Filtered page, not a full-directory assertion.
		`{"code":200,"data":{"content":[{"name":"a","path":"/limited/encrypt/a","is_dir":false,"size":-1}],"total":99}}`,
	} {
		snap := &DirListSnapshot{DisplayPath: "/limited/encrypt", SourceMode: dirSyncModeReq, PayloadJSON: []byte(payload)}
		if ok, reason := validateSnapshotForDir(snap.DisplayPath, snap); !ok {
			t.Fatalf("valid explicit listing rejected: %s: %s", payload, reason)
		}
	}
}

func TestSnapshotShapeRejectsContradictoryCachedCount(t *testing.T) {
	snap := &DirListSnapshot{DisplayPath: "/limited/encrypt", ItemCount: 7, PayloadJSON: []byte(`{"code":200,"data":{"content":[],"total":0}}`)}
	if ok, _ := validateSnapshotForDir(snap.DisplayPath, snap); ok {
		t.Fatal("nonempty cached count was silently rendered as empty")
	}
}

func TestSnapshotShapeBuilderRejectsUnknown(t *testing.T) {
	h := &WebDAVHandler{}
	for name, payload := range malformedSnapshotPayloads() {
		t.Run(name, func(t *testing.T) {
			if body := h.buildSnapshotMultistatus("/limited/encrypt", []byte(payload)); len(body) != 0 {
				t.Fatalf("malformed payload became a successful self-only listing: %s", body)
			}
		})
	}
	body := h.buildSnapshotMultistatus("/limited/encrypt", []byte(`{"code":200,"data":{"content":[],"total":0}}`))
	if strings.Count(string(body), "<D:response>") != 1 {
		t.Fatalf("explicit empty directory must retain its self response: %s", body)
	}
}

func TestSnapshotShapeWritersDoNotPersistMalformed(t *testing.T) {
	h, store, _ := newWebDAVSnapshotTestHandler(t)
	ah := &AlistHandler{cfg: h.cfg, passwdDAO: h.passwdDAO, dirSyncStore: store}
	for _, writer := range []string{"http", "webdav"} {
		for name, payload := range malformedSnapshotPayloads() {
			t.Run(writer+"/"+name, func(t *testing.T) {
				key := writer + name
				if writer == "http" {
					ah.persistSnapshot(context.Background(), "/156联通云盘/encrypt", key, "anon", []byte(payload), 0, dirSyncModeReq, "")
				} else {
					h.upsertWebDAVSnapshot(context.Background(), "/156联通云盘/encrypt", key, []byte(payload), 0)
				}
				if _, exists, err := store.GetSnapshot(context.Background(), key); err != nil || exists {
					t.Fatalf("malformed snapshot persisted: exists=%v err=%v", exists, err)
				}
			})
		}
		// A known explicit empty array may be persisted. A positive cached
		// item count must not contradict it; upstream total remains independent.
		empty := []byte(`{"code":200,"data":{"content":[],"total":0}}`)
		for _, count := range []int{0, 4} {
			key := fmt.Sprintf("%s-empty-%d", writer, count)
			if writer == "http" {
				ah.persistSnapshot(context.Background(), "/156联通云盘/encrypt", key, "anon", empty, count, dirSyncModeReq, "")
			} else {
				h.upsertWebDAVSnapshot(context.Background(), "/156联通云盘/encrypt", key, empty, count)
			}
			if _, exists, err := store.GetSnapshot(context.Background(), key); err != nil || exists != (count == 0) {
				t.Fatalf("explicit empty persistence count=%d exists=%v err=%v", count, exists, err)
			}
		}
	}
}

func configureShapeUpstream(t *testing.T, cfg *config.Config, upstream string) {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg.AlistServer.ServerHost = u.Hostname()
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = false
}

func seedMalformedShape(t *testing.T, h *WebDAVHandler, store DirSyncStore, dir, payload string) {
	t.Helper()
	now := time.Now()
	s := DirListSnapshot{ScopeKey: buildDirScopeKey(dir, "anon"), ProviderHost: h.cfg.GetAlistURL(), DisplayPath: dir, SourceMode: dirSyncModeReq, PayloadJSON: []byte(payload), UpdatedAt: now, NextRefreshAt: now.Add(time.Minute)}
	if err := store.UpsertSnapshot(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotShapeBadCacheFallsBackAndWarmParity(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		t.Run(fmt.Sprintf("slash=%t", suffix != ""), func(t *testing.T) {
			for name, payload := range map[string]string{"missing": `{"code":200}`, "null": `{"code":200,"data":{"content":null}}`, "bad_child": `{"code":200,"data":{"content":[null]}}`} {
				t.Run(name, func(t *testing.T) {
					h, store, fileDAO := newWebDAVSnapshotTestHandler(t)
					dir := "/156联通云盘/encrypt"
					h.cfg.AlistServer.PasswdList[0].EncName = false
					// A known collection is eligible for the snapshot path with either spelling.
					if err := fileDAO.Set(&dao.FileInfo{Path: dir + "/", Name: "encrypt", IsDir: true}); err != nil {
						t.Fatal(err)
					}
					hits := 0
					upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						hits++
						if r.Method != "PROPFIND" || r.Header.Get("Depth") != "1" {
							t.Error("fallback lost PROPFIND semantics")
						}
						w.WriteHeader(http.StatusMultiStatus)
						io.WriteString(w, `<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/156联通云盘/encrypt/</D:href><D:propstat><D:prop><D:displayname>encrypt</D:displayname><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response><D:response><D:href>/dav/156联通云盘/encrypt/child/</D:href><D:propstat><D:prop><D:displayname>child</D:displayname><D:resourcetype><D:collection/></D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`)
					}))
					defer upstream.Close()
					configureShapeUpstream(t, h.cfg, upstream.URL)
					h.stdClient = upstream.Client()
					seedMalformedShape(t, h, store, dir, payload)
					otherSuffix := "/"
					if suffix == "/" {
						otherSuffix = ""
					}
					for i, requestSuffix := range []string{suffix, otherSuffix} {
						r := httptest.NewRequest("PROPFIND", "/dav"+dir+requestSuffix, nil)
						r.Header.Set("Depth", "1")
						w := httptest.NewRecorder()
						h.handlePropfind(w, r, dir+requestSuffix)
						if w.Code != http.StatusMultiStatus || !strings.Contains(w.Body.String(), ">child<") || strings.Count(w.Body.String(), "<D:response>") != 2 {
							t.Fatalf("pass %d must retain exactly self and child: status=%d body=%s", i, w.Code, w.Body.String())
						}
						cacheHit := w.Header().Get("X-Alist-Encrypt-Cache") == "dir-snapshot"
						if cacheHit != (i == 1) {
							t.Fatalf("pass %d cache hit=%v; want cold live then opposite-spelling warm snapshot", i, cacheHit)
						}
					}
					if hits != 1 {
						t.Fatalf("expected live fallback followed by warm hit, got %d upstream calls", hits)
					}
				})
			}
		})
	}
}

func TestSnapshotShapeHTTPBadCacheFallsBack(t *testing.T) {
	hits := 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		io.WriteString(w, `{"code":200,"data":{"content":[{"name":"child","is_dir":true,"path":"/156联通云盘/encrypt/child"}],"total":1}}`)
	}))
	defer upstream.Close()
	h, store, _ := newWebDAVSnapshotTestHandler(t)
	cfg := config.LoadFromBaseDir(t.TempDir())
	cfg.AlistServer = h.cfg.AlistServer
	cfg.AlistServer.PasswdList[0].EncName = false
	configureShapeUpstream(t, cfg, upstream.URL)
	local, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Close() })
	ah := &AlistHandler{cfg: cfg, fileDAO: dao.NewFileDAO(local), passwdDAO: dao.NewPasswdDAO(local, cfg), httpClient: upstream.Client()}
	ah.SetDirSyncStore(store)
	t.Cleanup(ah.Stop)
	configureShapeUpstream(t, h.cfg, upstream.URL)
	r := httptest.NewRequest(http.MethodPost, "/api/fs/list", strings.NewReader(`{"path":"/156联通云盘/encrypt","page":1,"per_page":100}`))
	authHash := authScopeHash(ah.requestAuthHeaders(r))
	now := time.Now()
	if err := store.UpsertSnapshot(context.Background(), DirListSnapshot{
		ScopeKey: buildDirScopeKey("/156联通云盘/encrypt", authHash), DisplayPath: "/156联通云盘/encrypt",
		ProviderHost: cfg.GetAlistURL(), AuthScopeHash: authHash, SourceMode: dirSyncModeReq,
		PayloadJSON: []byte(`{"code":200,"data":null}`), UpdatedAt: now, NextRefreshAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	ah.HandleFsList(w, r)
	var response struct {
		CacheHit bool `json:"cache_hit"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if hits != 1 || response.CacheHit || !strings.Contains(w.Body.String(), `"name":"child"`) {
		t.Fatalf("bad HTTP cache did not fall back: hits=%d body=%s", hits, w.Body.String())
	}
}
