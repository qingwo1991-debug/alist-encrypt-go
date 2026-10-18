package handler

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

func TestProtectedFilenamePutBoundedReservedAndVerified(t *testing.T) {
	var raw string
	var stored []byte
	puts := 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fs/list" {
			if r.Header.Get("Authorization") != "Bearer unit" {
				t.Errorf("API verification lost caller authorization")
			}
			w.Header().Set("Content-Type", "application/json")
			if len(stored) == 0 {
				_, _ = io.WriteString(w, `{"code":200,"data":{"total":0,"content":null}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"code":200,"data":{"total":1,"content":[{"name":%q,"size":%d,"is_dir":false}]}}`, pathBase(raw), len(stored))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/dav") {
			t.Errorf("API credentials incorrectly used on DAV")
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/api/fs/put" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(500)
			return
		}
		puts++
		raw, _ = url.QueryUnescape(r.Header.Get("File-Path"))
		stored, _ = io.ReadAll(r.Body)
		if r.Header.Get("As-Task") != "false" {
			t.Errorf("as-task=%q", r.Header.Get("As-Task"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":null}`)
	}))
	defer upstream.Close()
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
	h, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(h.Stop)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	name := strings.Repeat("长视频名称", 30) + ".mp4"
	original := "/limited/" + name
	upload := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/api/fs/put", strings.NewReader("plain"))
		r.Header.Set("File-Path", url.QueryEscape(original))
		r.Header.Set("Authorization", "Bearer unit")
		r.Header.Set("Content-Length", "5")
		rr := httptest.NewRecorder()
		h.HandleFsPut(rr, r)
		return rr
	}
	rr := upload()
	if rr.Code != 200 {
		t.Fatalf("first status=%d body=%s", rr.Code, rr.Body.String())
	}
	if len(pathBase(raw)) > 100 {
		t.Errorf("filename length=%d", len(pathBase(raw)))
	}
	if !strings.HasSuffix(encryption.ConvertShowNameWithSuffixOptions(ep.Password, ep.EncType, pathBase(raw), ep.EncSuffix, false), ".mp4") {
		t.Errorf("short name lost original extension")
	}
	rec, ok, err := d.GetFilenameReservation(h.cfg.GetAlistURL(), raw)
	if err != nil || !ok || rec.Status != storage.FilenameComplete || rec.OriginalPath != original {
		t.Fatalf("reservation=%+v ok=%v err=%v", rec, ok, err)
	}
	rr = upload()
	if rr.Code != 409 || puts != 1 {
		t.Fatalf("repeat status=%d puts=%d", rr.Code, puts)
	}
}
func pathBase(s string) string { i := strings.LastIndex(s, "/"); return s[i+1:] }

func TestProtectedFilenameMissingStoreAndAmbiguousHeadFailClosed(t *testing.T) {
	cfg := config.Get()
	old := cfg.AlistServer
	t.Cleanup(func() { cfg.AlistServer = old })
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", EncPath: []string{"/limited/*"}}
	r := httptest.NewRequest(http.MethodPut, "http://proxy/upload", nil)
	if _, _, err := prepareFilenameWrite(cfg, dao.NewFileDAO(nil), r, ep, "/limited/movie.mp4", "/raw", 5, false, nil); err == nil {
		t.Fatal("missing store allowed write")
	}
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	cfg.AlistServer.ServerHost = u.Hostname()
	cfg.AlistServer.ServerPort, _ = strconv.Atoi(u.Port())
	cfg.AlistServer.HTTPS = false
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	d := dao.NewFileDAO(store)
	defer d.Stop()
	if _, _, err := prepareFilenameWrite(cfg, d, r, ep, "/limited/movie.mp4", "/raw", 5, false, upstream.Client()); err == nil {
		t.Fatal("403 treated as absent")
	}
	if _, _, err := prepareFilenameWrite(cfg, d, r, ep, "/limited/movie.mp4", "/raw", 5, false, upstream.Client()); err == nil {
		t.Fatal("uninspectable destination unexpectedly allowed")
	}
	if _, _, err := prepareFilenameWrite(cfg, d, r, ep, "/limited/other.mp4", "/raw", 5, true, upstream.Client()); err == nil {
		t.Fatal("resumed protected upload allowed")
	}
}

func TestProtectedFilenamePropfindVerifiesExactResource(t *testing.T) {
	for _, tc := range []struct {
		name, href string
		status     int
		want       bool
	}{{"matching", "/dav/limited/cipher%252f.bin", 207, true}, {"wrong-path", "/dav/limited/other.bin", 207, false}, {"foreign-origin", "https://foreign.example/dav/limited/cipher%252f.bin", 207, false}, {"revoked", "/dav/limited/cipher%252f.bin", 403, false}, {"stale", "/dav/limited/cipher%252f.bin", 404, false}} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PROPFIND" || r.Header.Get("Depth") != "0" {
					t.Errorf("unexpected verification request")
				}
				if r.Header.Get("Authorization") != "Bearer test" {
					t.Errorf("lost authorization")
				}
				w.WriteHeader(tc.status)
				var href strings.Builder
				_ = xml.EscapeText(&href, []byte(tc.href))
				_, _ = fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href><d:propstat><d:prop><d:getcontentlength>37</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, href.String())
			}))
			defer upstream.Close()
			r := httptest.NewRequest(http.MethodPut, "http://proxy/upload", nil)
			r.Header.Set("Authorization", "Bearer test")
			n, err := filenameRemotePropfind(r, upstream.URL, "/limited/cipher%2f.bin", upstream.Client())
			if (err == nil) != tc.want || (tc.want && n != 37) {
				t.Errorf("size=%d err=%v", n, err)
			}
		})
	}
}

func TestProtectedFilenameAPIListingRequiresFreshCompleteEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		wantStatus int
	}{
		{"absent", `{"code":200,"data":{"total":0,"content":[]}}`, 200, 404},
		{"empty-null", `{"code":200,"data":{"total":0,"content":null}}`, 200, 404},
		{"nonempty-null", `{"code":200,"data":{"total":1,"content":null}}`, 200, 0},
		{"invalid-content-type", `{"code":200,"data":{"total":0,"content":{}}}`, 200, 0},
		{"present", `{"code":200,"data":{"total":1,"content":[{"name":"cipher.bin","size":37}]}}`, 200, 200},
		{"app-error", `{"code":500,"data":null}`, 200, 0},
		{"partial", `{"code":200,"data":{"total":2,"content":[{"name":"other.bin","size":37}]}}`, 200, 0},
		{"missing-content", `{"code":200,"data":{"total":0}}`, 200, 0},
		{"missing-total", `{"code":200,"data":{"content":[]}}`, 200, 0},
		{"revoked", `{"code":401}`, 401, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/fs/list" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer user" {
					t.Errorf("wrong API verification %s %s", r.Method, r.URL.Path)
				}
				data, _ := io.ReadAll(r.Body)
				if !strings.Contains(string(data), `"refresh":true`) || !strings.Contains(string(data), `"per_page":0`) {
					t.Errorf("not fresh complete request: %s", data)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer upstream.Close()
			r := httptest.NewRequest(http.MethodPut, "http://proxy/api/fs/put", nil)
			r.Header.Set("Authorization", "Bearer user")
			status, size, err := filenameRemoteHead(r, upstream.URL, "/limited/cipher.bin", upstream.Client())
			if tc.wantStatus == 0 {
				if err == nil {
					t.Errorf("unsafe listing accepted status=%d size=%d", status, size)
				}
			} else if err != nil || status != tc.wantStatus || (status == 200 && size != 37) {
				t.Errorf("status=%d size=%d err=%v", status, size, err)
			}
		})
	}
}

// A failed preflight has not admitted a write and must not create audit state
// that later blocks an unrelated pre-existing legacy object.
func TestProtectedFilenamePreflightRejectDoesNotReserve(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusInternalServerError} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			requests := 0
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.WriteHeader(status)
			}))
			defer upstream.Close()
			ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
			h, d := newTestAlistHandler(t, upstream.URL, ep)
			t.Cleanup(h.Stop)
			h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
			display := "/limited/legacy.mp4"
			encoded, _, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, "legacy.mp4", ep.EncSuffix, 100)
			if err != nil {
				t.Fatal(err)
			}
			raw := "/limited/" + encoded
			d.SetEncPathMapping(display, raw)
			r := httptest.NewRequest(http.MethodPut, "/dav"+display, nil)
			if _, _, err := prepareFilenameWrite(h.cfg, d, r, ep, display, raw, 5, false, upstream.Client()); err == nil {
				t.Fatal("existing or uninspectable destination admitted")
			}
			if _, found, err := d.GetFilenameReservation(h.cfg.GetAlistURL(), raw); err != nil || found {
				t.Fatalf("rejected preflight created reservation: found=%v err=%v", found, err)
			}
			if got, ok := d.GetEncPath(display); !ok || got != raw {
				t.Fatal("rejected write changed legacy mapping")
			}
			guard := &WebDAVHandler{cfg: h.cfg, fileDAO: d, passwdDAO: dao.NewPasswdDAO(nil, h.cfg)}
			if guard.hasInvalidProtectedFilenameScope(r, display) {
				t.Fatal("rejected preflight fenced the legacy read")
			}
			if requests != 1 {
				t.Fatalf("unexpected requests=%d", requests)
			}
		})
	}
}

func TestProtectedFilenameCancelledPreflightDoesNotReserve(t *testing.T) {
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("cancelled preflight unexpectedly reached upstream")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
	h, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(h.Stop)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodPut, "/dav/limited/cancelled.mp4", nil).WithContext(ctx)
	if _, _, err := prepareFilenameWrite(h.cfg, d, r, ep, "/limited/cancelled.mp4", "/raw", 5, false, upstream.Client()); err == nil {
		t.Fatal("cancelled preflight admitted")
	}
	encoded, _, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, "cancelled.mp4", ep.EncSuffix, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.GetFilenameReservation(h.cfg.GetAlistURL(), "/limited/"+encoded); err != nil || found {
		t.Fatalf("cancelled preflight reserved destination: found=%v err=%v", found, err)
	}
}

func TestProtectedFilenamePostReservationFailureRemainsFenced(t *testing.T) {
	requests := 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
	h, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(h.Stop)
	h.cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	display := "/limited/raced.mp4"
	encoded, _, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, "raced.mp4", ep.EncSuffix, 100)
	if err != nil {
		t.Fatal(err)
	}
	raw := "/limited/" + encoded
	r := httptest.NewRequest(http.MethodPut, "/dav"+display, nil)
	if _, _, err := prepareFilenameWrite(h.cfg, d, r, ep, display, raw, 5, false, upstream.Client()); err == nil {
		t.Fatal("post-reservation existence change admitted")
	}
	rec, found, err := d.GetFilenameReservation(h.cfg.GetAlistURL(), raw)
	if err != nil || !found || rec.Status != storage.FilenameFailed {
		t.Fatalf("post-admission failure not retained: found=%v status=%s err=%v", found, rec.Status, err)
	}
	if _, err := d.ReserveFilename(rec); err == nil {
		t.Fatal("existing failed reservation released")
	}
	d.SetEncPathMapping(display, raw)
	guard := &WebDAVHandler{cfg: h.cfg, fileDAO: d, passwdDAO: dao.NewPasswdDAO(nil, h.cfg)}
	for _, authorization := range []string{"", "Basic test", "Bearer test"} {
		read := httptest.NewRequest(http.MethodGet, "/dav"+display, nil)
		read.Header.Set("Authorization", authorization)
		if !guard.hasInvalidProtectedFilenameScope(read, display) {
			t.Fatal("failed reservation read guard relaxed")
		}
	}
	if requests != 2 {
		t.Fatalf("absence must be checked both before and after reservation: requests=%d", requests)
	}
}

func TestProtectedFilenamePolicySegmentAndLongestPrefix(t *testing.T) {
	cfg := config.Get()
	old := cfg.AlistServer
	t.Cleanup(func() { cfg.AlistServer = old })
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100, "/limited/strict": 80}
	for _, tc := range []struct {
		p string
		n int
	}{{"/limited/a", 100}, {"/limited/strict/a", 80}, {"/limited-other/a", 0}, {"/other/a", 0}} {
		if got := protectedFilenameLimit(cfg, tc.p); got != tc.n {
			t.Errorf("%s=%d want%d", tc.p, got, tc.n)
		}
	}
}
