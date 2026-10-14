package handler

import (
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
		if r.Method == http.MethodHead {
			if len(stored) == 0 {
				w.WriteHeader(404)
				return
			}
			if r.URL.Path != "/dav"+raw {
				t.Errorf("postflight path %q != %q", r.URL.Path, "/dav"+raw)
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(stored)))
			w.WriteHeader(200)
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
		t.Fatal("failed reservation released")
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
	}{{"matching", "/dav/limited/cipher%252f.bin", 207, true}, {"wrong-path", "/dav/limited/other.bin", 207, false}, {"foreign-origin", "https://foreign.example/dav/limited/cipher%252f.bin", 207, false}, {"revoked", "/dav/limited/cipher%252f.bin", 403, false}} {
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
