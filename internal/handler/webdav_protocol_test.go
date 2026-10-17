package handler

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func protocolDAV(raw string, size int64, dir bool) string {
	resource := ""
	if dir {
		resource = "<D:collection/>"
	}
	return fmt.Sprintf(`<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav%s</D:href><D:propstat><D:prop><D:displayname>file.bin</D:displayname><D:getcontentlength>%d</D:getcontentlength><D:resourcetype>%s</D:resourcetype></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>`, raw, size, resource)
}

type protocolMetaStore struct{ writes []FileMeta }

func (s *protocolMetaStore) Get(context.Context, string, string) (FileMeta, bool, error) {
	return FileMeta{}, false, nil
}
func (s *protocolMetaStore) Upsert(_ context.Context, m FileMeta) error {
	s.writes = append(s.writes, m)
	return nil
}
func (s *protocolMetaStore) Cleanup(context.Context, time.Time) error { return nil }

func TestLP0ConfirmedPropfindGeometryAndBinding(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		version               int
		plain, cipher, header int64
	}{
		{"V1", 1, 1024, 1024, 0}, {"V2", 2, 1024, 1056, 32}, {"V3", 3, 1024, 1200, 64}, {"emptyV3", 3, 0, 64, 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
			ah, d := newTestAlistHandler(t, "http://127.0.0.1:1", ep)
			t.Cleanup(ah.Stop)
			metaStore := &protocolMetaStore{}
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, metaStore: metaStore}
			raw := "/limited/raw.bin"
			if err := d.Set(&dao.FileInfo{Path: raw, EncryptedPath: raw, Name: "raw.bin", Size: tc.plain, CiphertextSize: tc.cipher, ContentVersion: tc.version, HeaderLen: tc.header}); err != nil {
				t.Fatal(err)
			}
			body := []byte(protocolDAV(raw, tc.cipher, false))
			h.parsePropfindResponse(context.Background(), body, "/limited/")
			out := h.rewritePropfindBody(body, ep)
			entries := h.parsePropfindEntries(out)
			if len(entries) != 1 || entries[0].Size != tc.plain {
				t.Fatalf("length rewrite: %s", out)
			}
			fi, _ := d.Get(raw)
			if fi.Size != tc.plain || fi.ContentVersion != tc.version {
				t.Fatalf("listing corrupted geometry: %+v", fi)
			}
			r := httptest.NewRequest("PROPFIND", "http://proxy/dav/limited/original.mp4", nil)
			rememberVerifiedFilenamePath(r, "/limited/original.mp4", raw)
			out = restoreBoundFilenameResponse(r, out, body)
			if !bytes.Contains(out, []byte("original.mp4")) || !bytes.Contains(out, []byte(fmt.Sprintf("<D:getcontentlength>%d</D:getcontentlength>", tc.plain))) {
				t.Fatalf("overlay corrupted length: %s", out)
			}
		})
	}
}

func TestLP0UnknownListingLengthUnavailable(t *testing.T) {
	ep := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr"}
	ah, d := newTestAlistHandler(t, "http://127.0.0.1:1", ep)
	t.Cleanup(ah.Stop)
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO}
	out := h.rewritePropfindBody([]byte(protocolDAV("/limited/unknown.bin", 1056, false)), ep)
	if bytes.Contains(out, []byte(">1056<")) || !bytes.Contains(out, []byte("404 Not Found")) {
		t.Fatalf("unknown length leaked: %s", out)
	}
	for _, generic := range []string{
		strings.ReplaceAll(protocolDAV("/limited/unknown.bin", 1056, false), "D:", "x:"),
		strings.Replace(protocolDAV("/limited/unknown.bin", 1056, false), "<D:response>", `<D:response xmlns:extra="urn:fixture">`, 1),
	} {
		generic = strings.ReplaceAll(generic, "xmlns:D=", "xmlns:x=")
		// Restore D namespace in the attribute-only case.
		if strings.Contains(generic, "<D:") {
			generic = strings.ReplaceAll(generic, "xmlns:x=", "xmlns:D=")
		}
		out = h.rewritePropfindBody([]byte(generic), ep)
		entries := h.parsePropfindEntries(out)
		if bytes.Contains(out, []byte(">1056<")) || len(entries) != 1 || entries[0].Size != -1 {
			t.Fatalf("generic XML unknown not preserved: %s entries=%+v", out, entries)
		}
	}
	// Snapshot serialization must preserve unknown, not publish an empty file.
	var snapshot bytes.Buffer
	snapshot.WriteString(`<D:multistatus xmlns:D="DAV:">`)
	writeSnapshotResponse(&snapshot, "/dav/limited/unknown.bin", "unknown.bin", false, -1, "", "", "", "")
	writeSnapshotResponse(&snapshot, "/dav/limited/empty.bin", "empty.bin", false, 0, "", "", "", "")
	snapshot.WriteString(`</D:multistatus>`)
	entries := h.parsePropfindEntries(snapshot.Bytes())
	if len(entries) != 2 || entries[0].Size != -1 || entries[1].Size != 0 {
		t.Fatalf("unknown/empty collapsed: %+v %s", entries, snapshot.Bytes())
	}
}

func TestLP0DirectorySlashFallbackUniqueTargets(t *testing.T) {
	var targets []string
	ep := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr", EncName: true, EncSuffix: ".bin", EncPath: []string{"/limited/*"}}
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targets = append(targets, r.URL.Path)
		if r.Method != "PROPFIND" || r.Header.Get("Depth") != "1" || r.Header.Get("Authorization") != "Basic caller" {
			t.Error("fallback lost request semantics")
		}
		if r.URL.Path != "/dav/limited/encrypt/" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(207)
		io.WriteString(w, protocolDAV("/limited/encrypt/", 0, true))
	}))
	defer upstream.Close()
	ah, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(ah.Stop)
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: upstream.Client(), negCache: newNegativePathCache(time.Minute)}
	for i := 0; i < 2; i++ {
		before := len(targets)
		r := httptest.NewRequest("PROPFIND", "http://proxy/dav/limited/encrypt", strings.NewReader("<propfind/>"))
		r.Header.Set("Depth", "1")
		r.Header.Set("Authorization", "Basic caller")
		rr := httptest.NewRecorder()
		h.handlePropfind(rr, r, "/limited/encrypt")
		if rr.Code != 207 {
			t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
		}
		seen := map[string]bool{}
		for _, target := range targets[before:] {
			if seen[target] {
				t.Fatalf("duplicate retry: %v", targets)
			}
			seen[target] = true
		}
		if i == 1 && len(targets)-before != 1 {
			t.Fatalf("known directory incurred fallback: %v", targets)
		}
	}
}

func TestLP0MissingPropfindDoesNotRetrySameCandidate(t *testing.T) {
	for _, requested := range []string{"/limited/missing.bin", "/limited/missing/"} {
		t.Run(requested, func(t *testing.T) {
			seen := map[string]bool{}
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if seen[r.URL.Path] {
					t.Errorf("duplicate request to %s", r.URL.Path)
				}
				seen[r.URL.Path] = true
				http.NotFound(w, r)
			}))
			defer upstream.Close()
			ep := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr", EncName: true, EncSuffix: ".bin", EncPath: []string{"/limited/*"}}
			ah, d := newTestAlistHandler(t, upstream.URL, ep)
			t.Cleanup(ah.Stop)
			// A preexisting raw-path self mapping must not induce a second 404 request.
			d.SetEncPathMapping(requested, requested)
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: upstream.Client()}
			r := httptest.NewRequest("PROPFIND", "http://proxy/dav"+requested, nil)
			r.Header.Set("Depth", "1")
			rr := httptest.NewRecorder()
			h.handlePropfind(rr, r, requested)
			if rr.Code != 404 {
				t.Fatalf("status %d", rr.Code)
			}
		})
	}
}

func TestLP0CachedDirectory404HasOneTarget(t *testing.T) {
	for _, requested := range []string{"/limited/encrypt", "/limited/encrypt/"} {
		t.Run(requested, func(t *testing.T) {
			var targets []string
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targets = append(targets, r.URL.Path)
				http.NotFound(w, r)
			}))
			defer upstream.Close()
			ep := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr", EncName: true, EncSuffix: ".bin", EncPath: []string{"/limited/*"}}
			ah, d := newTestAlistHandler(t, upstream.URL, ep)
			t.Cleanup(ah.Stop)
			if err := d.Set(&dao.FileInfo{Path: "/limited/encrypt/", Name: "encrypt", IsDir: true}); err != nil {
				t.Fatal(err)
			}
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: upstream.Client()}
			r := httptest.NewRequest("PROPFIND", "http://proxy/dav"+requested, nil)
			r.Header.Set("Depth", "1")
			rr := httptest.NewRecorder()
			h.handlePropfind(rr, r, requested)
			if rr.Code != 404 || len(targets) != 1 || targets[0] != "/dav/limited/encrypt/" {
				t.Fatalf("known missing collection must not retry/derive file: status=%d targets=%v", rr.Code, targets)
			}
		})
	}
}

// Real encrypted bytes and loopback HTTP: a cold single-resource PROPFIND
// confirms V2 rather than guessing 32; subsequent listings reuse that evidence.
func TestLP0ColdV2PropfindThenGET(t *testing.T) {
	plain := bytes.Repeat([]byte("length-fixture"), 64)
	enc, err := encryption.NewLatestContentEncryptor("pw", "aesctr", int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	raw := "/limited/file.bin"
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			w.WriteHeader(207)
			io.WriteString(w, protocolDAV(raw, int64(len(cipher)), false))
			return
		}
		http.ServeContent(w, r, "file.bin", time.Time{}, bytes.NewReader(cipher))
	}))
	defer upstream.Close()
	ep := &config.PasswdInfo{Enable: true, Password: "pw", EncType: "aesctr", EncPath: []string{"/limited/*"}}
	ah, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(ah.Stop)
	sp := proxy.NewStreamProxy(ah.cfg)
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: upstream.Client(), streamProxy: sp}
	for _, depth := range []string{"0", "1"} {
		r := httptest.NewRequest("PROPFIND", "http://proxy/dav"+raw, nil)
		r.Header.Set("Depth", depth)
		rr := httptest.NewRecorder()
		h.handlePropfind(rr, r, raw)
		if rr.Code != 207 || !strings.Contains(rr.Body.String(), fmt.Sprintf("<D:getcontentlength>%d</D:getcontentlength>", len(plain))) {
			t.Fatalf("Depth%s: %d %s", depth, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("Content-Length") != strconv.Itoa(rr.Body.Len()) {
			t.Fatal("XML body Content-Length mismatch")
		}
	}
	fi, _ := d.Get(raw)
	if fi.Size != int64(len(plain)) || fi.ContentVersion != 2 {
		t.Fatalf("cold inspection cache %+v", fi)
	}
}
