package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/storage"
)

// A real TCP DAV endpoint, not a mock transport: upload and playback use
// different credential formats for the same upstream account.
func TestProtectedFilenameReadAuthorizesCurrentCaller(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached=%v", cached), func(t *testing.T) {
			raw := "/limited/cipher%2f.bin"
			original := "/limited/4k688.com@WA-596.part003.mp4"
			calls := 0
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "PROPFIND" || r.URL.Path != "/dav"+raw || r.Header.Get("Depth") != "0" {
					t.Errorf("wrong authorization target: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") == "Bearer upload-secret" {
					t.Error("upload credential forwarded")
				}
				if r.Header.Get("Authorization") != "Basic current-account" && r.Header.Get("Authorization") != "Bearer alternate-account-token" {
					w.WriteHeader(403)
					return
				}
				w.WriteHeader(207)
				fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href><d:propstat><d:prop><d:getcontentlength>37</d:getcontentlength><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, (&url.URL{Path: "/dav" + raw}).EscapedPath())
			}))
			defer upstream.Close()
			ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
			ah, d := newTestAlistHandler(t, upstream.URL, ep)
			t.Cleanup(ah.Stop)
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: upstream.Client(), shortClient: upstream.Client()}
			upload := httptest.NewRequest("PUT", "http://proxy/upload", nil)
			upload.Header.Set("Authorization", "Bearer upload-secret")
			rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: h.cfg.GetAlistURL(), EncryptedPath: raw, OriginalPath: original, DisplayName: "short.bin", AuthScope: filenameRequestScope(upload), RuleFingerprint: filenameRuleScope(ep), CiphertextSize: 37})
			if err != nil {
				t.Fatal(err)
			}
			if err = d.FinishFilenameReservation(rec.Origin, raw, rec.Token, storage.FilenameComplete); err != nil {
				t.Fatal(err)
			}
			if cached {
				d.SetEncPathMapping(original, raw)
			}
			for _, method := range []string{"PROPFIND", "GET", "HEAD"} {
				for _, auth := range []string{"Basic current-account", "Bearer alternate-account-token", "", "Basic other-account"} {
					r := httptest.NewRequest(method, "http://proxy/dav"+original, nil)
					r.Header.Set("Authorization", auth)
					before := calls
					invalid, err := h.hasInvalidProtectedFilenameScope(r, original)
					want := auth != "" && auth != "Basic other-account"
					if err != nil || invalid == want {
						t.Fatalf("%s %q invalid=%v err=%v", method, auth, invalid, err)
					}
					if calls != before+1 {
						t.Fatal("read skipped fresh upstream authorization")
					}
					bound, ok := r.Context().Value(filenameRawPathKey{}).(filenameRawPath)
					if ok != want || ok && bound.raw != raw {
						t.Fatalf("unexpected request-local binding %+v", bound)
					}
				}
			}
			if !cached {
				if _, ok := d.GetEncPath(original); ok {
					t.Fatal("private mapping escaped to global cache")
				}
			}
			full := httptest.NewRequest("PROPFIND", "http://proxy/dav"+original, nil)
			full.Header.Set("Authorization", "Basic current-account")
			full.Header.Set("Depth", "0")
			rr := httptest.NewRecorder()
			h.Handle(rr, full)
			if rr.Code != 207 || !strings.Contains(rr.Body.String(), "WA-596.part003.mp4") {
				t.Fatalf("full PROPFIND: %d %s", rr.Code, rr.Body.String())
			}
			denied := httptest.NewRequest("PROPFIND", "http://proxy/dav"+original, nil)
			rr = httptest.NewRecorder()
			h.Handle(rr, denied)
			if rr.Code != 404 || strings.Contains(rr.Body.String(), "WA-596") {
				t.Fatalf("unauthorized plaintext: %d %s", rr.Code, rr.Body.String())
			}
			got, ok, err := d.GetFilenameReservation(rec.Origin, raw)
			if err != nil || !ok || got.AuthScope != rec.AuthScope || got.Status != storage.FilenameComplete {
				t.Fatal("read modified audit record")
			}
		})
	}
}

func TestProtectedFilenameReadRejectsIncompleteAndChangedRule(t *testing.T) {
	for _, status := range []string{storage.FilenamePending, storage.FilenameFailed, storage.FilenameComplete} {
		t.Run(status, func(t *testing.T) {
			ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, Enable: true, EncPath: []string{"/limited/*"}}
			ah, d := newTestAlistHandler(t, "http://127.0.0.1:1", ep)
			t.Cleanup(ah.Stop)
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO}
			rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: h.cfg.GetAlistURL(), EncryptedPath: "/limited/raw.bin", OriginalPath: "/limited/original.mp4", DisplayName: "raw.bin", AuthScope: strings.Repeat("a", 64), RuleFingerprint: strings.Repeat("b", 64)})
			if err != nil {
				t.Fatal(err)
			}
			if status != storage.FilenamePending {
				if err = d.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, status); err != nil {
					t.Fatal(err)
				}
			}
			r := httptest.NewRequest("GET", "http://proxy/dav"+rec.OriginalPath, nil)
			invalid, err := h.hasInvalidProtectedFilenameScope(r, rec.OriginalPath)
			if !invalid || err != nil {
				t.Fatalf("invalid=%v err=%v", invalid, err)
			}
			if _, ok := r.Context().Value(filenameRawPathKey{}).(filenameRawPath); ok {
				t.Fatal("rejected record bound")
			}
		})
	}
}
