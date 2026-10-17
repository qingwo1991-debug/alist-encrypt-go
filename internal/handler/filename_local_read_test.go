package handler

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/ports"
	"github.com/alist-encrypt-go/internal/storage"
)

type unavailableFilenameReadRepository struct{ ports.FileRepository }

func (unavailableFilenameReadRepository) FindFilenameReservationForRead(string, string) (storage.FilenameRecord, bool, error) {
	return storage.FilenameRecord{}, false, errors.New("filename read index not ready")
}

func TestFilenameReadIndexUnavailableReturnsRetry(t *testing.T) {
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, Enable: true, EncPath: []string{"/limited/*"}}
	ah, d := newTestAlistHandler(t, "http://127.0.0.1:1", ep)
	t.Cleanup(ah.Stop)
	ah.cfg.AlistServer.PlaybackProfile = config.PlaybackProfileTrustedLocal
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: unavailableFilenameReadRepository{d}, passwdDAO: ah.passwdDAO}
	for _, method := range []string{"GET", "HEAD", "PROPFIND"} {
		rr := httptest.NewRecorder()
		h.Handle(rr, httptest.NewRequest(method, "http://proxy/dav/limited/missing.mp4", nil))
		if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
			t.Fatalf("%s returned %d retry=%q", method, rr.Code, rr.Header().Get("Retry-After"))
		}
	}
}

// Loopback TCP counts distinguish the routing preflight from the actual DAV
// operation. Literal percent escapes must survive both paths without decoding.
func TestProtectedFilenamePlaybackProfiles(t *testing.T) {
	for _, profile := range []string{config.PlaybackProfileStandard, config.PlaybackProfileTrustedLocal} {
		t.Run(profile, func(t *testing.T) {
			raw, original := "/limited/cipher%2f.bin", "/limited/original%2f.mp4"
			calls := 0
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "PROPFIND" || r.URL.Path != "/dav"+raw || r.Header.Get("Depth") != "0" || r.Header.Get("Authorization") != "Basic current-account" {
					t.Errorf("unexpected upstream request: %s %s depth=%s auth=%s", r.Method, r.URL.Path, r.Header.Get("Depth"), r.Header.Get("Authorization"))
				}
				w.WriteHeader(http.StatusMultiStatus)
				fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href><d:propstat><d:prop><d:displayname>cipher.bin</d:displayname><d:getcontentlength>37</d:getcontentlength><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, (&url.URL{Path: "/dav" + raw}).EscapedPath())
			}))
			defer upstream.Close()
			ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
			ah, d := newTestAlistHandler(t, upstream.URL, ep)
			t.Cleanup(ah.Stop)
			ah.cfg.AlistServer.PlaybackProfile = profile
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, stdClient: upstream.Client(), shortClient: upstream.Client()}
			rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: h.cfg.GetAlistURL(), EncryptedPath: raw, OriginalPath: original, DisplayName: "cipher.bin", AuthScope: strings.Repeat("a", 64), RuleFingerprint: filenameRuleScope(ep), CiphertextSize: 37})
			if err != nil {
				t.Fatal(err)
			}
			if err = d.FinishFilenameReservation(rec.Origin, raw, rec.Token, storage.FilenameComplete); err != nil {
				t.Fatal(err)
			}
			preflight := 1
			if profile == config.PlaybackProfileTrustedLocal {
				preflight = 0
			}
			for _, method := range []string{"GET", "HEAD", "PROPFIND"} {
				r := httptest.NewRequest(method, "http://proxy"+(&url.URL{Path: "/dav" + original}).EscapedPath(), nil)
				r.Header.Set("Authorization", "Basic current-account")
				before := calls
				invalid, err := h.hasInvalidProtectedFilenameScope(r, original)
				if invalid || err != nil {
					t.Fatalf("%s invalid=%v err=%v", method, invalid, err)
				}
				bound, ok := r.Context().Value(filenameRawPathKey{}).(filenameRawPath)
				if !ok || bound.raw != raw || bound.remoteAuthorized != (preflight == 1) {
					t.Fatalf("bad binding: %+v", bound)
				}
				if calls-before != preflight {
					t.Fatalf("%s preflight=%d want=%d", method, calls-before, preflight)
				}
				if got, _ := h.resolveRealPathForRequest(r, original, ep); got != raw {
					t.Fatalf("%s target=%q", method, got)
				}
			}
			r := httptest.NewRequest("PROPFIND", "http://proxy"+(&url.URL{Path: "/dav" + original}).EscapedPath(), nil)
			r.Header.Set("Authorization", "Basic current-account")
			r.Header.Set("Depth", "0")
			before := calls
			rr := httptest.NewRecorder()
			h.Handle(rr, r)
			if rr.Code != http.StatusMultiStatus || calls-before != preflight+1 {
				t.Fatalf("actual PROPFIND status=%d calls=%d want=%d body=%s", rr.Code, calls-before, preflight+1, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "original%252f.mp4") {
				t.Fatalf("original-name overlay missing: %s", rr.Body.String())
			}
			if _, ok := d.GetEncPath(original); ok {
				t.Fatal("local binding leaked to shared mapping")
			}
		})
	}
}

func TestTrustedLocalFilenameRejectsIncompleteAndWrongRule(t *testing.T) {
	for _, status := range []string{storage.FilenamePending, storage.FilenameFailed, storage.FilenameComplete} {
		t.Run(status, func(t *testing.T) {
			ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, Enable: true, EncPath: []string{"/limited/*"}}
			ah, d := newTestAlistHandler(t, "http://127.0.0.1:1", ep)
			t.Cleanup(ah.Stop)
			ah.cfg.AlistServer.PlaybackProfile = config.PlaybackProfileTrustedLocal
			rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: ah.cfg.GetAlistURL(), EncryptedPath: "/limited/raw.bin", OriginalPath: "/limited/original.mp4", DisplayName: "raw.bin", AuthScope: strings.Repeat("a", 64), RuleFingerprint: strings.Repeat("b", 64)})
			if err != nil {
				t.Fatal(err)
			}
			if status != storage.FilenamePending {
				if err = d.FinishFilenameReservation(rec.Origin, rec.EncryptedPath, rec.Token, status); err != nil {
					t.Fatal(err)
				}
			}
			h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO}
			rr := httptest.NewRecorder()
			h.Handle(rr, httptest.NewRequest("GET", "http://proxy/dav"+rec.OriginalPath, nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("status=%d", rr.Code)
			}
		})
	}
}
