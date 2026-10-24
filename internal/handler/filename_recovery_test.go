package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

func TestAdminFilenameRecoveryPreservesAuditAndReprovesRead(t *testing.T) {
	original := "/limited/hhd800.com@SNOS-229.mp4"
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncSuffix: ".bin", Enable: true, EncName: true, EncPath: []string{"/limited/*"}}
	encoded, short, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, "hhd800.com@SNOS-229.mp4", ep.EncSuffix, 100)
	if err != nil {
		t.Fatal(err)
	}
	raw := "/limited/" + encoded
	calls := 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PROPFIND" || r.URL.Path != "/dav"+raw {
			t.Errorf("unexpected upstream operation %s %s", r.Method, r.URL.Path)
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("Authorization") != "Basic test" {
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(207)
		fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href><d:propstat><d:prop><d:getcontentlength>132</d:getcontentlength><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, (&url.URL{Path: "/dav" + raw}).EscapedPath())
	}))
	defer upstream.Close()
	ah, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(ah.Stop)
	meta := encryption.ContentMeta{EncType: encryption.EncTypeAESCTR, Version: encryption.ContentVersionV2, HeaderLen: 32, PlainSize: 100, CiphertextSize: 132, NonceField: bytes.Repeat([]byte{7}, 16)}
	inspector := &recoveryInspectorMock{result: proxy.MediaIdentityResult{Meta: meta, Ext: ".mp4", MIME: "video/mp4", Reusable: true, PrefixSHA256: strings.Repeat("c", 64)}}
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, streamProxy: inspector, shortClient: upstream.Client()}
	rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: h.cfg.GetAlistURL(), EncryptedPath: raw, OriginalPath: original, DisplayName: short, RuleFingerprint: filenameRuleScope(ep), AuthScope: strings.Repeat("a", 64), CiphertextSize: 132})
	if err != nil {
		t.Fatal(err)
	}
	post := func(auth string) int {
		r := httptest.NewRequest("POST", "http://proxy/enc-api/recoverFilename", strings.NewReader(`{"original_path":"`+original+`"}`))
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		h.HandleRecoverFilename(w, r)
		return w.Code
	}
	if code := post("Basic test"); code != 409 {
		t.Fatal("pending admitted", code)
	}
	if err := d.FinishFilenameReservation(rec.Origin, raw, rec.Token, storage.FilenameFailed); err != nil {
		t.Fatal(err)
	}
	rec, _, _ = d.GetFilenameReservation(rec.Origin, raw)
	if code := post("Basic wrong"); code != 409 {
		t.Fatal("owner proof skipped", code)
	}
	if code := post("Basic test"); code != 200 {
		t.Fatal("recovery failed", code)
	}
	after, _, _ := d.GetFilenameReservation(rec.Origin, raw)
	if !reflect.DeepEqual(after, rec) {
		t.Fatal("failed audit changed")
	}
	for _, auth := range []string{"Basic test", "Basic wrong", ""} {
		r := httptest.NewRequest("GET", "http://proxy/dav"+original, nil)
		r.Header.Set("Authorization", auth)
		before := calls
		invalid, err := h.hasInvalidProtectedFilenameScope(r, original)
		if err != nil || invalid != (auth != "Basic test") || calls != before+1 {
			t.Fatalf("read auth=%q invalid=%v err=%v", auth, invalid, err)
		}
	}
	inspector.result.PrefixSHA256 = strings.Repeat("d", 64)
	r := httptest.NewRequest("HEAD", "http://proxy/dav"+original, nil)
	r.Header.Set("Authorization", "Basic test")
	if invalid, _ := h.hasInvalidProtectedFilenameScope(r, original); !invalid {
		t.Fatal("same-size changed object admitted")
	}
	if _, ok := d.GetEncPath(original); ok {
		t.Fatal("recovery leaked global mapping")
	}
	inspector.result.PrefixSHA256 = strings.Repeat("c", 64)
	changed := *ep
	changed.Password = "changed"
	if _, ok := h.freshFilenameRecoveryRule(rec, h.cfg.RuntimeRevision()); !ok {
		t.Fatal("fresh rule unexpectedly rejected")
	}
	if h.recoveryFilenameMatches(rec, &changed) {
		t.Fatal("changed filename key admitted")
	}
	wrong := rec
	wrong.EncryptedPath = "/another/" + encoded
	if h.recoveryFilenameMatches(wrong, ep) {
		t.Fatal("different directory admitted")
	}
	wrong.EncryptedPath = "/limited/incorrect.bin"
	if h.recoveryFilenameMatches(wrong, ep) {
		t.Fatal("different ciphertext name admitted")
	}
	// Even without a runtime-generation update the fresh current rule must match.
	h.cfg.AlistServer.PasswdList[0].Password = "changed"
	if code := post("Basic test"); code != 409 {
		t.Fatal("changed current rule admitted", code)
	}
	if invalid, _ := h.hasInvalidProtectedFilenameScope(r, original); !invalid {
		t.Fatal("recovered read accepted changed current rule")
	}
}
