package handler

import (
	"bytes"
	"encoding/binary"
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
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

// Recovery tests persist runtime revisions. They must not use the shared
// config.Get() fixture: UpdateAlistServer would save trusted_local into the
// package's conf/config.json and change the next build-tag test process's
// authorization/cache semantics, even if cleanup restores the in-memory value.
func newFilenameRecoveryCacheTestHandler(t *testing.T, origin string, ep *config.PasswdInfo) (*WebDAVHandler, *dao.FileDAO, string) {
	t.Helper()
	base := t.TempDir()
	cfg := config.LoadFromBaseDir(base)
	u, err := url.Parse(origin)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	// Bind the fixture origin explicitly; CI/developer ALIST_HOST/PORT defaults
	// must not redirect proof requests or alter their origin-scoped identity.
	cfg.AlistServer.ServerHost = u.Hostname()
	cfg.AlistServer.ServerPort = port
	cfg.AlistServer.HTTPS = u.Scheme == "https"
	cfg.AlistServer.PasswdList = []config.PasswdInfo{*ep}
	cfg.AlistServer.PlaybackProfile = config.PlaybackProfileStandard
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(store, cfg)
	passwords := dao.NewPasswdDAO(store, cfg)
	h := &WebDAVHandler{cfg: cfg, fileDAO: files, passwdDAO: passwords, streamProxy: proxy.NewStreamProxy(cfg)}
	t.Cleanup(func() {
		h.Stop()
		passwords.Stop()
		files.Stop()
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return h, files, base
}

func TestFilenameRecoveryCacheFixturePersistsOnlyPrivateConfig(t *testing.T) {
	t.Setenv("ALIST_HOST", "unrelated-ci-default.invalid")
	t.Setenv("ALIST_PORT", "65000")
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, Enable: true, EncPath: []string{"/limited/*"}}
	h, files, base := newFilenameRecoveryCacheTestHandler(t, "http://127.0.0.1:1", ep)
	if files.Config() != h.cfg || h.cfg.GetAlistURL() != "http://127.0.0.1:1" {
		t.Fatal("recovery fixture did not bind its own configuration and origin")
	}
	if rule, ok := h.passwdDAO.FindByPath("/limited/recovery.mp4"); !ok || filenameRuleScope(rule) != filenameRuleScope(ep) {
		t.Fatal("recovery password DAO did not use the private configuration")
	}
	server := h.cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := h.cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	if got := config.LoadFromBaseDir(base).AlistServerSnapshot().PlaybackProfile; got != config.PlaybackProfileTrustedLocal {
		t.Fatalf("private profile was not persisted: %q", got)
	}
	next, nextFiles, nextBase := newFilenameRecoveryCacheTestHandler(t, "http://127.0.0.1:2", ep)
	if next.cfg == h.cfg || nextBase == base || nextFiles.Config() != next.cfg || next.cfg.AlistServerSnapshot().PlaybackProfile != config.PlaybackProfileStandard || next.cfg.GetAlistURL() != "http://127.0.0.1:2" {
		t.Fatal("trusted-local recovery configuration escaped into the next fixture")
	}
	if got := config.LoadFromBaseDir(nextBase).AlistServerSnapshot().PlaybackProfile; got != config.PlaybackProfileStandard {
		t.Fatalf("trusted-local recovery profile escaped into the next config file: %q", got)
	}
}

func TestRecoveredFilenameReadIgnoresHistoricalGeometryAndLocator(t *testing.T) {
	original := "/limited/recovery.mp4"
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncSuffix: ".bin", Enable: true, EncName: true, EncPath: []string{"/limited/*"}}
	encoded, short, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, "recovery.mp4", ep.EncSuffix, 100)
	if err != nil {
		t.Fatal(err)
	}
	raw := "/limited/" + encoded
	plain := make([]byte, 8192)
	binary.BigEndian.PutUint32(plain, 20)
	copy(plain[4:], "ftyp")
	copy(plain[8:], "mp42")
	copy(plain[16:], "isom")
	enc, err := encryption.NewLatestContentEncryptor(ep.Password, ep.EncType, int64(len(plain)))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := enc.EncryptReader(bytes.NewReader(plain), 0)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	unexpected, denied := 0, 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic test" {
			denied++
			w.WriteHeader(403)
			return
		}
		if r.URL.Path != "/dav"+raw {
			unexpected++
			w.WriteHeader(500)
			return
		}
		if r.Method == "PROPFIND" {
			w.WriteHeader(207)
			fmt.Fprintf(w, `<d:multistatus xmlns:d="DAV:"><d:response><d:href>%s</d:href><d:propstat><d:prop><d:getcontentlength>%d</d:getcontentlength><d:resourcetype/></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>`, (&url.URL{Path: "/dav" + raw}).EscapedPath(), len(blob))
			return
		}
		http.ServeContent(w, r, "cipher", time.Time{}, bytes.NewReader(blob))
	}))
	defer upstream.Close()
	h, d, _ := newFilenameRecoveryCacheTestHandler(t, upstream.URL, ep)
	h.shortClient = upstream.Client()
	server := h.cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := h.cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: upstream.URL, EncryptedPath: raw, OriginalPath: original, DisplayName: short, RuleFingerprint: filenameRuleScope(ep), AuthScope: strings.Repeat("a", 64), CiphertextSize: int64(len(blob))})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.FinishFilenameReservation(rec.Origin, raw, rec.Token, storage.FilenameFailed); err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRequest("POST", "http://proxy/enc-api/recoverFilename", strings.NewReader(`{"original_path":"`+original+`"}`))
	post.Header.Set("Authorization", "Basic test")
	rr := httptest.NewRecorder()
	h.HandleRecoverFilename(rr, post)
	if rr.Code != 200 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	identity := playbackIdentity(h.cfg, upstream.URL, raw, ep, http.Header{"Authorization": []string{"Basic test"}})
	old := &dao.FileInfo{Path: original, EncryptedPath: raw, Name: "recovery.mp4", Size: int64(len(plain)), CiphertextSize: int64(len(blob)), ContentVersion: 2, HeaderLen: 32, NonceField: bytes.Repeat([]byte{99}, 16), GeometryIdentity: identity, GeometryConfirmedAt: time.Now(), RawURL: upstream.URL + "/stale-signed-object", RawURLIdentity: identity, RawURLAuthScope: "trusted_local", UpstreamFetchedAt: time.Now()}
	if !d.PublishConfirmedPlayback(old, d.PlaybackEpoch(original)) {
		t.Fatal("seed durable geometry")
	}
	for _, method := range []string{"HEAD", "GET"} {
		r := httptest.NewRequest(method, "http://proxy/dav"+original, nil)
		r.Header.Set("Authorization", "Basic test")
		if method == "GET" {
			r.Header.Set("Range", "bytes=0-1023")
		}
		w := httptest.NewRecorder()
		h.Handle(w, r)
		if method == "HEAD" {
			if w.Code != 200 || w.Header().Get("Content-Length") != "8192" {
				t.Fatalf("HEAD %d %v", w.Code, w.Header())
			}
		} else if w.Code != 206 || !bytes.Equal(w.Body.Bytes(), plain[:1024]) {
			t.Fatalf("GET %d bytes=%d", w.Code, w.Body.Len())
		}
	}
	// Even trusted-local global geometry and a locator cannot authorize a
	// recovered filename for a different current caller (including HEAD).
	for _, method := range []string{"HEAD", "GET"} {
		for _, auth := range []string{"", "Basic other-account"} {
			r := httptest.NewRequest(method, "http://proxy/dav"+original, nil)
			r.Header.Set("Authorization", auth)
			before := denied
			w := httptest.NewRecorder()
			h.Handle(w, r)
			if w.Code != http.StatusNotFound || denied != before+1 {
				t.Fatalf("%s auth=%q bypassed current-caller proof: status=%d denied=%d", method, auth, w.Code, denied-before)
			}
		}
	}
	if unexpected != 0 {
		t.Fatal("recovered read used stale locator or global API", unexpected)
	}
	got, ok := d.GetConfirmedPlayback(identity)
	if !ok || !bytes.Equal(got.NonceField, old.NonceField) {
		t.Fatal("request-private proof changed global confirmation")
	}
}
