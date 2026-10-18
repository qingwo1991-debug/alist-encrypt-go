package handler

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/proxy"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

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
	unexpected := 0
	upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic test" {
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
	ah, d := newTestAlistHandler(t, upstream.URL, ep)
	t.Cleanup(ah.Stop)
	server := ah.cfg.AlistServerSnapshot()
	server.PlaybackProfile = config.PlaybackProfileTrustedLocal
	if err := ah.cfg.UpdateAlistServer(server); err != nil {
		t.Fatal(err)
	}
	sp := proxy.NewStreamProxy(ah.cfg)
	h := &WebDAVHandler{cfg: ah.cfg, fileDAO: d, passwdDAO: ah.passwdDAO, streamProxy: sp, shortClient: upstream.Client()}
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
	identity := playbackIdentity(ah.cfg, upstream.URL, raw, ep, http.Header{"Authorization": []string{"Basic test"}})
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
	if unexpected != 0 {
		t.Fatal("recovered read used stale locator or global API", unexpected)
	}
	got, ok := d.GetConfirmedPlayback(identity)
	if !ok || !bytes.Equal(got.NonceField, old.NonceField) {
		t.Fatal("request-private proof changed global confirmation")
	}
}
