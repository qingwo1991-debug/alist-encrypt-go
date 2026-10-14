package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
)

func TestFilenameAuditCursorBindingsAndSecrecy(t *testing.T) {
	token, err := encodeAuditCursor("secret", strings.Repeat("a", 64), "binding")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(token, "binding") || strings.Contains(token, strings.Repeat("a", 64)) {
		t.Fatal("plaintext cursor")
	}
	if after, err := decodeAuditCursor("secret", token, "binding"); err != nil || after != strings.Repeat("a", 64) {
		t.Fatalf("cursor %s %v", after, err)
	}
	for _, c := range []struct{ secret, token, binding string }{{"changed", token, "binding"}, {"secret", token, "other-caller-or-filter"}, {"secret", token + "!", "binding"}} {
		if _, err := decodeAuditCursor(c.secret, c.token, c.binding); err == nil {
			t.Fatal("scope/tampering accepted")
		}
	}
}
func TestFilenameAuditSensitiveJWTCurrentUserAndDryRun(t *testing.T) {
	s, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg := config.DefaultConfig()
	cfg.JWTSecret = "audit-test-secret"
	users := dao.NewUserDAO(s)
	// Persist a synthetic management identity without expensive password derivation.
	if err = s.SetJSON(storage.BucketUsers, "manager", dao.User{Username: "manager", PasswordHash: "nonempty-test-hash"}); err != nil {
		t.Fatal(err)
	}
	files := dao.NewFileDAO(s, cfg)
	h := &APIHandler{cfg: cfg, userDAO: users, fileDAO: files}
	now := time.Now().UTC()
	rec, err := files.ReserveFilename(storage.FilenameRecord{Origin: cfg.GetAlistURL(), EncryptedPath: "/enc/cipher.bin", OriginalPath: "/enc/secret original.mp4", DisplayName: "cipher.bin", RuleFingerprint: strings.Repeat("a", 64), AuthScope: strings.Repeat("b", 64), CiphertextSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("manager")
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"version": {"1"}, "sensitive": {"true"}, "from": {now.Add(-time.Hour).Format(time.RFC3339Nano)}, "until": {now.Add(time.Hour).Format(time.RFC3339Nano)}, "path_prefix": {"/enc"}, "limit": {"1"}}
	invoke := func(method, query, bearer string, dry bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/enc-api/filenameAudit?"+query, nil)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		if dry {
			h.FilenameReconcileDryRun(w, r)
		} else {
			h.FilenameAudit(w, r)
		}
		return w
	}
	if w := invoke("GET", values.Encode(), "", false); w.Code != 401 {
		t.Fatalf("missing JWT: %d", w.Code)
	}
	for _, key := range []string{"version", "sensitive", "from", "until", "limit", "path_prefix"} {
		v := url.Values{}
		for k, x := range values {
			v[k] = x
		}
		v.Del(key)
		if w := invoke("GET", v.Encode(), token, false); w.Code != 400 {
			t.Fatalf("missing %s: %d %s", key, w.Code, w.Body.String())
		}
	}
	w := invoke("GET", values.Encode(), token, false)
	if w.Code != 200 {
		t.Fatalf("query %d %s", w.Code, w.Body.String())
	}
	for _, secret := range []string{rec.Token, rec.OriginalPath, rec.AuthScope, rec.RuleFingerprint, "PasswordHash", "Nonce", "Token"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("secret in response: %s", w.Body.String())
		}
	}
	values.Set("include_names", "true")
	w = invoke("GET", values.Encode(), token, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), rec.OriginalPath) {
		t.Fatalf("names %d %s", w.Code, w.Body.String())
	}
	w = invoke("POST", values.Encode(), token, true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var result map[string]interface{}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["actual_remote_check"] != false || result["remote"] != "unknown" || result["op_id"] == "" {
		t.Fatal(result)
	}
	again := invoke("POST", values.Encode(), token, true)
	var second map[string]interface{}
	if err = json.Unmarshal(again.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if result["op_id"] == second["op_id"] {
		t.Fatal("reused operation ID")
	}
	after, ok, err := files.GetFilenameReservation(rec.Origin, rec.EncryptedPath)
	if err != nil || !ok || after != rec {
		t.Fatal("dry-run mutated reservation")
	}
	if err = users.Delete("manager"); err != nil {
		t.Fatal(err)
	}
	if w = invoke(http.MethodGet, values.Encode(), token, false); w.Code != 403 {
		t.Fatalf("deleted/stale user: %d", w.Code)
	}
}
