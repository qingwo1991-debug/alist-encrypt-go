package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	encryption "github.com/alist-encrypt-go/shared/encryptcore"
)

type filenameRetryFixture struct {
	h     *WebDAVHandler
	d     *dao.FileDAO
	store *storage.Store
	rec   storage.FilenameRecord
	ep    *config.PasswdInfo
}

// Keep the real repository reads, but fail even if an attempted release would
// itself reject the claim without writing. No handler path may call release.
type filenameRetryReleaseGuard struct {
	*dao.FileDAO
	t *testing.T
}

func (g *filenameRetryReleaseGuard) ReleaseFailedFilename(storage.FilenameRecord) error {
	g.t.Error("retry handler called ReleaseFailedFilename")
	return errors.New("retry handler must not release a filename claim")
}

func newFilenameRetryFixture(t *testing.T) *filenameRetryFixture {
	t.Helper()
	// Probe-path tests explicitly opt in; production leaves this unset.
	t.Setenv("ALIST_FILENAME_RETRY_MAINTENANCE_ENABLE", "1")
	cfg := config.LoadFromBaseDir(t.TempDir())
	ep := &config.PasswdInfo{Password: "test", EncType: "aesctr", EncName: true, EncSuffix: ".bin", Enable: true, EncPath: []string{"/limited/*"}}
	cfg.AlistServer.ServerHost, cfg.AlistServer.ServerPort, cfg.AlistServer.HTTPS = "upstream.invalid", 5244, false
	cfg.AlistServer.PasswdList = []config.PasswdInfo{*ep}
	cfg.AlistServer.FilenameWriteLimits = map[string]int{"/limited": 100}
	s, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := dao.NewFileDAO(s)
	t.Cleanup(func() { d.Stop(); _ = s.Close() })
	encoded, short, err := encryption.BoundEncryptedFilename(ep.Password, ep.EncType, "retry.mp4", ep.EncSuffix, 100)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := d.ReserveFilename(storage.FilenameRecord{Origin: cfg.GetAlistURL(), EncryptedPath: "/limited/" + encoded, OriginalPath: "/limited/retry.mp4", DisplayName: short, RuleFingerprint: filenameRuleScope(ep), AuthScope: strings.Repeat("a", 64), CiphertextSize: 132})
	if err != nil {
		t.Fatal(err)
	}
	rec.Status = storage.FilenameFailed
	rec.CreatedAt = time.Now().UTC().Add(-time.Hour)
	rec.UpdatedAt = time.Now().UTC().Add(-11 * time.Minute)
	f := &filenameRetryFixture{d: d, store: s, rec: rec, ep: ep}
	f.save(t, rec)
	f.h = &WebDAVHandler{cfg: cfg, fileDAO: &filenameRetryReleaseGuard{FileDAO: d, t: t}, passwdDAO: dao.NewPasswdDAO(s, cfg)}
	return f
}

func (f *filenameRetryFixture) save(t *testing.T, rec storage.FilenameRecord) {
	t.Helper()
	sum := sha256.Sum256([]byte(rec.Origin + "\x00" + rec.EncryptedPath))
	if err := f.store.SetJSON([]byte("filename_reservations_v1"), hex.EncodeToString(sum[:]), rec); err != nil {
		t.Fatal(err)
	}
}

func (f *filenameRetryFixture) post(t *testing.T, body string, auth string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/enc-api/retryFilename", strings.NewReader(body))
	r.Header.Set("Authorizetoken", "management-jwt-never-forward")
	r.Header.Set("Authorization", auth)
	r.Header.Set("Cookie", "management-cookie-never-forward")
	w := httptest.NewRecorder()
	f.h.HandleRetryFilename(w, r)
	return w
}

func (f *filenameRetryFixture) body(extra map[string]interface{}) string {
	body := map[string]interface{}{"original_path": f.rec.OriginalPath, "audit_digest": storage.FilenameAuditDigest(f.rec), "maintenance_confirmed": true}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func (f *filenameRetryFixture) assertRetained(t *testing.T, expected storage.FilenameRecord, writes uint64) {
	t.Helper()
	got, found, err := f.d.GetFilenameReservation(expected.Origin, expected.EncryptedPath)
	if err != nil || !found || !reflect.DeepEqual(got, expected) {
		t.Fatalf("reservation changed: got=%+v found=%v err=%v want=%+v", got, found, err, expected)
	}
	got, found, err = f.d.FindFilenameReservationForRead(expected.Origin, expected.OriginalPath)
	if err != nil || !found || !reflect.DeepEqual(got, expected) {
		t.Fatalf("read mapping changed: got=%+v found=%v err=%v want=%+v", got, found, err, expected)
	}
	if gotWrites := f.store.WriteTxnCount(); gotWrites != writes {
		t.Fatalf("retry wrote to store: got=%d want=%d", gotWrites, writes)
	}
}

func assertFilenameRetryPhysicalProofUnavailable(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != http.StatusServiceUnavailable || len(result) != 2 || result["error"] != "physical_parent_proof_unavailable" || result["retryable"] != false {
		t.Fatalf("caller-scoped probes authorized release: status=%d body=%s err=%v", w.Code, w.Body, err)
	}
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unsafe failure headers: %v", w.Header())
	}
}

const retryDAVAuth = "Basic b3duZXI6c2VjcmV0"

func filenameRetryMockAPI(t *testing.T, r *http.Request, raw string) (*http.Response, bool) {
	t.Helper()
	if r.URL.Path != "/api/auth/login" && r.URL.Path != "/api/fs/list" {
		return nil, false
	}
	if r.Method != http.MethodPost || r.Header.Get("Authorizetoken") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
		t.Errorf("unsafe API request %s %s %v", r.Method, r.URL.Path, r.Header)
	}
	var payload map[string]interface{}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		t.Fatal("malformed retry API payload")
	}
	body := `{"code":200,"data":{"token":"temporary-owner-token"}}`
	if r.URL.Path == "/api/auth/login" {
		if r.Header.Get("Authorization") != "" || len(payload) != 2 || payload["username"] != "owner" || payload["password"] != "secret" {
			t.Errorf("login did not use explicit owner pair only: %v %v", payload, r.Header)
		}
	} else {
		if r.Header.Get("Authorization") != "temporary-owner-token" || len(payload) != 5 || payload["path"] != path.Dir(raw) || payload["refresh"] != true || payload["page"] != float64(1) || payload["per_page"] != float64(0) || payload["password"] != "" {
			t.Errorf("not a fresh full caller-scoped parent request: %v %v", payload, r.Header)
		}
		body = `{"code":200,"data":{"total":1,"content":[{"name":"other-existing.bin"}]}}`
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, true
}

func TestFilenameRetryReleaseDisabledByDefaultButDryRunAvailable(t *testing.T) {
	for _, value := range []string{"", "0", "true", " 1", "1 "} {
		t.Run("disabled="+value, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			t.Setenv("ALIST_FILENAME_RETRY_MAINTENANCE_ENABLE", value)
			f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				t.Error("disabled release or dry run reached upstream")
				return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
			})}
			writes := f.store.WriteTxnCount()
			w := f.post(t, f.body(nil), retryDAVAuth)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"error":"maintenance_release_disabled"`) || !strings.Contains(w.Body.String(), `"retryable":false`) {
				t.Fatalf("disabled release status=%d body=%s", w.Code, w.Body)
			}
			w = f.post(t, `{"original_path":"/limited/retry.mp4","dry_run":true}`, retryDAVAuth)
			var inspect map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &inspect); err != nil || w.Code != 200 || len(inspect) != 2 || inspect["audit_digest"] != storage.FilenameAuditDigest(f.rec) || inspect["status"] != storage.FilenameFailed {
				t.Fatalf("disabled inspection=%d %s err=%v", w.Code, w.Body, err)
			}
			f.assertRetained(t, f.rec, writes)
		})
	}
}

func TestFilenameRetryDryRunAndCanonicalAbsenceStillRetainsClaim(t *testing.T) {
	f := newFilenameRetryFixture(t)
	var methods []string
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	originURL, err := url.Parse(f.rec.Origin)
	if err != nil {
		t.Fatal(err)
	}
	jar.SetCookies(originURL, []*http.Cookie{{Name: "service-session-must-not-forward", Value: "secret", Path: "/"}})
	f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		methods = append(methods, r.Method)
		if response, handled := filenameRetryMockAPI(t, r, f.rec.EncryptedPath); handled {
			return response, nil
		}
		if r.URL.String() != f.rec.Origin+(&url.URL{Path: "/dav" + f.rec.EncryptedPath}).EscapedPath() || r.Header.Get("Authorization") != retryDAVAuth || r.Header.Get("Authorizetoken") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
			t.Errorf("wrong target or leaked credentials: %s %v", r.URL, r.Header)
		}
		if r.Method == "PROPFIND" && r.Header.Get("Depth") != "0" {
			t.Error("not a canonical depth-zero probe")
		}
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	f.h.shortClient.Jar = jar
	writes := f.store.WriteTxnCount()
	w := f.post(t, `{"original_path":"/limited/retry.mp4","dry_run":true}`, retryDAVAuth)
	var inspect map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &inspect); err != nil || w.Code != 200 || len(inspect) != 2 || inspect["audit_digest"] != storage.FilenameAuditDigest(f.rec) || inspect["status"] != storage.FilenameFailed || len(methods) != 0 {
		t.Fatalf("inspection=%d %s calls=%v err=%v", w.Code, w.Body, methods, err)
	}
	f.assertRetained(t, f.rec, writes)
	w = f.post(t, f.body(nil), retryDAVAuth)
	assertFilenameRetryPhysicalProofUnavailable(t, w)
	if !reflect.DeepEqual(methods, []string{"POST", "POST", "HEAD", "PROPFIND"}) {
		t.Fatalf("caller-scoped probes must stay ordered and never PUT/DELETE: %v", methods)
	}
	f.assertRetained(t, f.rec, writes)
}

func TestFilenameRetrySuccessfulLookingCallerScopedProbesNeverRelease(t *testing.T) {
	for _, tc := range []struct {
		name, loginBody, listBody string
	}{
		{"valid-basic-pair", "", ""},
		{"empty-full-parent-total-zero", "", `{"code":200,"data":{"total":0,"content":[]}}`},
		{"ordinary-full-parent", "", `{"code":200,"data":{"total":2,"content":[{"name":"existing.bin"},{"name":"another.bin"}]}}`},
		{"account-base-path-misleading-response", `{"code":200,"data":{"token":"temporary-owner-token","user":{"username":"owner","base_path":"/account-root"}}}`, `{"code":200,"data":{"base_path":"/account-root/limited","total":1,"content":[{"name":"account-visible-only.bin"}]}}`},
		{"filtered-virtual-navigation-listing", "", `{"code":200,"data":{"total":1,"content":[{"name":"virtual-navigation","is_dir":true}],"provider":"Virtual","filtered":true}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			originURL, err := url.Parse(f.rec.Origin)
			if err != nil {
				t.Fatal(err)
			}
			jar.SetCookies(originURL, []*http.Cookie{{Name: "service-session-must-not-forward", Value: "secret", Path: "/"}})
			var calls []string
			f.h.shortClient = &http.Client{Jar: jar, Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				if r.URL.Scheme+"://"+r.URL.Host != f.rec.Origin {
					t.Errorf("probe left configured origin: %s", r.URL)
				}
				if response, handled := filenameRetryMockAPI(t, r, f.rec.EncryptedPath); handled {
					body := tc.loginBody
					if r.URL.Path == "/api/fs/list" {
						body = tc.listBody
					}
					if body != "" {
						response.Body = io.NopCloser(strings.NewReader(body))
					}
					return response, nil
				}
				if r.Method != http.MethodHead && r.Method != "PROPFIND" {
					t.Fatalf("caller-scoped probes made a cloud mutation: %s %s", r.Method, r.URL)
				}
				if r.URL.String() != f.rec.Origin+(&url.URL{Path: "/dav" + f.rec.EncryptedPath}).EscapedPath() || r.Header.Get("Authorization") != retryDAVAuth || r.Header.Get("Authorizetoken") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Proxy-Authorization") != "" {
					t.Errorf("wrong DAV target or credential leak: %s %v", r.URL, r.Header)
				}
				if r.Method == "PROPFIND" && r.Header.Get("Depth") != "0" {
					t.Error("DAV caller-scoped probe must use canonical depth zero")
				}
				return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Header: make(http.Header)}, nil
			})}
			writes := f.store.WriteTxnCount()
			w := f.post(t, f.body(nil), retryDAVAuth)
			assertFilenameRetryPhysicalProofUnavailable(t, w)
			wantCalls := []string{"POST /api/auth/login", "POST /api/fs/list", "HEAD /dav" + f.rec.EncryptedPath, "PROPFIND /dav" + f.rec.EncryptedPath}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("unexpected caller-scoped probe order or retry: got=%v want=%v", calls, wantCalls)
			}
			f.assertRetained(t, f.rec, writes)
		})
	}
}

func TestFilenameRetryParentInventoryRejectsFalse404AndIncompleteCallerScopedProbe(t *testing.T) {
	for _, tc := range []struct {
		name, endpoint, body string
		httpStatus, want     int
	}{
		{"parent-503-false-child-404", "/api/fs/list", `{"code":200,"data":{"total":0,"content":[]}}`, 503, 503},
		{"parent-auth-denied", "/api/fs/list", `{"code":403,"data":null}`, 200, 503},
		{"parent-object-present", "/api/fs/list", "TARGET", 200, 409},
		{"parent-partial", "/api/fs/list", `{"code":200,"data":{"total":2,"content":[{"name":"other.bin"}]}}`, 200, 503},
		{"parent-null-content", "/api/fs/list", `{"code":200,"data":{"total":0,"content":null}}`, 200, 503},
		{"parent-missing-content", "/api/fs/list", `{"code":200,"data":{"total":0}}`, 200, 503},
		{"parent-null-total", "/api/fs/list", `{"code":200,"data":{"total":null,"content":[]}}`, 200, 503},
		{"parent-negative-total", "/api/fs/list", `{"code":200,"data":{"total":-1,"content":[]}}`, 200, 503},
		{"parent-float-total", "/api/fs/list", `{"code":200,"data":{"total":0.0,"content":[]}}`, 200, 503},
		{"parent-bool-total", "/api/fs/list", `{"code":200,"data":{"total":false,"content":[]}}`, 200, 503},
		{"parent-null-entry", "/api/fs/list", `{"code":200,"data":{"total":1,"content":[null]}}`, 200, 503},
		{"parent-invalid-basename", "/api/fs/list", `{"code":200,"data":{"total":1,"content":[{"name":"../other.bin"}]}}`, 200, 503},
		{"parent-empty-basename", "/api/fs/list", `{"code":200,"data":{"total":1,"content":[{"name":""}]}}`, 200, 503},
		{"parent-duplicate", "/api/fs/list", `{"code":200,"data":{"total":2,"content":[{"name":"same"},{"name":"same"}]}}`, 200, 503},
		{"parent-malformed", "/api/fs/list", `{"code":200,"data":`, 200, 503},
		{"parent-redirect", "/api/fs/list", "", 302, 503},
		{"login-denied-no-configured-fallback", "/api/auth/login", `{"code":401,"data":null}`, 200, 503},
		{"login-http-denied", "/api/auth/login", `{"code":200,"data":{"token":"bad"}}`, 401, 503},
		{"login-token-null", "/api/auth/login", `{"code":200,"data":{"token":null}}`, 200, 503},
		{"login-data-null", "/api/auth/login", `{"code":200,"data":null}`, 200, 503},
		{"login-token-empty", "/api/auth/login", `{"code":200,"data":{"token":""}}`, 200, 503},
		{"login-redirect", "/api/auth/login", "", 302, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			f.h.cfg.AlistServer.ScanUsername = "configured-admin-must-not-be-used"
			f.h.cfg.AlistServer.ScanPassword = "configured-password-must-not-be-used"
			f.h.cfg.AlistServer.ScanAuthHeader = "configured-token-must-not-be-used"
			var calls []string
			f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				response, handled := filenameRetryMockAPI(t, r, f.rec.EncryptedPath)
				if !handled {
					t.Error("failed caller-scoped parent probe reached child probe", r.Method, r.URL.Path)
					return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
				}
				if r.URL.Path == tc.endpoint {
					body := tc.body
					if body == "TARGET" {
						raw, _ := json.Marshal(map[string]interface{}{"code": 200, "data": map[string]interface{}{"total": 1, "content": []interface{}{map[string]string{"name": path.Base(f.rec.EncryptedPath)}}}})
						body = string(raw)
					}
					response.StatusCode = tc.httpStatus
					response.Body = io.NopCloser(strings.NewReader(body))
					response.Header.Set("Location", "http://foreign.invalid/steal-token")
				}
				return response, nil
			})}
			writes := f.store.WriteTxnCount()
			w := f.post(t, f.body(nil), retryDAVAuth)
			code := "parent_inventory_unavailable"
			if tc.want == 409 {
				code = "destination_present"
			}
			if w.Code != tc.want || !strings.Contains(w.Body.String(), `"error":"`+code+`"`) {
				t.Fatalf("status=%d body=%s calls=%v", w.Code, w.Body, calls)
			}
			wantCalls := []string{"POST /api/auth/login"}
			if tc.endpoint != "/api/auth/login" {
				wantCalls = append(wantCalls, "POST /api/fs/list")
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("unsafe fallback or credential retry: calls=%v", calls)
			}
			f.assertRetained(t, f.rec, writes)
		})
	}
}

func TestFilenameRetryParentInventoryRejectsOversizedResponse(t *testing.T) {
	f := newFilenameRetryFixture(t)
	f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
		response, handled := filenameRetryMockAPI(t, r, f.rec.EncryptedPath)
		if !handled {
			t.Fatal("oversized caller-scoped parent response reached DAV")
		}
		if r.URL.Path == "/api/fs/list" {
			response.Body = io.NopCloser(strings.NewReader(`{"code":200,"data":{"total":0,"content":[]},"padding":"` + strings.Repeat("x", 8*1024*1024) + `"}`))
		}
		return response, nil
	})}
	writes := f.store.WriteTxnCount()
	w := f.post(t, f.body(nil), retryDAVAuth)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"error":"parent_inventory_unavailable"`) {
		t.Fatalf("oversized response admitted: %d %s", w.Code, w.Body)
	}
	f.assertRetained(t, f.rec, writes)
}

func TestFilenameRetryFailsClosedForPresentAuthUnavailableAndTimeout(t *testing.T) {
	for _, tc := range []struct {
		name       string
		head, prop int
		err        error
		want       int
		code       string
	}{
		{"head-present", 200, 404, nil, 409, "destination_present"},
		{"prop-present", 404, 207, nil, 409, "destination_present"},
		{"head-401", 401, 404, nil, 503, "upstream_unavailable"},
		{"prop-403", 404, 403, nil, 503, "upstream_unavailable"},
		{"head-503", 503, 404, nil, 503, "upstream_unavailable"},
		{"prop-503", 404, 503, nil, 503, "upstream_unavailable"},
		{"redirect", 302, 404, nil, 503, "upstream_unavailable"},
		{"timeout", 404, 404, context.DeadlineExceeded, 504, "upstream_unavailable"},
		{"network-error", 404, 404, errors.New("network unavailable"), 503, "upstream_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				if response, handled := filenameRetryMockAPI(t, r, f.rec.EncryptedPath); handled {
					return response, nil
				}
				if r.Method != "HEAD" && r.Method != "PROPFIND" {
					t.Fatal("cloud mutation", r.Method)
				}
				if tc.err != nil {
					return nil, tc.err
				}
				status := tc.head
				if r.Method == "PROPFIND" {
					status = tc.prop
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})}
			writes := f.store.WriteTxnCount()
			w := f.post(t, f.body(nil), retryDAVAuth)
			if w.Code != tc.want || !strings.Contains(w.Body.String(), `"error":"`+tc.code+`"`) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
			f.assertRetained(t, f.rec, writes)
		})
	}
}

func TestFilenameRetryRejectsUnconfirmedStalePendingCompleteAndYoung(t *testing.T) {
	for _, tc := range []string{"unconfirmed", "stale-audit", "pending", "complete", "too-young", "future-time", "wrong-rule", "wrong-mapping", "wrong-policy", "missing-dav", "jwt-as-dav", "jwt-in-basic", "arbitrary-origin", "arbitrary-physical"} {
		t.Run(tc, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				t.Error("rejected request reached upstream")
				return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
			})}
			extra, auth, want := map[string]interface{}{}, retryDAVAuth, 409
			switch tc {
			case "unconfirmed":
				extra["maintenance_confirmed"], want = false, 400
			case "stale-audit":
				extra["audit_digest"] = strings.Repeat("0", 64)
			case "pending", "complete":
				f.rec.Status = tc
				f.save(t, f.rec)
			case "too-young":
				f.rec.UpdatedAt = time.Now().UTC()
				f.save(t, f.rec)
			case "future-time":
				f.rec.UpdatedAt = time.Now().UTC().Add(time.Hour)
				f.save(t, f.rec)
			case "wrong-rule":
				f.h.cfg.AlistServer.PasswdList[0].Password = "changed"
			case "wrong-mapping":
				f.rec.DisplayName = "not-the-current-mapping.mp4"
				f.save(t, f.rec)
			case "wrong-policy":
				f.h.cfg.AlistServer.FilenameWriteLimits = nil
			case "missing-dav":
				auth, want = "", 400
			case "jwt-as-dav":
				auth, want = "Bearer management-jwt-never-forward", 400
			case "jwt-in-basic":
				auth, want = "Basic management-jwt-never-forward", 400
			case "arbitrary-origin":
				extra["origin"], want = "http://arbitrary.invalid", 400
			case "arbitrary-physical":
				extra["encrypted_path"], want = "/arbitrary.bin", 400
			}
			writes := f.store.WriteTxnCount()
			w := f.post(t, f.body(extra), auth)
			if w.Code != want {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
			}
			f.assertRetained(t, f.rec, writes)
		})
	}
}

func TestFilenameRetryRechecksConfigRuleAndRetainsAuditChangesAfterProbes(t *testing.T) {
	for _, tc := range []string{"audit", "config-aba", "rule-without-revision", "policy-without-revision", "cancelled"} {
		t.Run(tc, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			expected := f.rec
			writes := f.store.WriteTxnCount()
			var calls []string
			f.h.shortClient = &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				calls = append(calls, r.Method+" "+r.URL.Path)
				if response, handled := filenameRetryMockAPI(t, r, f.rec.EncryptedPath); handled {
					return response, nil
				}
				if r.Method == "PROPFIND" {
					switch tc {
					case "audit":
						expected.CiphertextSize++
						f.save(t, expected)
					case "config-aba":
						// An equal-value managed update still advances the revision.
						if err := f.h.cfg.UpdateAlistServer(f.h.cfg.AlistServerSnapshot()); err != nil {
							t.Fatal(err)
						}
					case "rule-without-revision":
						f.h.cfg.AlistServer.PasswdList[0].Password = "changed"
					case "policy-without-revision":
						f.h.cfg.AlistServer.FilenameWriteLimits = nil
					case "cancelled":
						cancel()
					}
				}
				return &http.Response{StatusCode: 404, Body: http.NoBody}, nil
			})}
			r := httptest.NewRequest(http.MethodPost, "/enc-api/retryFilename", strings.NewReader(f.body(nil))).WithContext(ctx)
			r.Header.Set("Authorization", retryDAVAuth)
			w := httptest.NewRecorder()
			f.h.HandleRetryFilename(w, r)
			if tc == "audit" {
				// There is no final audit/release CAS: the mandatory safety gate
				// rejects release without overwriting this concurrent audit update.
				assertFilenameRetryPhysicalProofUnavailable(t, w)
				writes++ // Only the deliberate concurrent audit update may write.
				if expected.CiphertextSize != f.rec.CiphertextSize+1 || storage.FilenameAuditDigest(expected) == storage.FilenameAuditDigest(f.rec) {
					t.Fatal("concurrent audit change was not exercised")
				}
			} else if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"error":"filename_mapping_changed"`) || !strings.Contains(w.Body.String(), `"retryable":false`) {
				t.Fatalf("stale rule/config or cancellation not rejected: %d %s", w.Code, w.Body)
			}
			wantCalls := []string{"POST /api/auth/login", "POST /api/fs/list", "HEAD /dav" + f.rec.EncryptedPath, "PROPFIND /dav" + f.rec.EncryptedPath}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("post-probe change was not exercised in order: got=%v want=%v", calls, wantCalls)
			}
			f.assertRetained(t, expected, writes)
		})
	}
}

func TestFilenameWriteStructuredConflictsAndConservativeDefault(t *testing.T) {
	for _, tc := range []struct {
		name, reservation string
		remote            int
		want              int
		code              string
	}{
		{"failed", storage.FilenameFailed, 404, 409, "reserved_failed"},
		{"pending", storage.FilenamePending, 404, 409, "reserved_pending"},
		{"complete", storage.FilenameComplete, 404, 409, "reserved_complete"},
		{"physical-present", "", 200, 409, "destination_present"},
		{"unauthorized", "", 401, 503, "upstream_unavailable"},
		{"unavailable", "", 503, 503, "upstream_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFilenameRetryFixture(t)
			if tc.reservation == "" {
				if err := f.d.ReleaseFailedFilename(f.rec); err != nil {
					t.Fatal(err)
				}
			} else {
				f.rec.Status = tc.reservation
				f.save(t, f.rec)
			}
			calls := 0
			client := &http.Client{Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "HEAD" {
					t.Fatal("failed preflight made mutation", r.Method)
				}
				return &http.Response{StatusCode: tc.remote, Body: http.NoBody}, nil
			})}
			r := httptest.NewRequest(http.MethodPut, "/dav"+f.rec.OriginalPath, nil)
			_, _, err := prepareFilenameWrite(f.h.cfg, f.d, r, f.ep, f.rec.OriginalPath, f.rec.EncryptedPath, 100, false, client)
			if err == nil {
				t.Fatal("unsafe write admitted")
			}
			w := httptest.NewRecorder()
			respondFilenameWriteError(w, err)
			if w.Code != tc.want || !strings.Contains(w.Body.String(), `"error":"`+tc.code+`"`) || !strings.Contains(w.Body.String(), `"retryable":false`) {
				t.Fatalf("wrong structured failure: %d %s", w.Code, w.Body)
			}
			if tc.reservation != "" && calls != 0 {
				t.Fatal("reserved path retried upstream")
			}
		})
	}
}
