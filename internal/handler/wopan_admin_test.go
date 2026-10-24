package handler

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/storage"
	"github.com/alist-encrypt-go/internal/wopan"
	"github.com/golang-jwt/jwt/v5"
)

const (
	wopanTestAccess  = "mock-access-private-1234567890"
	wopanTestRefresh = "mock-refresh-private-1234567890"
	wopanTestScan    = "mock-upstream-admin-private-12345"
	wopanTestID      = "private-account-identity-12345"
)

// All provider calls, especially EmptyRecycle, are mocked. This fixture never
// instantiates or invokes a real provider client after construction.
type wopanMockProvider struct {
	mu                        sync.Mutex
	accountID                 string
	quota                     wopan.Quota
	accountErr, quotaErr      error
	clearErr                  error
	accountCalls, quotaCalls  int
	clearCalls                int
	accesses                  []string
	clearStarted, clearFinish chan struct{}
	accountHook               func()
}

func (p *wopanMockProvider) Account(ctx context.Context, access string) (wopan.Account, error) {
	p.mu.Lock()
	p.accountCalls++
	p.accesses = append(p.accesses, access)
	id, err, hook := p.accountID, p.accountErr, p.accountHook
	p.mu.Unlock()
	if hook != nil {
		hook()
	}
	return wopan.Account{ID: id}, err
}
func (p *wopanMockProvider) Quota(ctx context.Context, access, accountID string) (wopan.Quota, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.quotaCalls++
	p.accesses = append(p.accesses, access)
	if accountID != p.accountID {
		return wopan.Quota{}, errors.New("mock identity mismatch")
	}
	return p.quota, p.quotaErr
}
func (p *wopanMockProvider) EmptyRecycle(ctx context.Context, access string) error {
	p.mu.Lock()
	p.clearCalls++
	p.accesses = append(p.accesses, access)
	err, started, finish := p.clearErr, p.clearStarted, p.clearFinish
	p.mu.Unlock()
	if started != nil {
		close(started)
	}
	if finish != nil {
		select {
		case <-finish:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}
func (p *wopanMockProvider) counts() (int, int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accountCalls, p.quotaCalls, p.clearCalls
}

type wopanMockUpstream struct {
	t          *testing.T
	mu         sync.Mutex
	storages   map[int]wopanStorage
	role       int
	requests   []string
	auths      []string
	loginCount int
	password   string
	username   string
	meBody     string
	getBody    string
	listBody   string
	redirect   string
	fail       bool
	pageSize   int
	listTotal  int
}

func wopanMockAddition(access, family string) string {
	encoded, _ := json.Marshal(wopanAddition{AccessToken: access, RefreshToken: wopanTestRefresh, FamilyID: family, RootFolderID: "0"})
	return string(encoded)
}
func wopanMockStorage(id int) wopanStorage {
	return wopanStorage{ID: id, MountPath: "/any-personal-mount", Driver: "WoPan", Status: "work", Addition: wopanMockAddition(wopanTestAccess, "")}
}
func (u *wopanMockUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.requests = append(u.requests, r.URL.RequestURI())
	u.auths = append(u.auths, r.Header.Get("Authorization"))
	if r.Method != http.MethodGet && r.URL.Path != "/api/auth/login" {
		u.t.Errorf("unexpected upstream mutation %s %s", r.Method, r.URL.Path)
		w.WriteHeader(500)
		return
	}
	if r.Header.Get("Authorizetoken") != "" || r.Header.Get("Cookie") != "" {
		u.t.Error("browser authentication forwarded upstream")
	}
	w.Header().Set("Content-Type", "application/json")
	if u.redirect != "" {
		http.Redirect(w, r, u.redirect, http.StatusFound)
		return
	}
	if u.fail {
		w.WriteHeader(500)
		fmt.Fprint(w, wopanTestAccess+" "+wopanTestRefresh)
		return
	}
	if r.URL.Path == "/api/auth/login" {
		u.loginCount++
		var credentials map[string]string
		if json.NewDecoder(r.Body).Decode(&credentials) != nil {
			u.t.Error("invalid login body")
		}
		if credentials["username"] != u.username || credentials["password"] != u.password {
			u.t.Error("nonconfigured credentials sent")
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": map[string]string{"token": wopanTestScan}})
		return
	}
	if r.Header.Get("Authorization") != wopanTestScan {
		u.t.Errorf("unexpected upstream authorization: length=%d", len(r.Header.Get("Authorization")))
	}
	var data interface{}
	switch r.URL.Path {
	case "/api/me":
		if u.meBody != "" {
			fmt.Fprint(w, u.meBody)
			return
		}
		data = map[string]int{"role": u.role}
	case "/api/admin/storage/get":
		if u.getBody != "" {
			fmt.Fprint(w, u.getBody)
			return
		}
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		data = u.storages[id]
	case "/api/admin/storage/list":
		if u.listBody != "" {
			fmt.Fprint(w, u.listBody)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 || r.URL.Query().Get("per_page") != "100" {
			u.t.Error("unbounded or malformed pagination")
		}
		keys := make([]int, 0, len(u.storages))
		for id := range u.storages {
			keys = append(keys, id)
		}
		sort.Ints(keys)
		size := u.pageSize
		if size == 0 {
			size = 100
		}
		start := (page - 1) * size
		if start > len(keys) {
			start = len(keys)
		}
		end := start + size
		if end > len(keys) {
			end = len(keys)
		}
		content := make([]wopanStorage, 0)
		for _, id := range keys[start:end] {
			entry := u.storages[id]
			entry.Addition = "" // Privacy-hidden list; raw get is required.
			content = append(content, entry)
		}
		total := len(keys)
		if u.listTotal != 0 {
			total = u.listTotal
		}
		data = map[string]interface{}{"content": content, "total": total}
	default:
		u.t.Errorf("unexpected endpoint %s", r.URL.Path)
		w.WriteHeader(404)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"code": 200, "data": data})
}
func (u *wopanMockUpstream) change(fn func()) { u.mu.Lock(); defer u.mu.Unlock(); fn() }
func (u *wopanMockUpstream) requestCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

type wopanFixture struct {
	h        *WopanAdminHandler
	cfg      *config.Config
	users    *dao.UserDAO
	upstream *wopanMockUpstream
	provider *wopanMockProvider
	jwt      string
}

func newWopanFixture(t *testing.T) *wopanFixture {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	// Authentication tests don't need Argon2 or a generated production account.
	if err := store.SetJSON(storage.BucketUsers, "admin", dao.User{Username: "admin", PasswordHash: "unused-fixture"}); err != nil {
		t.Fatal(err)
	}
	upstream := &wopanMockUpstream{t: t, role: 2, storages: map[int]wopanStorage{27: wopanMockStorage(27)}}
	mock := httptest.NewServer(upstream)
	t.Cleanup(mock.Close)
	origin, err := url.Parse(mock.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(origin.Port())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.JWTSecret = "local-test-jwt-secret"
	cfg.AlistServer.ServerHost, cfg.AlistServer.ServerPort, cfg.AlistServer.HTTPS = origin.Hostname(), port, false
	cfg.AlistServer.ScanAuthHeader = wopanTestScan
	users := dao.NewUserDAO(store)
	h := NewWopanAdminHandler(cfg, users)
	provider := &wopanMockProvider{accountID: wopanTestID, quota: wopan.Quota{TotalBytes: 9007199254740993, UsedBytes: 123, AvailableBytes: 9007199254740870}}
	h.provider = provider
	h.now = func() time.Time { return time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC) }
	token, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("admin")
	if err != nil {
		t.Fatal(err)
	}
	return &wopanFixture{h, cfg, users, upstream, provider, token}
}

func (f *wopanFixture) request(method, path, token, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://manager.test"+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorizetoken", token)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		if value == "" {
			req.Header.Del(key)
		} else {
			req.Header.Set(key, value)
		}
	}
	rr := httptest.NewRecorder()
	switch req.URL.Path {
	case "/enc-api/wopan/storages":
		f.h.Storages(rr, req)
	case "/enc-api/wopan/quota":
		f.h.Quota(rr, req)
	case "/enc-api/wopan/automation":
		if method == http.MethodGet {
			f.h.GetAutomation(rr, req)
		} else {
			f.h.SaveAutomation(rr, req)
		}
	case "/enc-api/wopan/recycle/prepare":
		f.h.PrepareRecycle(rr, req)
	case "/enc-api/wopan/recycle/clear":
		f.h.ClearRecycle(rr, req)
	}
	return rr
}
func wopanResponseData(t *testing.T, rr *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var response struct {
		Code int                        `json:"code"`
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if rr.Code != 200 || response.Code != 0 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	return response.Data
}
func (f *wopanFixture) prepare(t *testing.T) string {
	t.Helper()
	rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, nil)
	data := wopanResponseData(t, rr)
	var token string
	if err := json.Unmarshal(data["confirmation_token"], &token); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		t.Fatal("confirmation is not a 256-bit nonce")
	}
	if string(data["scope"]) != `"personal_account"` || string(data["confirmation_phrase"]) != `"清空个人账号全部回收站"` || string(data["warning"]) != `"不可恢复；清空整个个人账号回收站，不仅当前挂载目录"` {
		t.Fatal(rr.Body.String())
	}
	var expiry string
	json.Unmarshal(data["expires_at"], &expiry)
	parsed, err := time.Parse(time.RFC3339, expiry)
	if err != nil || parsed.Sub(f.h.now()) != wopanChallengeTTL {
		t.Fatal("incorrect expiry")
	}
	return token
}
func wopanClearBody(token, phrase string, id int) string {
	body, _ := json.Marshal(wopanClearRequest{id, token, phrase})
	return string(body)
}
func wopanAssertPrivate(t *testing.T, rr *httptest.ResponseRecorder, secrets ...string) {
	t.Helper()
	for _, secret := range append(secrets, wopanTestAccess, wopanTestRefresh, wopanTestScan, wopanTestID) {
		if secret != "" && strings.Contains(rr.Body.String(), secret) {
			t.Fatal("response leaked private data")
		}
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("management response is cacheable")
	}
}

func TestWopanAdminLocalAuthenticationAllOperations(t *testing.T) {
	operations := []struct{ method, path, body string }{
		{http.MethodGet, "/enc-api/wopan/storages", ""},
		{http.MethodGet, "/enc-api/wopan/quota?storage_id=27", ""},
		{http.MethodPost, "/enc-api/wopan/recycle/prepare", `{"storage_id":27}`},
		{http.MethodPost, "/enc-api/wopan/recycle/clear", wopanClearBody("missing", wopanConfirmationPhrase, 27)},
	}
	for _, operation := range operations {
		t.Run(operation.path, func(t *testing.T) {
			f := newWopanFixture(t)
			unknown, err := f.h.jwtAuth.GenerateToken("deleted-admin")
			if err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{"", "invalid", "Basic YWRtaW46cGFzcw==", unknown} {
				rr := f.request(operation.method, operation.path, token, operation.body, nil)
				want := 401
				if token == unknown {
					want = 403
				}
				if rr.Code != want {
					t.Fatalf("status=%d expected=%d", rr.Code, want)
				}
				wopanAssertPrivate(t, rr, token)
			}
			query := "?"
			if strings.Contains(operation.path, "?") {
				query = "&"
			}
			if rr := f.request(operation.method, operation.path+query+"token="+f.jwt, "", operation.body, nil); rr.Code != 401 {
				t.Fatalf("query token accepted: %d", rr.Code)
			}
			if f.upstream.requestCount() != 0 {
				t.Fatal("unauthenticated operation contacted upstream")
			}
			if err := f.users.Delete("admin"); err != nil {
				t.Fatal(err)
			}
			if rr := f.request(operation.method, operation.path, f.jwt, operation.body, nil); rr.Code != 403 {
				t.Fatal("deleted current user accepted")
			}
		})
	}
}

func TestWopanAdminHeaderAndConfiguredUpstreamSessions(t *testing.T) {
	for _, header := range []map[string]string{{"Authorizetoken": "", "Authorization": "Bearer "}, {"Authorizetoken": "", "Authorization": ""}, nil} {
		f := newWopanFixture(t)
		if header != nil {
			header["Authorization"] += f.jwt
		}
		rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", header)
		if rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
		wopanAssertPrivate(t, rr, f.jwt)
		f.upstream.mu.Lock()
		for _, actual := range f.upstream.auths {
			if actual != wopanTestScan {
				t.Error("local JWT forwarded")
			}
		}
		f.upstream.mu.Unlock()
	}
	for _, raw := range []string{"", "Basic YW55OmNyZWRlbnRpYWxz"} {
		f := newWopanFixture(t)
		f.cfg.AlistServer.ScanAuthHeader = raw
		f.cfg.AlistServer.ScanUsername, f.cfg.AlistServer.ScanPassword = "configured-scan-user", "configured-private-password"
		f.upstream.username, f.upstream.password = f.cfg.AlistServer.ScanUsername, f.cfg.AlistServer.ScanPassword
		for i := 0; i < 2; i++ {
			rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", map[string]string{"Cookie": "browser-private-cookie", "Authorization": "browser-upstream-injection"})
			if rr.Code != 200 {
				t.Fatal(rr.Body.String())
			}
			wopanAssertPrivate(t, rr, f.cfg.AlistServer.ScanPassword, f.jwt)
		}
		if f.upstream.loginCount != 2 {
			t.Fatal("operations unexpectedly reused session")
		}
	}
	f := newWopanFixture(t)
	f.cfg.AlistServer.ScanAuthHeader = "Basic YW55OmNyZWRlbnRpYWxz"
	if rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", nil); rr.Code != 403 || f.upstream.requestCount() != 0 {
		t.Fatal("Basic-only upstream session accepted")
	}
	f.cfg.AlistServer.ScanAuthHeader = f.jwt
	if rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", nil); rr.Code != 403 || f.upstream.requestCount() != 0 {
		t.Fatal("local JWT used upstream")
	}
}

func TestWopanAdminRequiresUpstreamAdminEveryOperation(t *testing.T) {
	for _, role := range []int{0, 1, 3} {
		f := newWopanFixture(t)
		f.upstream.role = role
		for _, op := range []struct{ method, path, body string }{
			{http.MethodGet, "/enc-api/wopan/storages", ""},
			{http.MethodGet, "/enc-api/wopan/quota?storage_id=27", ""},
			{http.MethodPost, "/enc-api/wopan/recycle/prepare", `{"storage_id":27}`},
		} {
			if rr := f.request(op.method, op.path, f.jwt, op.body, nil); rr.Code != 403 {
				t.Fatalf("role=%d status=%d", role, rr.Code)
			}
		}
		if accounts, quotas, clears := f.provider.counts(); accounts+quotas+clears != 0 {
			t.Fatal("reader reached provider")
		}
	}
	f := newWopanFixture(t)
	token := f.prepare(t)
	f.upstream.change(func() { f.upstream.role = 0 })
	body := wopanClearBody(token, wopanConfirmationPhrase, 27)
	if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, body, nil); rr.Code != 403 {
		t.Fatal(rr.Body.String())
	}
	f.upstream.change(func() { f.upstream.role = 2 })
	if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, body, nil); rr.Code != 409 {
		t.Fatal("failed authorization did not consume confirmation")
	}
	if _, _, clears := f.provider.counts(); clears != 0 {
		t.Fatal("reader cleared provider")
	}
}

func TestWopanAdminStrictMutationJSONAndOrigin(t *testing.T) {
	f := newWopanFixture(t)
	for _, body := range []string{
		``, `{`, `null`, `[]`, `{}`, `{"storage_id":0}`, `{"storage_id":-1}`, `{"storage_id":"27"}`, `{"storage_id":27.0}`, `{"storage_id":null}`,
		`{"storage_id":27,"storage_id":28}`, `{"storage_id":27,"Storage_ID":27}`, `{"storage_id":27,"url":"https://attacker.invalid"}`,
		`{"storage_id":27,"credentials":"injected"}`, `{"storage_id":27} {}`, `{"storage_id":27} false`, strings.Repeat(" ", 4097) + `{"storage_id":27}`,
	} {
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, body, nil); rr.Code != 400 {
			t.Fatalf("body=%q status=%d", body, rr.Code)
		}
	}
	for _, contentType := range []string{"", "text/plain", "application/jsonx", "application/json; broken"} {
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, map[string]string{"Content-Type": contentType}); rr.Code != 415 {
			t.Fatalf("content-type=%q status=%d", contentType, rr.Code)
		}
	}
	for _, origin := range []string{"https://manager.test", "http://evil.test", "null", "HTTP://manager.test", "http://manager.test/", "http://manager.test?", "http://manager.test#", "http://user@manager.test", "http://manager.test:80"} {
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, map[string]string{"Origin": origin, "X-Forwarded-Proto": "https"}); rr.Code != 403 {
			t.Fatalf("origin=%q status=%d", origin, rr.Code)
		}
	}
	for _, site := range []string{"cross-site", "same-site", "cross-origin"} {
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, map[string]string{"Sec-Fetch-Site": site}); rr.Code != 403 {
			t.Fatalf("site=%q accepted", site)
		}
	}
	if f.upstream.requestCount() != 0 {
		t.Fatal("invalid mutation contacted upstream")
	}
	for _, headers := range []map[string]string{nil, {"Origin": "http://manager.test", "Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none", "Content-Type": "application/json; charset=utf-8"}} {
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, headers); rr.Code != 200 {
			t.Fatal(rr.Body.String())
		}
	}
	// TLS, rather than a spoofable forwarded header, determines browser origin.
	r := httptest.NewRequest(http.MethodPost, "https://manager.test/enc-api/wopan/recycle/prepare", strings.NewReader(`{"storage_id":27}`))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "http://manager.test")
	if wopanCSRF(r) == nil {
		t.Fatal("TLS request accepted http origin")
	}
	r.Header.Set("Origin", "https://manager.test")
	if err := wopanCSRF(r); err != nil {
		t.Fatal(err)
	}
	r.Header.Add("Origin", "https://manager.test")
	if wopanCSRF(r) == nil {
		t.Fatal("duplicate Origin accepted")
	}
	for _, body := range []string{`{"storage_id":27}`, `{"storage_id":27,"confirmation_token":"x","confirmation_token":"y","confirmation_phrase":"x"}`, `{"storage_id":27,"confirmation_token":"x","confirmation_phrase":"x","url":"http://attacker.invalid"}`} {
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, body, nil); rr.Code != 400 {
			t.Fatal("ambiguous clear accepted")
		}
	}
}

func TestWopanAdminStoragesDiscoveryAndPersonalValidation(t *testing.T) {
	f := newWopanFixture(t)
	family, disabled, other, broken := wopanMockStorage(28), wopanMockStorage(29), wopanMockStorage(30), wopanMockStorage(31)
	family.Addition, disabled.Disabled, other.Driver, broken.Addition = wopanMockAddition(wopanTestAccess, "family-private-id"), true, "OtherDriver", `{"access_token":"masked"}`
	f.upstream.storages[28], f.upstream.storages[29], f.upstream.storages[30], f.upstream.storages[31] = family, disabled, other, broken
	f.upstream.pageSize = 2
	rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", nil)
	data := wopanResponseData(t, rr)
	var views []wopanStorageView
	if err := json.Unmarshal(data["storages"], &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 4 || !views[0].Available || views[0].StorageID != 27 || views[0].Scope != "personal" || !views[0].ClearSupported {
		t.Fatal(rr.Body.String())
	}
	if views[1].Scope != "family" || views[1].Available || views[1].ClearSupported || views[1].UnsupportedReason != "family_not_supported" || views[2].Available || views[3].Available {
		t.Fatal(rr.Body.String())
	}
	wopanAssertPrivate(t, rr, "family-private-id", "addition", f.cfg.GetAlistURL(), f.jwt)
	for _, id := range []int{28, 29, 30, 31, 99} {
		if rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id="+strconv.Itoa(id), f.jwt, "", nil); rr.Code != 409 {
			t.Fatalf("id=%d status=%d", id, rr.Code)
		}
		if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, fmt.Sprintf(`{"storage_id":%d}`, id), nil); rr.Code != 409 {
			t.Fatalf("prepare id=%d status=%d", id, rr.Code)
		}
	}
	if accounts, quotas, clears := f.provider.counts(); accounts+quotas+clears != 0 {
		t.Fatal("unsupported storage reached provider")
	}
	for _, alter := range []func(*wopanStorage){
		func(s *wopanStorage) { s.Status = "working" },
		func(s *wopanStorage) { s.Addition = wopanMockAddition("***hidden***", "") },
		func(s *wopanStorage) {
			s.Addition = `{"family_id":"family-private","family_id":"","access_token":"` + wopanTestAccess + `","refresh_token":"` + wopanTestRefresh + `"}`
		},
		func(s *wopanStorage) {
			s.Addition = `{"access_token":"` + wopanTestAccess + `","refresh_token":"short"}`
		},
		func(s *wopanStorage) { s.Addition = "null" },
	} {
		storage := wopanMockStorage(27)
		alter(&storage)
		f.upstream.storages[27] = storage
		if rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", nil); rr.Code != 409 {
			t.Fatal(rr.Body.String())
		}
	}
}

func TestWopanAdminQuotaExactStringsUnknownRecycleAndFailure(t *testing.T) {
	f := newWopanFixture(t)
	rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", nil)
	data := wopanResponseData(t, rr)
	for key, expected := range map[string]string{"total_bytes": `"9007199254740993"`, "used_bytes": `"123"`, "available_bytes": `"9007199254740870"`, "recycle_bin_bytes": `null`, "scope": `"personal"`, "checked_at": `"2026-10-24T12:00:00Z"`} {
		if string(data[key]) != expected {
			t.Fatalf("%s=%s", key, data[key])
		}
	}
	wopanAssertPrivate(t, rr, f.jwt, f.cfg.GetAlistURL(), "account_id", "addition")
	f.provider.quotaErr = errors.New(wopanTestAccess + " https://secret.invalid/" + wopanTestRefresh)
	rr = f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", nil)
	if rr.Code != 502 || strings.Contains(rr.Body.String(), "total_bytes") {
		t.Fatal("quota error became cached quota or fabricated zero")
	}
	wopanAssertPrivate(t, rr, "secret.invalid")
	f.provider.quotaErr = nil
	for _, quota := range []wopan.Quota{{}, {TotalBytes: -1}, {TotalBytes: 100, UsedBytes: 101, AvailableBytes: -1}, {TotalBytes: 100, UsedBytes: -1, AvailableBytes: 101}, {TotalBytes: 100, UsedBytes: 10, AvailableBytes: 0}} {
		f.provider.quota = quota
		if rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", nil); rr.Code != 502 {
			t.Fatal("invalid quota accepted")
		}
	}
	f.provider.quota = wopan.Quota{TotalBytes: 100, UsedBytes: 0, AvailableBytes: 100}
	if rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", nil); rr.Code != 200 {
		t.Fatal("valid empty quota rejected")
	}
	for _, query := range []string{"", "storage_id=0", "storage_id=-1", "storage_id=27&storage_id=27", "storage_id=x", "storage_id=1.5"} {
		if rr := f.request(http.MethodGet, "/enc-api/wopan/quota?"+query, f.jwt, "", nil); rr.Code != 400 {
			t.Fatal("ambiguous quota id accepted")
		}
	}
}

func TestWopanAdminChallengeBindingsAndSingleUse(t *testing.T) {
	for _, name := range []string{"missing", "expired", "wrong_phrase", "wrong_storage", "wrong_session", "account_rotation", "credential_rotation", "refresh_rotation", "mount_change", "root_change", "family_change", "disabled", "driver_change", "status_change", "config_change", "account_failure", "upstream_failure", "user_removed", "restart"} {
		t.Run(name, func(t *testing.T) {
			f := newWopanFixture(t)
			token := f.prepare(t)
			id, phrase, jwtToken := 27, wopanConfirmationPhrase, f.jwt
			expected := 409
			switch name {
			case "missing":
				token = "missing"
			case "expired":
				f.h.now = func() time.Time { return time.Date(2026, 10, 24, 12, 2, 0, 0, time.UTC) }
			case "wrong_phrase":
				phrase, expected = "清空", 400
			case "wrong_storage":
				id = 28
			case "wrong_session":
				var err error
				jwtToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, auth.Claims{Username: "admin", RegisteredClaims: jwt.RegisteredClaims{ID: "different-session", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}).SignedString([]byte(f.cfg.JWTSecret))
				if err != nil {
					t.Fatal(err)
				}
			case "account_rotation":
				f.provider.accountID = "new-private-account"
			case "credential_rotation":
				s := f.upstream.storages[27]
				s.Addition = wopanMockAddition("rotated-access-private-12345678", "")
				f.upstream.storages[27] = s
			case "refresh_rotation":
				s := f.upstream.storages[27]
				s.Addition = strings.Replace(s.Addition, wopanTestRefresh, "rotated-refresh-private-12345678", 1)
				f.upstream.storages[27] = s
			case "mount_change":
				s := f.upstream.storages[27]
				s.MountPath = "/changed"
				f.upstream.storages[27] = s
			case "root_change":
				s := f.upstream.storages[27]
				s.Addition = strings.Replace(s.Addition, `"root_folder_id":"0"`, `"root_folder_id":"changed"`, 1)
				f.upstream.storages[27] = s
			case "family_change":
				s := f.upstream.storages[27]
				s.Addition = wopanMockAddition(wopanTestAccess, "family")
				f.upstream.storages[27] = s
			case "disabled":
				s := f.upstream.storages[27]
				s.Disabled = true
				f.upstream.storages[27] = s
			case "driver_change":
				s := f.upstream.storages[27]
				s.Driver = "Other"
				f.upstream.storages[27] = s
			case "status_change":
				s := f.upstream.storages[27]
				s.Status = "error"
				f.upstream.storages[27] = s
			case "config_change":
				f.cfg.AlistServer.ScanUsername = "configuration-change"
			case "account_failure":
				f.provider.accountErr, expected = errors.New(wopanTestAccess), 502
			case "upstream_failure":
				f.upstream.fail, expected = true, 502
			case "user_removed":
				if err := f.users.Delete("admin"); err != nil {
					t.Fatal(err)
				}
				expected = 403
			case "restart":
				f.h.pending = make(map[[32]byte]wopanChallenge)
			}
			body := wopanClearBody(token, phrase, id)
			rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", jwtToken, body, nil)
			if rr.Code != expected {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, expected, rr.Body.String())
			}
			wopanAssertPrivate(t, rr, token, jwtToken)
			if _, _, clears := f.provider.counts(); clears != 0 {
				t.Fatal("invalid confirmation reached provider clear")
			}
			if name != "user_removed" {
				rr = f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, wopanClearBody(token, wopanConfirmationPhrase, 27), nil)
				if rr.Code != 409 {
					t.Fatal("failed clear confirmation remained reusable")
				}
			}
		})
	}
}

func TestWopanAdminClearAcceptedNotCapacityOrEmptyClaim(t *testing.T) {
	f := newWopanFixture(t)
	token := f.prepare(t)
	body := wopanClearBody(token, wopanConfirmationPhrase, 27)
	rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, body, map[string]string{"Origin": "http://manager.test"})
	data := wopanResponseData(t, rr)
	if string(data["status"]) != `"accepted"` || string(data["message"]) != `"清空请求已成功提交；容量回收可能延迟"` || len(data) != 4 {
		t.Fatal(rr.Body.String())
	}
	if accounts, quotas, clears := f.provider.counts(); accounts != 2 || quotas != 0 || clears != 1 {
		t.Fatalf("accounts=%d quota=%d clears=%d", accounts, quotas, clears)
	}
	if f.upstream.requestCount() != 4 {
		t.Fatal("upstream admin and raw storage not reverified on clear")
	}
	wopanAssertPrivate(t, rr, token, f.jwt)
	if rr = f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, body, nil); rr.Code != 409 {
		t.Fatal("replay accepted")
	}
	for _, access := range f.provider.accesses {
		if access != wopanTestAccess {
			t.Fatal("provider received nonaccess credential")
		}
	}
}

func TestWopanAdminConcurrentClearExactlyOneAttemptEvenOnFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			f := newWopanFixture(t)
			first, second := f.prepare(t), f.prepare(t)
			f.provider.clearStarted, f.provider.clearFinish = make(chan struct{}), make(chan struct{})
			if fail {
				f.provider.clearErr = errors.New("private " + wopanTestAccess)
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, wopanClearBody(first, wopanConfirmationPhrase, 27), nil)
			}()
			select {
			case <-f.provider.clearStarted:
			case <-time.After(3 * time.Second):
				t.Fatal("mock clear not reached")
			}
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, wopanClearBody(first, wopanConfirmationPhrase, 27), nil)
					if rr.Code != 409 {
						t.Errorf("parallel replay status=%d", rr.Code)
					}
				}()
			}
			wg.Wait()
			rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, wopanClearBody(second, wopanConfirmationPhrase, 27), nil)
			if rr.Code != 409 || !strings.Contains(rr.Body.String(), "clear_in_progress") {
				t.Fatal(rr.Body.String())
			}
			close(f.provider.clearFinish)
			rr = <-done
			want := 200
			if fail {
				want = 502
			}
			if rr.Code != want {
				t.Fatal(rr.Body.String())
			}
			if fail && !strings.Contains(rr.Body.String(), "clear_outcome_unknown") {
				t.Fatal("failure claimed known outcome")
			}
			wopanAssertPrivate(t, rr, first, second)
			for _, token := range []string{first, second} {
				if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, wopanClearBody(token, wopanConfirmationPhrase, 27), nil); rr.Code != 409 {
					t.Fatal("parallel failure token reusable")
				}
			}
			if _, _, clears := f.provider.counts(); clears != 1 {
				t.Fatalf("clear calls=%d", clears)
			}
		})
	}
}

func TestWopanAdminBoundedStateAndConfigChangesDuringProviderRead(t *testing.T) {
	f := newWopanFixture(t)
	for i := 0; i < wopanStateLimit; i++ {
		f.h.pending[sha256.Sum256([]byte(strconv.Itoa(i)))] = wopanChallenge{expires: f.h.now().Add(time.Minute)}
	}
	if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/prepare", f.jwt, `{"storage_id":27}`, nil); rr.Code != 429 {
		t.Fatal("unbounded challenge state")
	}
	f.h.now = func() time.Time { return time.Date(2026, 10, 24, 12, 1, 0, 0, time.UTC) }
	f.prepare(t)
	if len(f.h.pending) != 1 {
		t.Fatal("expired challenges not pruned")
	}
	f.provider.accountHook = func() { f.cfg.AlistServer.ScanPassword = "changed-at-provider-read" }
	if rr := f.request(http.MethodGet, "/enc-api/wopan/quota?storage_id=27", f.jwt, "", nil); rr.Code != 409 {
		t.Fatal("quota published across config change")
	}
	f.provider.accountHook = nil
	token := f.prepare(t)
	f.provider.accountHook = func() { f.cfg.AlistServer.ScanPassword = "changed-again-at-clear-account-check" }
	if rr := f.request(http.MethodPost, "/enc-api/wopan/recycle/clear", f.jwt, wopanClearBody(token, wopanConfirmationPhrase, 27), nil); rr.Code != 409 {
		t.Fatal("clear submitted across config change")
	}
	if _, _, clears := f.provider.counts(); clears != 0 {
		t.Fatal("changed config reached clear")
	}
}

func TestWopanAdminUpstreamFailuresBoundedAndNoRedirect(t *testing.T) {
	var externalCalls atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { externalCalls.Add(1); w.WriteHeader(500) }))
	defer external.Close()
	f := newWopanFixture(t)
	f.upstream.redirect = external.URL
	rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", nil)
	if rr.Code != 502 || externalCalls.Load() != 0 {
		t.Fatal("upstream redirect followed")
	}
	wopanAssertPrivate(t, rr, external.URL)
	f.upstream.redirect = ""
	for _, body := range []string{`{"code":200,"data":{"role":2,"role":0}}`, `{"code":200,"data":{"role":2},"code":500}`, `{"code":200,"data":{"role":2}} {}`, `{"code":200,"data":{"role":2,"error":"` + strings.Repeat("x", wopanUpstreamBodyLimit) + `"}}`, `{"code":401,"data":{"role":2},"message":"` + wopanTestAccess + `"}`} {
		f.upstream.meBody = body
		rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", nil)
		if rr.Code != 502 {
			t.Fatal("invalid or oversized upstream response accepted")
		}
		wopanAssertPrivate(t, rr)
	}
	f.upstream.meBody = ""
	for _, body := range []string{`{"code":200,"data":{"content":[],"total":1001}}`, `{"code":200,"data":{"content":[],"total":1}}`, `{"code":200,"data":{"content":[]}}`} {
		f.upstream.listBody = body
		if rr := f.request(http.MethodGet, "/enc-api/wopan/storages", f.jwt, "", nil); rr.Code != 502 {
			t.Fatal("incomplete or unbounded storage list accepted")
		}
	}
	if f.h.upstream.Timeout > 15*time.Second || f.h.upstream.Timeout <= 0 {
		t.Fatal("unbounded management timeout")
	}
}
