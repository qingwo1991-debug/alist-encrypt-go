package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

type interestTestFiles map[string]*dao.FileInfo

func (f interestTestFiles) Get(p string) (*dao.FileInfo, bool) { v, ok := f[p]; return v, ok }

type interestTestScheduler struct {
	advanceCalls, enqueueCalls int
	err, errorEnqueue          error
	scope, provider            string
	generation                 uint64
	target                     string
	kinds                      []handler.WarmKind
	headers                    []http.Header
	configs                    []config.AlistServer
	advanceHook                func()
}

func (s *interestTestScheduler) AdvancePlaybackInterest(scope, session, provider string, generation uint64, target string) (bool, error) {
	s.advanceCalls++
	s.scope = scope
	s.provider = provider
	if s.advanceHook != nil {
		s.advanceHook()
	}
	if s.err != nil {
		return false, s.err
	}
	if generation < s.generation {
		return false, handler.ErrPlaybackInterestStale
	}
	if generation == s.generation && target != s.target {
		return false, handler.ErrPlaybackInterestInvalid
	}
	advanced := generation > s.generation
	s.generation = generation
	s.target = target
	return advanced, nil
}
func (s *interestTestScheduler) EnqueuePlaybackInterestWithConfig(scope, session, provider string, generation uint64, file handler.FileItem, headers http.Header, size int64, kind handler.WarmKind, alist config.AlistServer) error {
	s.enqueueCalls++
	s.kinds = append(s.kinds, kind)
	s.headers = append(s.headers, headers.Clone())
	s.configs = append(s.configs, alist)
	return s.errorEnqueue
}
func interestTestRouter(t *testing.T) (*gin.Engine, string, *config.Config, *interestTestScheduler, interestTestFiles) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	cfg := config.DefaultConfig()
	cfg.JWTSecret = "interest-test-secret"
	origin := cfg.GetAlistURL()
	files := interestTestFiles{"/current.mp4": {Path: "/current.mp4", Name: "current.mp4", RawURL: origin + "/d/current.mp4", Size: 4096}, "/next.mp4": {Path: "/next.mp4", RawURL: origin + "/d/next.mp4", Size: 4096}}
	scheduler := &interestTestScheduler{}
	r := gin.New()
	r.POST("/enc-api/playbackInterest", AuthMiddleware(cfg.JWTSecret, cfg.JWTExpire), playbackInterestHandler(cfg, files, scheduler))
	token, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("admin")
	if err != nil {
		t.Fatal(err)
	}
	return r, token, cfg, scheduler, files
}
func interestTestRequest(r *gin.Engine, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/enc-api/playbackInterest", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorizetoken", token)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}
func TestPlaybackInterestProtectedExplicitIntent(t *testing.T) {
	r, token, cfg, scheduler, _ := interestTestRouter(t)
	body := `{"session":"player-1","generation":1,"path":"/current.mp4","speculativePaths":["/next.mp4"]}`
	for _, badToken := range []string{"", "not-a-JWT"} {
		if rr := interestTestRequest(r, badToken, body); rr.Code != 401 {
			t.Fatalf("unauth status=%d", rr.Code)
		}
	}
	if scheduler.advanceCalls != 0 {
		t.Fatal("unauth request advanced session")
	}
	rr := interestTestRequest(r, token, body)
	if rr.Code != 202 || scheduler.advanceCalls != 1 || scheduler.enqueueCalls != 2 {
		t.Fatalf("status=%d advance=%d enqueue=%d body=%s", rr.Code, scheduler.advanceCalls, scheduler.enqueueCalls, rr.Body.String())
	}
	if scheduler.kinds[0] != handler.WarmForeground || scheduler.kinds[1] != handler.WarmSpeculative {
		t.Fatal("wrong task kinds")
	}
	if len(scheduler.scope) != 64 || strings.Contains(scheduler.scope, token) || scheduler.provider != handler.ProviderKey(cfg.GetAlistURL(), "/current.mp4") {
		t.Fatal("scope/provider was not server derived")
	}
	for _, h := range scheduler.headers {
		if len(h) != 0 {
			t.Fatalf("server JWT leaked upstream: %v", h)
		}
	}
	if strings.Contains(rr.Body.String(), token) || strings.Contains(rr.Body.String(), cfg.GetAlistURL()) {
		t.Fatal("response exposes credentials or target")
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("intent response cacheable")
	}
	rr = interestTestRequest(r, token, `{"session":"player-1","generation":2,"path":"/next.mp4"}`)
	if rr.Code != 202 {
		t.Fatal(rr.Body.String())
	}
	rr = interestTestRequest(r, token, body)
	if rr.Code != 409 {
		t.Fatalf("old generation status=%d", rr.Code)
	}
}
func TestPlaybackInterestValidatesBatchBeforeMutation(t *testing.T) {
	cases := []struct {
		body   string
		status int
	}{
		{`{"session":"p","generation":1,"path":"/missing.mp4"}`, 404},
		{`{"session":"p","generation":1,"path":"/current.mp4","speculativePaths":["/missing.mp4"]}`, 404},
		{`{"session":"p","generation":1,"path":"/x/../current.mp4"}`, 400},
		{`{"session":"p","generation":1,"path":"https://bad.invalid/file"}`, 400},
		{`{"session":"p","generation":1,"path":"/current.mp4","provider":"client-injected"}`, 400},
		{`{"session":"p","generation":0,"path":"/current.mp4"}`, 400},
		{`{"session":"p","generation":1,"path":"/current.mp4","speculativePaths":["/current.mp4"]}`, 400},
		{`{"session":"p","generation":1,"path":"/current.mp4"} {}`, 400},
		{strings.Repeat(" ", 4097) + `{}`, 400},
	}
	for _, tc := range cases {
		r, token, _, s, _ := interestTestRouter(t)
		rr := interestTestRequest(r, token, tc.body)
		if rr.Code != tc.status || s.advanceCalls != 0 || s.enqueueCalls != 0 {
			t.Fatalf("%s status=%d advance=%d enqueue=%d", tc.body, rr.Code, s.advanceCalls, s.enqueueCalls)
		}
	}
	for _, raw := range []string{"https://cdn.invalid/current.mp4", "file:///current.mp4", "http://user:pass@invalid/current.mp4", ""} {
		r, token, _, s, f := interestTestRouter(t)
		f["/current.mp4"].RawURL = raw
		if rr := interestTestRequest(r, token, `{"session":"p","generation":1,"path":"/current.mp4"}`); rr.Code != 400 || s.advanceCalls != 0 {
			t.Fatalf("foreign provider status=%d", rr.Code)
		}
	}
}
func TestPlaybackInterestErrorMappingAndBoundedWarming(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{{handler.ErrPlaybackInterestInvalid, 400}, {handler.ErrPlaybackInterestStale, 409}, {handler.ErrPlaybackInterestCapacity, 429}, {handler.ErrPlaybackInterestStopped, 503}, {errors.New("internal detail"), 503}} {
		r, token, _, s, _ := interestTestRouter(t)
		s.err = tc.err
		if rr := interestTestRequest(r, token, `{"session":"p","generation":1,"path":"/current.mp4"}`); rr.Code != tc.status || s.enqueueCalls != 0 {
			t.Fatalf("error %v status=%d", tc.err, rr.Code)
		}
	}
	r, token, _, s, _ := interestTestRouter(t)
	s.errorEnqueue = handler.ErrPlaybackInterestCapacity
	rr := interestTestRequest(r, token, `{"session":"p","generation":1,"path":"/current.mp4"}`)
	if rr.Code != 202 || !strings.Contains(rr.Body.String(), `"warmRejected":1`) {
		t.Fatalf("bounded warm status=%d body=%s", rr.Code, rr.Body.String())
	}
}
func TestPlaybackInterestScopeBindsVerifiedTokenAndConfiguration(t *testing.T) {
	r, token, cfg, s, _ := interestTestRouter(t)
	body := `{"session":"p","generation":1,"path":"/current.mp4"}`
	interestTestRequest(r, token, body)
	initial := s.scope
	another, err := auth.NewJWTAuth(cfg.JWTSecret, time.Hour).GenerateToken("other-admin")
	if err != nil {
		t.Fatal(err)
	}
	interestTestRequest(r, another, body)
	if s.scope == initial {
		t.Fatal("different verified token shared scope")
	}
	// This isolated config is not shared with workers; do not persist test credentials.
	cfg.AlistServer.ScanAuthHeader = "changed-provider-token"
	interestTestRequest(r, token, body)
	if s.scope == initial {
		t.Fatal("configuration credential rotation shared scope")
	}
}

func TestPlaybackInterestPinsValidatedConfigThroughAdmission(t *testing.T) {
	r, token, cfg, s, _ := interestTestRouter(t)
	cfg.AlistServer.ScanAuthHeader = "provider-A"
	body := `{"session":"p","generation":1,"path":"/current.mp4","speculativePaths":["/next.mp4"]}`
	if rr := interestTestRequest(r, token, body); rr.Code != http.StatusAccepted {
		t.Fatal(rr.Body.String())
	}
	scopeA := s.scope
	// Simulate configuration rotation after validation/scope creation but before
	// enqueue. This isolated fixture has no background workers or disk mutation.
	s.advanceHook = func() {
		cfg.AlistServer.ScanAuthHeader = "provider-B"
		cfg.AlistServer.ServerHost = "rotated.invalid"
	}
	rr := interestTestRequest(r, token, body)
	if rr.Code != http.StatusAccepted || s.scope != scopeA {
		t.Fatalf("scope drift status=%d", rr.Code)
	}
	for _, bound := range s.configs[len(s.configs)-2:] {
		if bound.ScanAuthHeader != "provider-A" || bound.ServerHost == "rotated.invalid" {
			t.Fatal("enqueue authentication/origin drifted from the validated snapshot")
		}
	}
}
