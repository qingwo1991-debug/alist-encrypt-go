package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

func TestFilenameRetryRouteRequiresManagementJWTAndSeparateDAVCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "synthetic-filename-retry-secret"
	s := &Server{cfg: &config.Config{JWTSecret: secret, JWTExpire: 1}}
	router := gin.New()
	s.registerRoutes(router, &handler.APIHandler{}, &handler.ProxyHandler{}, &handler.AlistHandler{}, &handler.WebDAVHandler{}, &handler.StatsHandler{})
	token, err := auth.NewJWTAuth(secret, time.Hour).GenerateToken("synthetic-admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		jwt, dav string
		want     int
	}{
		{"", "", 401}, {"", "Basic b3duZXI6c2VjcmV0", 401}, {"invalid", "Basic b3duZXI6c2VjcmV0", 401},
		{token, "", 400}, {token, token, 400}, {token, "Bearer " + token, 400},
		{token, "Basic b3duZXI6c2VjcmV0", 503},
	} {
		r := httptest.NewRequest(http.MethodPost, "/enc-api/retryFilename", strings.NewReader(`{"original_path":"/limited/retry.mp4","dry_run":true}`))
		r.Header.Set("Authorizetoken", tc.jwt)
		r.Header.Set("Authorization", tc.dav)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("management JWT=%v DAV=%v status=%d want=%d body=%s", tc.jwt != "", tc.dav != "", w.Code, tc.want, w.Body)
		}
	}
}
