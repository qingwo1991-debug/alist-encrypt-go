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

func TestFilenameRecoveryRouteRequiresManagementJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const secret = "synthetic-filename-recovery-secret"
	s := &Server{cfg: &config.Config{JWTSecret: secret, JWTExpire: 1}}
	router := gin.New()
	s.registerRoutes(router, &handler.APIHandler{}, &handler.ProxyHandler{}, &handler.AlistHandler{}, &handler.WebDAVHandler{}, &handler.StatsHandler{})
	token, err := auth.NewJWTAuth(secret, time.Hour).GenerateToken("synthetic-admin")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		jwt, owner string
		want       int
	}{
		{"", "", 401}, {"", "Basic owner", 401}, {"invalid", "Basic owner", 401}, {token, "Basic owner", 503},
	} {
		req := httptest.NewRequest(http.MethodPost, "/enc-api/recoverFilename", strings.NewReader(`{"original_path":"/limited/original.mp4"}`))
		req.Header.Set("Authorizetoken", tc.jwt)
		req.Header.Set("Authorization", tc.owner)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("JWT configured=%v status=%d want=%d", tc.jwt != "", rr.Code, tc.want)
		}
	}
}
