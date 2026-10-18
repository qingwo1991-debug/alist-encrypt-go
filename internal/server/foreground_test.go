package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

func TestForegroundMiddlewareRegistersMediaBeforeHandlerAndReleases(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AlistServer.PasswdList = []config.PasswdInfo{{Enable: true, Password: "fixture-password", EncType: "aesctr", EncPath: []string{"/media/*"}}}
	f := handler.NewForegroundTracker(func() bool { return true })
	s := &Server{passwdDAO: dao.NewPasswdDAO(nil, cfg), foreground: f}
	defer s.passwdDAO.Stop()
	for _, tc := range []struct {
		method, path string
		active       bool
	}{
		{"GET", "/dav/media/movie.mp4", true},
		{"HEAD", "/d/media/movie.mp4", true},
		{"GET", "/p/media/movie.mp4", true},
		{"GET", "/redirect/fixture", true},
		{"PROPFIND", "/dav/media/", false},
		{"GET", "/enc-api/getStats", false},
		{"GET", "/dav/plain/movie.mp4", false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			r := gin.New()
			r.Use(s.foregroundPlaybackMiddleware())
			r.NoRoute(func(c *gin.Context) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()
				err := f.WaitBackground(ctx)
				if tc.active {
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("media was not registered before route: %v", err)
					}
				} else if err != nil {
					t.Fatalf("non-media was registered as playback: %v", err)
				}
				c.Status(http.StatusNoContent)
			})
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, nil))
			if rr.Code != http.StatusNoContent {
				t.Fatalf("status=%d", rr.Code)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := f.WaitBackground(ctx); err != nil {
				t.Fatalf("middleware did not release playback registration: %v", err)
			}
		})
	}
}
