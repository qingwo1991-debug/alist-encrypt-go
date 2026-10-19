package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alist-encrypt-go/internal/auth"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

func (s *interestTestScheduler) ClearPlaybackInterest(scope, session, provider string, generation uint64) (bool, error) {
	if generation < s.generation {
		return false, handler.ErrPlaybackInterestStale
	}
	advanced := generation > s.generation
	s.generation = generation
	s.target = ""
	return advanced, nil
}

// Exercise a real TCP listener, JWT middleware and wire JSON, not source strings.
func TestPlaybackInterestCapabilityAndClearActualSocket(t *testing.T) {
	r, token, cfg, s, _ := interestTestRouter(t)
	r.GET("/enc-api/playbackInterest/capabilities", AuthMiddleware(cfg.JWTSecret, cfg.JWTExpire), playbackInterestCapabilityHandler(s))
	server := httptest.NewServer(r)
	defer server.Close()
	send := func(method, endpoint, jwt, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+endpoint, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorizetoken", jwt)
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(payload)
	}
	for _, jwt := range []string{"", "invalid"} {
		if status, _ := send("GET", "/enc-api/playbackInterest/capabilities", jwt, ""); status != 401 {
			t.Fatal(status)
		}
	}
	expired, err := auth.NewJWTAuth(cfg.JWTSecret, -time.Hour).GenerateToken("admin")
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := send("POST", "/enc-api/playbackInterest", expired, `{"session":"p","generation":1,"clear":true}`); status != 401 {
		t.Fatal("expired JWT accepted", status)
	}
	if status, body := send("GET", "/enc-api/playbackInterest/capabilities", token, ""); status != 200 || !strings.Contains(body, `"version":2`) || !strings.Contains(body, `"signedCDN":false`) {
		t.Fatal(status, body)
	}
	for _, body := range []string{`{"session":"p","generation":1,"path":"/current.mp4"}`, `{"session":"p","generation":2,"clear":true}`} {
		if status, payload := send("POST", "/enc-api/playbackInterest", token, body); status != 202 {
			t.Fatal(status, payload)
		}
	}
	if s.enqueueCalls != 1 {
		t.Fatal("clear enqueued warm")
	}
	if status, _ := send("POST", "/enc-api/playbackInterest", token, `{"session":"p","generation":1,"clear":true}`); status != 409 {
		t.Fatal("stale clear", status)
	}
	if status, _ := send("POST", "/enc-api/playbackInterest", token, `{"session":"p","generation":3,"clear":true,"path":"/current.mp4"}`); status != 400 {
		t.Fatal("ambiguous clear", status)
	}
}

func TestPlaybackInterestStoppedCapability(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var scheduler *handler.ProbeScheduler
	r := gin.New()
	r.GET("/capability", playbackInterestCapabilityHandler(scheduler))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest("GET", "/capability", nil))
	if !strings.Contains(rr.Body.String(), `"available":false`) {
		t.Fatal(rr.Body.String())
	}
}
