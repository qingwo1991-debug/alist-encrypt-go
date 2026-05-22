//go:build noembedwebui

package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetupWebUIRoutesNoEmbedBuildReturnsNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	s := &Server{}
	r := gin.New()
	s.setupWebUIRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/index", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusNotFound)
	}
}
