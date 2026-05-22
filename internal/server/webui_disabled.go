//go:build noembedwebui

package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (s *Server) setupWebUIRoutes(r *gin.Engine) {
	r.GET("/index", func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"code": 404,
			"msg":  "embedded web UI disabled for this build; use the platform-specific management app",
		})
	})
}
