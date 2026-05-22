//go:build !noembedwebui

package server

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/alist-encrypt-go/web"
)

func (s *Server) setupWebUIRoutes(r *gin.Engine) {
	r.StaticFS("/public", web.GetFileSystem())
	r.StaticFS("/static", web.GetFileSystem())
	r.GET("/index", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/public/index.html")
	})
}
