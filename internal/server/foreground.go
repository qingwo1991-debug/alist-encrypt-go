package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Select only media routes, not ordinary APIs, directory listings, or UI assets.
// Registration happens before protected-name recovery and other network calls.
func (s *Server) foregroundPlaybackMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			c.Next()
			return
		}
		p := r.URL.Path
		candidate := strings.HasPrefix(p, "/redirect/")
		for _, prefix := range []string{"/dav/", "/d/", "/p/"} {
			if !strings.HasPrefix(p, prefix) {
				continue
			}
			display := "/" + strings.TrimPrefix(p, prefix)
			if s.passwdDAO != nil {
				_, candidate = s.passwdDAO.FindByPath(display)
				if !candidate {
					_, candidate = s.passwdDAO.FindByDir(display)
				}
			}
			break
		}
		if candidate {
			defer s.foreground.Begin()()
		}
		c.Next()
	}
}
