package encrypt

import (
	"io/fs"
	"net/http"

	"github.com/OpenListTeam/OpenList/v4/public"
)

// handleEncWebUIIndex redirects /index to the embedded enc-webui management
// console, matching the docker server's setupWebUIRoutes behaviour.
func (p *ProxyServer) handleEncWebUIIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/public/index.html", http.StatusFound)
}

// encWebUIFileServer returns an http.Handler that serves the embedded enc-webui
// static assets from public/dist/enc. Returns nil when the assets are
// unavailable (e.g. a stripped build), in which case the /public route is not
// registered.
func encWebUIFileServer() http.Handler {
	sub, err := fs.Sub(public.Public, "dist/enc")
	if err != nil {
		return nil
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		return nil
	}
	return http.FileServer(http.FS(sub))
}
