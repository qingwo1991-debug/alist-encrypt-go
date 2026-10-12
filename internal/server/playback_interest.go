package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/internal/dao"
	"github.com/alist-encrypt-go/internal/handler"
	"github.com/gin-gonic/gin"
)

type playbackInterestScheduler interface {
	AdvancePlaybackInterest(string, string, string, uint64, string) (bool, error)
	EnqueuePlaybackInterestWithConfig(string, string, string, uint64, handler.FileItem, http.Header, int64, handler.WarmKind, config.AlistServer) error
}
type playbackInterestFiles interface {
	Get(string) (*dao.FileInfo, bool)
}
type playbackInterestRequest struct {
	Session          string   `json:"session"`
	Generation       uint64   `json:"generation"`
	Path             string   `json:"path"`
	SpeculativePaths []string `json:"speculativePaths,omitempty"`
}

// Only an explicit authenticated application intent advances generations. No
// Range, HEAD, source-IP heuristic or media stream is attached to this context.
func playbackInterestHandler(cfg *config.Config, files playbackInterestFiles, scheduler playbackInterestScheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		token := c.GetString("user_token")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"code": 401, "msg": "user unlogin"})
			return
		}
		var input playbackInterestRequest
		dec := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&input); err != nil {
			c.JSON(400, gin.H{"code": 400, "msg": "invalid playback interest"})
			return
		}
		if err := dec.Decode(new(interface{})); err != io.EOF || strings.TrimSpace(input.Session) == "" || len(input.Session) > 128 || input.Generation == 0 || len(input.SpeculativePaths) > 4 {
			c.JSON(400, gin.H{"code": 400, "msg": "invalid playback interest"})
			return
		}
		if cfg == nil || files == nil || scheduler == nil {
			playbackInterestError(c, handler.ErrPlaybackInterestStopped)
			return
		}
		snapshot := cfg.AlistServerSnapshot()
		origin, err := url.Parse(config.BuildAlistURL(snapshot))
		if err != nil || origin.Host == "" || (origin.Scheme != "http" && origin.Scheme != "https") || origin.User != nil {
			playbackInterestError(c, handler.ErrPlaybackInterestStopped)
			return
		}
		paths := append([]string{input.Path}, input.SpeculativePaths...)
		items := make([]handler.FileItem, 0, len(paths))
		sizes := make([]int64, 0, len(paths))
		seen := make(map[string]bool)
		// Validate the complete batch before advancing. A stored URL is not proof of
		// configured provider membership: conservatively require the configured origin.
		for _, name := range paths {
			if name == "" || len(name) > 2048 || !strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsAny(name, "\\\x00\r\n") || seen[name] {
				c.JSON(400, gin.H{"code": 400, "msg": "invalid playback path"})
				return
			}
			seen[name] = true
			info, ok := files.Get(name)
			if !ok || info == nil || info.IsDir {
				c.JSON(404, gin.H{"code": 404, "msg": "unknown playback file"})
				return
			}
			target, err := url.Parse(info.RawURL)
			if err != nil || target.User != nil || target.Fragment != "" || !strings.EqualFold(target.Scheme, origin.Scheme) || !strings.EqualFold(target.Host, origin.Host) {
				c.JSON(400, gin.H{"code": 400, "msg": "playback file is outside configured provider"})
				return
			}
			items = append(items, handler.FileItem{DisplayPath: name, EncryptedPath: info.EncryptedPath, TargetURL: info.RawURL, FileName: info.Name, PropfindSize: info.Size})
			sizes = append(sizes, info.Size)
		}
		// Bind the verified token and configuration (including credential rotation)
		// without exposing either in registry identifiers, logs or response bodies.
		scopeJSON, _ := json.Marshal(struct {
			Domain, Token string
			Config        config.AlistServer
		}{"playback-interest-scope-v1", token, snapshot})
		digest := sha256.Sum256(scopeJSON)
		scope := hex.EncodeToString(digest[:])
		provider := handler.ProviderKey(origin.String(), input.Path)
		advanced, err := scheduler.AdvancePlaybackInterest(scope, input.Session, provider, input.Generation, input.Path)
		if err != nil {
			playbackInterestError(c, err)
			return
		}
		accepted, rejected := 0, 0
		for i, item := range items {
			kind := handler.WarmForeground
			if i > 0 {
				kind = handler.WarmSpeculative
			}
			// Server login JWT is never a provider credential. No client credentials
			// cross this boundary; provider-auth resolution belongs to the scheduler.
			err = scheduler.EnqueuePlaybackInterestWithConfig(scope, input.Session, provider, input.Generation, item, http.Header{}, sizes[i], kind, snapshot)
			if err != nil {
				rejected++
			} else {
				accepted++
			}
		}
		// Intent remains valid even if bounded warming admission is full. Do not undo
		// generation withdrawal or imply media HTTP was canceled/started by this API.
		c.JSON(http.StatusAccepted, gin.H{"code": 0, "msg": "accepted", "data": gin.H{"generation": input.Generation, "advanced": advanced, "warmAccepted": accepted, "warmRejected": rejected}})
	}
}
func playbackInterestError(c *gin.Context, err error) {
	status := http.StatusServiceUnavailable
	message := "playback interest unavailable"
	switch {
	case errors.Is(err, handler.ErrPlaybackInterestInvalid):
		status = 400
		message = "invalid playback interest"
	case errors.Is(err, handler.ErrPlaybackInterestStale):
		status = 409
		message = "stale playback interest"
	case errors.Is(err, handler.ErrPlaybackInterestCapacity):
		status = 429
		message = "playback interest capacity exhausted"
	}
	c.JSON(status, gin.H{"code": status, "msg": message})
}
