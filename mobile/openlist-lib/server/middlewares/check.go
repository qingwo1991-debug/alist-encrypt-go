package middlewares

import (
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

// Initialization is tracked per mount by op, not by a global request barrier.
// Already-ready mounts and static/management endpoints remain responsive while
// an unrelated storage initializes. Filesystem operations report StorageNotInit
// for pending or failed mounts; virtual ancestors can still list their mounts.
func StoragesLoaded(c *gin.Context) {
	if c.Request.Context().Err() != nil {
		c.Abort()
		return
	}
	common.GinAppendValues(c, conf.ApiUrlKey, common.GetApiUrlFromRequest(c.Request))
	c.Next()
}
