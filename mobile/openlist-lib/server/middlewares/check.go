package middlewares

import (
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

// storagesLoadTimeout 等待 storage 加载完成的兜底时长。storage 串行加载时代，
// 国外盘 Init 可能拖 30s+，此处超时后放行，避免所有请求无限转圈。
const storagesLoadTimeout = 30 * time.Second

func StoragesLoaded(c *gin.Context) {
	if !conf.StoragesLoaded {
		if utils.SliceContains([]string{"", "/", "/favicon.ico"}, c.Request.URL.Path) {
			c.Next()
			return
		}
		paths := []string{"/assets", "/images", "/streamer", "/static"}
		for _, path := range paths {
			if strings.HasPrefix(c.Request.URL.Path, path) {
				c.Next()
				return
			}
		}
		select {
		case <-conf.StoragesLoadSignal():
		case <-time.After(storagesLoadTimeout):
			// 兜底：storage 加载（尤其国外盘 Init）可能长时间不完成，
			// 超时后放行，返回当前已加载的 storage，避免请求无限转圈。
		case <-c.Request.Context().Done():
			c.Abort()
			return
		}
	}
	common.GinAppendValues(c,
		conf.ApiUrlKey, common.GetApiUrlFromRequest(c.Request),
	)
	c.Next()
}
