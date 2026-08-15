package middlewares

import (
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

// storagesLoadTimeout 等待 storage 加载完成的兜底时长。
// 移动端环境下，请求若等待过久会导致播放器/WebDAV/UI连接超时报错。
// 兜底时长设为 1.5 秒：国内盘通常 0.2s 内加载完成并唤醒信号；
// 若国外盘慢/超时，1.5 秒后直接放行已就绪存储，绝不拖死客户端请求。
const storagesLoadTimeout = 1500 * time.Millisecond

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
