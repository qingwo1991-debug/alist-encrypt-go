package bootstrap

import (
	"context"
	"sync"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

func LoadStorages() {
	storages, err := db.GetEnabledStorages()
	if err != nil {
		utils.Log.Fatalf("failed get enabled storages: %+v", err)
	}
	go func(storages []model.Storage) {
		// 并行加载：每个盘一个 goroutine。单个盘 Init（如国外盘连不上）最多
		// 拖 RestyClient 超时（30s），不再串行阻塞后续盘；所有盘完成后才发
		// StoragesLoaded 信号，避免外部请求（PROPFIND 根目录等）被门闩一直挡着。
		var wg sync.WaitGroup
		for i := range storages {
			wg.Add(1)
			go func(s model.Storage) {
				defer wg.Done()
				if err := op.LoadStorage(context.Background(), s); err != nil {
					utils.Log.Errorf("failed load storage [%s]: %+v", s.MountPath, err)
				} else {
					utils.Log.Infof("success load storage: [%s], driver: [%s], order: [%d]",
						s.MountPath, s.Driver, s.Order)
				}
			}(storages[i])
		}
		wg.Wait()
		conf.SendStoragesLoadedSignal()
	}(storages)
}
