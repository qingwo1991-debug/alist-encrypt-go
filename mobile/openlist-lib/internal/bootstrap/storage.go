package bootstrap

import (
	"context"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// StorageInitTimeout 单个存储启动初始化超时时间。
// 移动端/国内直连时国外盘无法访问，设置超时隔离（3s），防止拖死启动流程及整体门闩。
const StorageInitTimeout = 3 * time.Second

func LoadStorages() {
	storages, err := db.GetEnabledStorages()
	if err != nil {
		utils.Log.Fatalf("failed get enabled storages: %+v", err)
	}
	go func(storages []model.Storage) {
		// 并行加载：每个盘一个 goroutine，并带超时 context 隔离。
		// 单个盘 Init（如国外盘连不上）最多超时 3s，不会拖死整个服务；
		// 所有盘加载完成后（或超时后）发送 StoragesLoaded 信号。
		var wg sync.WaitGroup
		for i := range storages {
			wg.Add(1)
			go func(s model.Storage) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), StorageInitTimeout)
				defer cancel()
				if err := op.LoadStorage(ctx, s); err != nil {
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
