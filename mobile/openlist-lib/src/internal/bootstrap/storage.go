package bootstrap

import (
	"context"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	internalnet "github.com/OpenListTeam/OpenList/v4/internal/net"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
)

// StorageInitTimeout 单个存储启动初始化超时时间。
// 只有消费 context 的驱动能在此预算内退出；未配合的驱动不伪装成已隔离。
// 请求按挂载就绪状态处理，不依赖整体初始化门闩。
const StorageInitTimeout = 3 * time.Second

var storageLoadWG sync.WaitGroup

// JoinStorageLoads waits for actual Init calls, not merely their deadline.
func JoinStorageLoads() { storageLoadWG.Wait() }

func LoadStorages() {
	storages, err := db.GetEnabledStorages()
	if err != nil {
		utils.Log.Fatalf("failed get enabled storages: %+v", err)
	}
	op.PrepareStorageLoads(storages)
	storageLoadWG.Add(1)
	go func(storages []model.Storage) {
		defer storageLoadWG.Done()
		// 并行加载：每个盘一个 goroutine，并带超时 context 隔离。
		// 合作驱动在 3s 预算耗尽后退出；不为未消费 ctx 的驱动启动额外逃逸 goroutine。
		// 所有实际初始化调用返回后发送 StoragesLoaded 信号。
		var wg sync.WaitGroup
		for i := range storages {
			wg.Add(1)
			go func(s model.Storage) {
				defer wg.Done()
				parent := internalnet.StorageSessionContext(internalnet.BootstrapStorageContext(context.Background(), "", "", ""))
				ctx, cancel := context.WithTimeout(parent, StorageInitTimeout)
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
