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
		//
		// 注意：部分驱动（如 gdrive 的 oauth2 token 请求）不尊重传入 ctx，
		// Init 可能挂起远超 3s。这里再加一道硬性门闩（select + time.After），
		// 保证 wg 一定在 StorageInitTimeout+缓冲 内完成，StoragesLoaded 信号
		// 不被挂起的 Init 阻塞（否则所有 API 请求都要等 1.5s gate 超时）。
		var wg sync.WaitGroup
		for i := range storages {
			wg.Add(1)
			go func(s model.Storage) {
				defer wg.Done()
				done := make(chan error, 1)
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), StorageInitTimeout)
					defer cancel()
					done <- op.LoadStorage(ctx, s)
				}()
				select {
				case err := <-done:
					if err != nil {
						utils.Log.Errorf("failed load storage [%s]: %+v", s.MountPath, err)
					} else {
						utils.Log.Infof("success load storage: [%s], driver: [%s], order: [%d]",
							s.MountPath, s.Driver, s.Order)
					}
				case <-time.After(StorageInitTimeout + 2*time.Second):
					utils.Log.Errorf("failed load storage [%s]: init hung beyond %v, isolating",
						s.MountPath, StorageInitTimeout)
				}
			}(storages[i])
		}
		wg.Wait()
		conf.SendStoragesLoadedSignal()
	}(storages)
}
