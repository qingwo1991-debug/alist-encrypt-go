# Handoff: Multi-Artifact Migration

## Background

目标是把 `alist-encrypt-go` 演进成唯一主仓库，同时产出：

- 独立后端发行物
  - Docker
  - Windows/Linux/macOS 二进制
- Android APK
  - 基于 `OpenList-Mobile` / `OpenList-Encrypt` 的移动端壳
  - 内置 OpenList + 加密代理能力

核心约束：

- `OpenList` 是独立上游服务，后续可能继续更新
- `OpenList-Mobile` 也是独立上游，后续也可能继续更新
- `alist-encrypt-go` 应成为唯一维护仓库
- 后端 Web 管理页不能成为唯一管理入口
- 需要支持：
  - 默认独立后端构建带内嵌 WebUI
  - Android / 外部管理端构建关闭内嵌 WebUI
  - GitHub Actions 统一发布多平台产物
  - Android 版本升级

## What Was Completed

### 1. Embedded WebUI became optional

已完成后端“内嵌管理页可选化”第一步：

- `internal/server/server.go`
  - 不再直接硬编码 `/public`、`/static`、`/index`
- 新增：
  - `internal/server/webui_enabled.go`
  - `internal/server/webui_disabled.go`
  - `internal/server/webui_enabled_test.go`
  - `internal/server/webui_disabled_test.go`
- 新增 build tag 语义：
  - 默认构建：保留内嵌 WebUI
  - `noembedwebui`：关闭内嵌 WebUI

### 2. Build capability metadata added

已新增构建能力探测：

- `internal/buildinfo/webui_enabled.go`
- `internal/buildinfo/webui_disabled.go`

以及 API：

- `/enc-api/getBuildInfo`

用于告诉客户端：

- 当前构建是否带内嵌 WebUI
- 当前管理模式：
  - `embedded_web`
  - `external_app`

### 3. Shared app service layer introduced

已新增：

- `internal/appservice/service.go`

当前已抽出的能力包括：

- BuildInfo
- Login
- UserInfo
- UpdatePassword
- UpdateUsername
- Get/Save Alist config
- Validate scan config
- Get/Save/Update/Delete WebDAV config
- Encode/Decode folder name
- Get/Save scheme config
- Export file meta
- Cleanup legacy BoltDB
- Get/Refresh proxy dictionary
- Get/Save proxy routing config
- Get stats

### 4. HTTP handler partially moved onto appservice

`internal/handler/api.go` 已开始改成复用 `appservice`，不是所有逻辑都自己处理。

已迁移到 `appservice` 的接口包括：

- login
- getUserInfo
- getBuildInfo
- updatePasswd
- updateUsername
- get/save alist config
- validateScanConfig
- webdav config CRUD
- encode/decode folder name
- get/save scheme config
- exportFileMeta
- cleanupLegacyBoltDB
- proxy dictionary
- proxy routing config

### 5. Config loading now supports custom base dir

已在 `internal/config/config.go` 中新增：

- `LoadFromBaseDir(baseDir string)`

目的：

- 给 Android / 嵌入式场景使用
- 避免一切都绑定到当前工作目录

### 6. gomobile export skeleton added

已新增：

- `gomobilelib/manager.go`

当前提供的是管理器骨架，包含：

- `NewManager(baseDir)`
- `LoadConfigJSON`
- `SaveConfigJSON`
- `GetBuildInfoJSON`
- `GetStatusJSON`
- `GetVersion`
- `GetHTTPPort`
- `StartService`
- `StopService`
- `IsRunning`
- `SetBaseDir`

注意：

- 这是骨架，不是最终移动端桥接完成态

### 7. GitHub Actions restructured

已删除旧工作流：

- `.github/workflows/docker.yml`

已新增：

- `.github/workflows/release.yml`
- `.github/workflows/sync_upstream.yml`

当前状态：

- `release.yml`
  - 已具备统一发布结构
  - 包含 test / docker / binaries / mobile / release 分段
- `sync_upstream.yml`
  - 已开始同步：
    - `upstream_versions/openlist.txt`
    - `upstream_versions/openlist_mobile.txt`
    - `mobile/openlist_version`

### 8. Mobile project copied into repo

已把移动端项目迁入：

- `mobile/`

当前 `mobile/` 更接近 `OpenList-Encrypt` 基线，而不是纯 `OpenList-Mobile`。

已做的清理：

- 删除了 `mobile/.git`
- 删除了 `mobile/ios`
- 删除了部分大体积残留：
  - `mobile/enc-webui/node_modules`
  - `mobile/enc-webui/dist`
  - 若干 codex 调试文件

### 9. Android update source partially updated

已修改：

- `mobile/lib/utils/update_checker.dart`
- `mobile/lib/pages/app_update_dialog.dart`
- `mobile/lib/pages/openlist/about_dialog.dart`
- `mobile/android/app/build.gradle`
- `mobile/openlist_version`

当前变化：

- APK 更新检查仓库改为：
  - `qingwo1991-debug/alist-encrypt-go`
- APK 输出名改为：
  - `OpenList-Encrypt-<version><abi>.apk`
- `mobile/openlist_version` 写入了本地已知上游：
  - `v4.2.1`

## Current State

当前工作区有大量未提交改动。

关键变更文件：

- `internal/config/config.go`
- `internal/handler/api.go`
- `internal/server/server.go`
- `internal/server/webui_enabled.go`
- `internal/server/webui_disabled.go`
- `internal/buildinfo/*`
- `internal/appservice/service.go`
- `gomobilelib/manager.go`
- `.github/workflows/release.yml`
- `.github/workflows/sync_upstream.yml`
- `mobile/`

## Known Problems / Blockers

### 1. Tests still depend on socket listeners

当前环境不允许测试里起真实监听端口。

已做的处理：

- 增加了：
  - `internal/handler/test_helpers_test.go`
  - `newSocketTestServer(...)`
  - `newHTTPClientFromHandler(...)`
- 已将部分测试改成：
  - 无法监听时自动 `Skip`
  - 或改成纯 transport / recorder 模式

但还没有把全部测试清干净。

需要继续处理的模式：

- `httptest.NewServer(...)`
- `httptest.NewUnstartedServer(...)`

重点目录：

- `internal/handler/*_test.go`
- `internal/proxy/*_test.go`

### 2. API refactor is partial

`internal/handler/api.go` 已经接入 `appservice`，但还没完全清理干净。

需要继续做：

- 删除不再需要的残余辅助函数
- 统一错误映射
- 去掉重复状态来源

### 3. mobile/ still contains old project residue

`mobile/` 仍有旧项目痕迹，包括但不限于：

- 文案仍提到：
  - `OpenList-Encrypt`
  - `OpenList-Mobile`
  - `OpenEncrypt`
- 包名仍然是：
  - `openlist_encrypt`
- Pigeon channel 名仍然是：
  - `dev.flutter.pigeon.openlist_mobile.*`
- 说明文档和 build guide 仍是旧项目内容
- `mobile/openlist-lib` 仍是旧的独立 OpenList-Encrypt 方案

### 4. release.yml mobile job is not complete

当前 `release.yml` 中的 `build-mobile` 只是预留结构，不是最终可用链路。

缺失内容：

- 构建前生成 `openlist-lib` Android AAR
- `gomobile` 初始化
- Flutter / Android / NDK / Java 版本对齐
- 产物重命名与 ABI 拆分
- Release 资产与移动端升级逻辑对齐

### 5. gomobilelib is not wired into mobile bridges yet

当前 `gomobilelib/manager.go` 只是新增了 Go 侧骨架。

还没完成：

- Android 原生 bridge 接到 `gomobilelib`
- Flutter `generated_api.dart` / `pigeons` 与新管理器方法对齐
- 现有 `mobile/openlist-lib/openlistlib/encrypt_server.go` 与 `gomobilelib` 的关系统一

## What Still Needs To Be Done

### A. Finish Go-side stabilization

1. 继续处理所有测试中的 `httptest.NewServer`
2. 让以下命令稳定通过：

```bash
GOCACHE=/tmp/gocache go test ./...
GOCACHE=/tmp/gocache go test -tags noembedwebui ./...
```

3. 清理 `api.go` 和 `appservice` 的重复逻辑

### B. Complete mobile migration

1. 统一 `mobile/` 身份

- 改 `pubspec.yaml`
  - 应用名
  - 描述
  - 版本来源注释
- 统一 README / BUILD_GUIDE / ABOUT 页面
- 去掉旧仓文案

2. 统一包/仓库标识

- Flutter package 名
- Android applicationId
- 关于页 / 更新页链接
- Release 资产名

3. Android-only 清理

- 去掉所有 iOS 相关分支逻辑
  - UI
  - 更新
  - 下载
  - 通知
  - 文档

4. 接入真实 Go backend bridge

有两条路，但必须选一条，不要混着来：

- 路线 A：
  - 继续沿用 `mobile/openlist-lib` 的旧 gomobile 导出
- 路线 B：
  - 迁到根仓新增的 `gomobilelib`

建议：

- 最终收敛到根仓的 `gomobilelib`
- `mobile/openlist-lib` 只保留 OpenList upstream 绑定所需部分

### C. Finish CI / release chain

`release.yml` 需要补成真正一次产出：

- Docker
- 独立后端二进制
- Android APK

具体要补：

1. Mobile 构建前：

- setup Java
- setup Flutter
- setup Android SDK / NDK
- setup Go
- setup gomobile

2. 生成 AAR：

- 如果走 `mobile/openlist-lib`
  - 跑 `mobile/openlist-lib/scripts/init_openlist.sh`
  - 跑 `mobile/openlist-lib/scripts/init_gomobile.sh`
  - 跑 `mobile/openlist-lib/scripts/gobind.sh`
- 如果走新 `gomobilelib`
  - 新写绑定脚本
  - 输出到 `mobile/android/app/libs`

3. Flutter build：

- `flutter pub get`
- `flutter build apk --release`
- `flutter build apk --split-per-abi`

4. 上传 release 资产：

- Linux/macOS/Windows binaries
- Docker tags
- APK / split APK

### D. Align upgrade flow

移动端升级要和 release 资产完全匹配：

- ABI 命名
- release tag
- 版本比较
- prerelease 策略

重点文件：

- `mobile/lib/utils/update_checker.dart`
- `mobile/lib/pages/app_update_dialog.dart`
- `mobile/android/app/build.gradle`
- `.github/workflows/release.yml`

## Recommended Next Sequence

按这个顺序接手，风险最低：

1. 先把所有监听型测试处理掉
2. 让 `go test ./...` 和 `go test -tags noembedwebui ./...` 过
3. 再清 `mobile/` 的旧项目残留
4. 再统一移动端版本升级逻辑
5. 最后补齐 `release.yml` 的 mobile 构建链

## Useful Commands

### Go tests

```bash
mkdir -p /tmp/gocache
GOCACHE=/tmp/gocache go test ./...
GOCACHE=/tmp/gocache go test -tags noembedwebui ./...
```

### Find remaining socket-based tests

```bash
rg -n "httptest.NewServer|NewUnstartedServer" internal/handler internal/proxy internal/server -g '*_test.go'
```

### Find old mobile references

```bash
rg -n "OpenList-Encrypt|OpenList-Mobile|openlist_encrypt|openlist_mobile|OpenEncrypt" mobile --glob '!**/node_modules/**' --glob '!**/build/**'
```

## Suggested Next Prompt

Use something like:

```text
Continue from docs/HANDOFF_MULTI_ARTIFACT_MIGRATION.md.
First make the Go test suite pass in this sandbox by removing remaining socket-listener assumptions.
Then finish the Android-only mobile migration under mobile/, clean old project references, and wire release.yml so it can build Docker, binaries, and APKs from this repo.
Do not re-plan; continue implementation from the current working tree.
```
