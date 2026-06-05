# Alist-Encrypt-Go 项目认知基线与修复方案（修正版）

> 本文档基于实际源码逐条验证后编写，纠正了原始三份文档中的事实性错误。

---

## 第一部分：项目架构认知（修正版）

### 1.1 项目定位

Alist-Encrypt-Go 是一个基于 Go 语言编写的透明加密代理服务，部署在客户端与 Alist 之间，在请求链路中实时完成文件内容和文件名的加解密。项目同时提供可独立部署的后端服务端和集成了加密代理的 Android 移动端应用（Flutter + OpenList）。

核心请求链路：`Client → Alist-Encrypt-Go 代理层 → 原生 Alist`。下载/播放时代理从 Alist 拉取加密流实时解密，完整支持 Range Seek（视频拖拽无感）；上传时将文件名和文件内容加密后转发给 Alist。

### 1.2 后端目录结构（`internal/` + `cmd/`）

**`cmd/server/main.go`**：服务启动入口，加载配置、创建 Server、在 restart loop 中运行、处理 SIGINT/SIGTERM 信号的 graceful shutdown。

**`internal/server/server.go`**：服务生命周期管理。`New()` 初始化存储/路由/handler，`Start()` 启动 HTTP/HTTPS/Unix socket 服务，`Shutdown()` 优雅关闭。`setupRoutes()` 定义了完整路由表：`/d/*path`（下载解密）、`/dav/*`（WebDAV）、`/api/fs/*`（Alist API 拦截）、`NoRoute`（兜底代理）。

**`internal/encryption/`**：核心加解密模块。

- 内容加密支持三种流式加密算法：AES-128-CTR（`aesctr.go`）、ChaCha20（`chacha20.go`）、RC4-MD5（`rc4md5.go`），在 `registry.go` 的 `init()` 中统一注册。
- v1 和 v2 两种密钥派生配置（非两种不同 KDF）：v1 使用 PBKDF2 1000 次迭代，盐值为算法名（如 `"AES-CTR"`）；v2 使用 PBKDF2 600000 次迭代，盐值带 `-v2` 后缀。两者底层 KDF 均为 PBKDF2（`content_v2.go` 定义 `pbkdf2IterationsModern = 600000`）。
- V2 加密在文件头注入 32 字节结构（`contentHeaderSize = 32`，包含 magic/version/nonce/plainSize）。
- 文件名加密使用 MixBase64 算法结合 CRC6 完整性校验（`filename.go` 中 `EncodeName()`/`DecodeName()`）。
- PBKDF2/MixBase64 计算结果缓存在 `internal/encryption/flow.go` 中（`passwdOutwardCache` 和 `mixBase64Cache`，TTL 30 分钟），而非 `internal/cache` 包。

**`internal/handler/` + `internal/proxy/` + `internal/proxydict/`**：请求拦截与代理转发。

- `alist.go`：拦截 Alist API 端点（`/api/fs/list`、`/api/fs/get`、`/api/fs/put`、`/api/fs/search` 等）。
- `webdav.go`：完整兼容 WebDAV 协议（PROPFIND、PROPPATCH、MKCOL、COPY、MOVE 等）。
- `playback_orchestrator.go`：编排解密播放流程（元数据加载、策略选择、重试降级）。
- `stream_strategy.go`：基于 provider 的流策略自动降级/恢复（Range → Chunked → Full）。
- `probe_scheduler.go`：后台异步预探测文件大小和 Range 兼容性。
- `proxy/stream.go`：`ProxyDownloadDecryptWithStrategyForStorage()`（下载解密）和 `ProxyUploadEncrypt()`（上传加密），支持三种流策略自动选择。
- `proxydict/dictionary.go`：按域名分流的代理词典，支持直连或代理网盘。

**`internal/storage/` + `internal/dao/`**：数据持久化层。

- `storage/store.go`：BoltDB 实现（基于 `bbolt` 库），定义 BucketUsers/BucketFileInfo/BucketFileSize 等桶。
- `storage/mysqlstore/`：MySQL 实现，包含 `store.go`（带 Write-Behind 异步缓冲）、`file_meta.go`、`range_compat.go`、`strategy.go` 等。
- `dao/file.go`：`FileDAO` 管理文件元数据（路径、大小、加密路径、ContentVersion 等），使用 `PathCache`（内存分片缓存）+ BoltDB/MySQL 持久化。
- **注意**：Range 兼容性缓存（`RangeCompatStore`）的接口定义在 `proxy/` 包，实现在 `proxy`（FileRangeCompatStore/MemoryRangeCompatStore）和 `handler`（MySQLRangeCompatStore）中，不在 `storage` 包。

**`internal/cache/`**：通用内存缓存（TTL + maxSize + SingleFlight），由 `filecache.go` 实现。`internal/auth/jwt.go`：JWT token 生成和验证（HS256）。

### 1.3 移动端架构

移动端涉及**两个独立的 Go 项目**，通过 Flutter 整合：

**`gomobilelib/manager.go`（alist-encrypt-go 的 Go Mobile 绑定层）**：`Manager` 结构体封装了 alist-encrypt-go 的核心代理服务，暴露 `StartService()`/`StopService()`/`LoadConfigJSON()`/`GetStatusJSON()` 等 API 供 Android 端调用。

**`mobile/openlist-lib/`（独立的 OpenList 项目，Alist 的 fork）**：这是一个完整的 OpenList/Alist 文件服务器（`go.mod` 中 module 为 `github.com/OpenListTeam/OpenList/v4`），嵌入移动端运行，提供文件管理能力。其内部的 `openlistlib/encrypt/` 目录是 OpenList 自身的加密代理插件，包含以下关键文件：

- `proxy_server.go`：加密代理服务启动与生命周期管理（监听 5344 端口）
- `proxy_download.go` / `play_v2.go`：下载解密与播放服务
- `proxy.go`：请求代理核心逻辑
- `local_store.go`：SQLite 本地存储（`local_media.db`），保存文件元数据
- `meta_sync.go`：远端元数据导出同步（`EnableDBExportSync`，**默认关闭**）
- `range_probe.go`：Range 兼容性探测（`EnableRangeCompatCache`，默认开启）
- `config.go`：移动端加密代理配置

**Flutter UI 层（`mobile/lib/`）**：用户界面，包含设置面板、挂载配置页面、国际化支持等。

**Android 原生桥接层（`mobile/android/app/src/main/kotlin/com/openlist/mobile/`）**：包含 `OpenListService.kt`（前台服务保活，`startForeground()`）、`bridge/`（Flutter↔Go 桥接）、`sync/`（后台同步任务调度）等。

---

## 第二部分：后端核心修复方案

> 所有问题均已通过源码验证，以下按优先级排序。

### 修复 1（高危）：MySQL 数据丢失风险

**问题位置**：`internal/server/server.go` 第 435-462 行 `Shutdown()` 方法。

**现状**：Shutdown 流程关闭了 HTTP/HTTPS 服务和 BoltDB（`s.store.Close()`），但完全遗漏了 `s.mysqlStore` 的关闭和数据 flush。MySQL 持久化采用 Write-Behind 异步缓冲（默认 5 秒落盘，`mysqlstore/store.go` 第 74-77 行），buffer 中的 fileMeta/strategy/rangeCompat 数据在停机时会直接丢失。即使调用了 `mysqlStore.Close()`，其当前实现也只关闭 DB 连接而不 flush 缓冲区。

**修复动作**：
1. 在 `mysqlstore/store.go` 的 `Close()` 方法中，先调用 `flushAllBuffers()` 排空异步缓冲队列，再关闭 DB 连接。
2. 在 `server.go` 的 `Shutdown()` 流程末尾补充 `s.mysqlStore.Close()` 调用（带 context 超时保护）。

### 修复 2（高危）：V2 文件的 WebDAV 大小不匹配

**问题位置**：`internal/handler/webdav.go` `decryptPropfindResponse()` 函数（约第 1027-1058 行）。

**现状**：V2 加密在文件头注入 32 字节（`contentHeaderSize = 32`），使密文比明文大 32 字节。处理 PROPFIND 响应时，系统解密了 `<displayname>` 和 `<href>`，但直接透传了 `<getcontentlength>`（密文大小）。WebDAV 客户端（如播放器）拿到的文件体积比实际大 32 字节，拖拽到视频尾部时范围请求溢出导致播放错误。

**修复动作**：在 `decryptPropfindResponse()` 中，对 V2 加密文件的 `<getcontentlength>` 动态递减 32 字节，还原精确的原始文件体积。

### 修复 3（高危）：ChaCha20 274GB 超大文件截断 Bug

**问题位置**：`internal/encryption/chacha20.go` 第 65-89 行 `SetPosition()` 方法。

**现状**：`blockCount := uint32(position / 64)` 将块计数强制转换为 `uint32`。当 position > 274,877,906,880 字节（~256 GiB）时，`uint32` 溢出回绕，导致后续数据解密使用错误的密钥流偏移，输出乱码。

**修复动作**：将 `uint32` 升级为 `uint64`，向后兼容且支持 PB 级单文件寻址。

### 修复 4（中危）：Goroutine 与内存泄漏

**问题位置**：
- `internal/storage/cache.go` 第 81-93 行 `cleanup()`
- `internal/cache/filecache.go` 第 147-158 行 `cleanup()`
- `internal/storage/mysqlstore/store.go` 第 124-144 行 `startLoops()`（原文档未提及的额外发现）

**现状**：以上三处的清理循环都使用 `for range ticker.C` 无限循环，没有任何 stop channel、context 取消或 `ticker.Stop()` 机制。一旦 Cache/Store 创建，goroutine 永远无法回收。

**修复动作**：改造所有清理循环，传入 `context.Context`，在服务注销时触发停止信号，回收协程。

### 修复 5（中危）：上游响应导致的 OOM 风险

**问题位置**：`internal/handler/alist.go` 和 `internal/handler/webdav.go` 中的多处 `io.ReadAll(resp.Body)` 调用。

**现状**：拦截和修改上游 API 响应时（如 `/api/fs/list`、`/api/fs/get`、PROPFIND XML 等），大量使用无限制的 `io.ReadAll(resp.Body)`。虽然这些主要针对 API 元数据响应而非文件流（文件流通过 StreamProxy 流式代理），但对于包含数万文件的超大目录，API 响应仍可能达到 MB 级别。值得注意的是 `probe_scheduler.go` 中已部分使用 `io.LimitReader` 做了限制，说明作者意识到此问题但未全面处理。

**修复动作**：利用 `io.LimitReader` 包裹所有代理拦截层的 `io.ReadAll`（如限制最大缓冲 10MB），防止恶意或失控的上游吞噬内存。

### 修复 6（低危）：收口加密入口，切断 v1 增量

**问题位置**：`internal/encryption/aesctr.go` 和 `chacha20.go` 的 v1 密钥生成。

**现状**：v1 版本的 IV/Nonce 取值仅为 `MD5(str(fileSize))`，相同大小文件必然使用相同 IV，构成流密码复用安全隐患。v1 的 key 也包含 `fileSize`（`passwdSalt = passwdOutward + str(fileSize)`），但还包含密码成分，不同密码下 key 不同。

**修复动作**：
1. **坚决不修改 v1 解密逻辑**，确保旧历史数据仍可正常解密。
2. 排查所有上传和写入入口（`HandleFsPut`、WebDAV PUT 等），断言新文件完全强制使用 `NewLatestContentEncryptor()` 生成 V2 算法（随机 Nonce）。
3. 同时修复 `webdav_strategy.go` 中每次探测请求动态创建 `proxy.NewHTTPClient()` 的问题，改为复用全局实例，避免连接池与文件描述符滥用。

---

## 第三部分：移动端专项优化方案（修正版）

> 以下优化均基于 `mobile/openlist-lib/openlistlib/encrypt/` 目录下的实际代码验证。

### 优化 1：SQLite 备份阻塞与累积

**问题位置**：`local_store.go` 第 114-122 行 `newLocalStore()` 和第 150-178 行 `backupLocalStoreDB()`。

**现状（已验证）**：
- 每次创建 localStore 实例（即代理服务启动时），都会**同步调用** `backupLocalStoreDB(dbPath)`，使用 `io.Copy` 将整个 `local_media.db` 文件复制为 `.bak-<timestamp>` 文件。这确实是一次同步全量文件复制，对大数据库会拖慢启动速度。
- **备份文件（`.bak-*`）确实没有清理逻辑**，会无限累积，浪费存储空间。
- **但数据库内部数据有清理逻辑**：启动时 `local_integration.go` 中会调用 `p.localStore.Cleanup(sizeRetention, strategyRetention)`，删除过期的 size/strategy 记录。原文档将这两个问题混为一谈了。

**修复动作**：
1. **异步化**：将 `backupLocalStoreDB()` 放入独立 Goroutine，不阻塞 5344 端口绑定。
2. **数量限制**：加入清理逻辑，只保留最近 1-2 份备份（覆盖写入），删除旧 `.bak-*` 文件。

### 优化 2：meta_sync 同步循环（需用户启用）

**问题位置**：`meta_sync.go` 第 27 行定义默认间隔 300 秒（5 分钟），第 206-226 行 `startDBExportSyncLoop()` 和第 688-764 行 `syncDBExportMetaOnce()`。

**现状（已验证，含关键前提）**：
- `meta_sync.go` 确实实现了每 5 分钟循环拉取远端数据，且每次循环在 `cfg.AuthEnabled` 为 true 时都会调用 `dbExportLogin()` 重新获取 JWT token，没有 token 复用/缓存。
- **但该功能默认关闭**：`config.go` 第 66 行 `EnableDBExportSync: false`。只有用户在配置中手动启用后才会触发循环。原文档未提及此前提，容易误导。
- 该循环可通过 `metaSyncDone` channel 和 `stopDBExportSyncLoop()` 正常停止，不是不可控的"死循环"。

**修复动作**：
1. **JWT Token 复用**：缓存 JWT Token，只在过期或收到 401 时重新登录。
2. **首次同步延后**：启用后将首次同步延后 30-60 秒，避开启动高峰期。
3. **适当拉长周期**：将默认同步周期适当拉长。
4. **条件触发（可选）**：提供接口供 Android Native 层调用，仅在 `WIFI + 充电中` 闲置状态下才高频调度。

### 优化 3：Range Probe 后台循环

**问题位置**：`range_probe.go` 第 102-143 行 `startRangeProbeLoop()` 和第 161-183 行 `rangeProbeLoop()`。

**现状（已验证，含细微差别）**：
- 当 `EnableRangeCompatCache` 为 true（默认开启）时，`NewProxyServer()` 中自动启动后台 goroutine，每 10 分钟触发一次 `runScheduledRangeProbes()`。
- **探测目标只来自播放/下载行为**：`registerRangeProbeTarget()` 仅在 `proxy.go` 中处理流媒体请求时被调用。首次安装且从未播放过时，循环虽运行但不产生实际网络请求。
- **重启后会恢复历史目标**：启动时从本地存储加载之前持久化的探测目标并全部入队。如果之前有过播放行为，重启后即使没有新播放也会对历史目标发起探测。

**修复动作**：
1. **移除全局盲目循环**：改为按需触发模式。当用户产生实际的目录浏览或播放请求时，作为请求处理链条的副作用（Side-effect）异步触发探针。
2. 保留缓存和去重逻辑，避免对同一目标重复探测。

### 优化 4：代理服务后台保活保障

**现状（已验证，无需修复）**：
- 代理服务 `ProxyServer` 使用 Go `net/http` 的 `ListenAndServe()` 启动，底层使用 Go runtime 的 network poller（Linux 上 epoll，BSD/macOS 上 kqueue），当没有请求到达时 goroutine 被 runtime park，确实不主动消耗 CPU。
- Android 原生层 `OpenListService.kt` 明确调用了 `startForeground(FOREGROUND_ID, notification)`，`AndroidManifest.xml` 声明了 `android:foregroundServiceType="mediaPlayback"` 和 `FOREGROUND_SERVICE` 权限。
- 切到后台后，只要进程存活，代理服务随时可毫秒级响应请求。

**无需修复动作**。上述机制为后续优化提供了安全基线。

---

## 第四部分：修复优先级与实施建议

| 优先级 | 修复项 | 影响范围 | 工作量 |
|--------|--------|----------|--------|
| P0 | 修复 1：MySQL Shutdown 数据丢失 | 使用 MySQL 后端的用户 | 小 |
| P0 | 修复 2：WebDAV V2 文件 32 字节偏差 | WebDAV 播放器用户 | 小 |
| P0 | 修复 3：ChaCha20 超大文件截断 | 处理 >256GiB 文件的用户 | 小 |
| P1 | 修复 4：Goroutine 泄漏（含 mysqlstore 额外发现） | 长期运行的服务 | 中 |
| P1 | 优化 1：SQLite 备份异步化 + 清理 | 移动端启动速度和存储 | 小 |
| P2 | 修复 5：io.ReadAll OOM 防御 | 超大目录场景 | 中 |
| P2 | 优化 3：Range Probe 按需触发 | 移动端耗电 | 中 |
| P2 | 优化 2：JWT Token 复用（meta_sync） | 启用 DBExportSync 的用户 | 小 |
| P3 | 修复 6：切断 v1 入口 + HTTP Client 复用 | 安全性 + 连接池管理 | 中 |
