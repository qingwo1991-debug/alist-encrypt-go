## alist-encrypt-go 全面代码审查报告

本报告基于对整个代码库的逐行审查，按严重程度分为 P0（必须修复）、P1（重要）、P2（建议改进）三个等级，共发现 5 个 P0 问题、13 个 P1 问题、12 个 P2 问题。

---

### P0 — 必须修复（安全/数据丢失）

**P0-1: admin 密码明文写入日志**

文件: `internal/dao/user.go:188`

```go
log.Warn().Str("username", "admin").Str("password", password).Msg("Generated initial admin password; change it after first login")
```

生产环境中日志通常被 ELK/CloudWatch 等系统集中收集，任何有日志查看权限的人都能看到明文密码。应改为仅输出到 stdout 一次（`fmt.Println`），或要求用户首次登录时自行设置密码。

**P0-2: `/redirect/:key` 无鉴权**

文件: `internal/handler/proxy.go:183`

`HandleRedirect` 方法直接通过 `redirectMap.Load(key)` 查找后开始流式代理，不做任何 JWT/session 验证。redirect key 是 `url:fileSize:time.Now().UnixNano()` 的 MD5，时间分量可预测。任何获取到 key 的人都能绕过鉴权解密并流式传输文件。应在路由注册时把 `/redirect/` 加入 auth 中间件，或在方法内增加 token 校验。

**P0-3: 三个 HTTP Server 均缺少 `ReadHeaderTimeout`**

文件: `internal/server/server.go:359, 381, 422`

`startHTTP`、`startHTTPS`、`startUnix` 都设置了 `ReadTimeout: 0` 和 `WriteTimeout: 0`（为了流式传输），但没有设置 `ReadHeaderTimeout`。这使得服务器容易受到 Slowloris 慢速头部攻击。有趣的是，mobile 端的 `proxy_server.go:396` 已正确设置了 `ReadHeaderTimeout: 10 * time.Second`，后端反而遗漏了。

**P0-4: V1 加密 — 确定性 IV/Nonce（AES-CTR + ChaCha20）**

文件: `internal/encryption/aesctr.go:47`, `internal/encryption/chacha20.go:50`

V1 模式的 IV/Nonce 均为 `MD5(fileSize)`。同一密码下，相同大小的文件会产生完全相同的密钥流。对于流密码来说，Nonce 重用意味着两段密文异或就能恢复两段明文的异或，属于密码学灾难级问题。V2 已使用随机 Nonce（正确），但 V1 仍在使用。建议：在配置/文档中将 V1 标记为"仅兼容旧数据"，新上传强制使用 V2。

**P0-5: MySQL flush 失败时缓冲记录永久丢失**

文件: `internal/storage/mysqlstore/store.go:173`

`flushBuffers` 在调用 `upsertStrategies`/`upsertFileMeta` 之前已经把记录从内存 buffer 中 drain 出来了。如果 upsert 失败（网络中断、约束冲突），这些记录已经不在 buffer 里了，永远丢失。应在失败时将记录重新入队（可加最大重试次数防止无限增长）。

---

### P1 — 重要（性能/可靠性/安全）

**P1-1: `io.ReadAll(r.Body)` 无大小限制 — 请求体 OOM 风险**

涉及文件:
- `internal/handler/alist.go` — 6 处 (行 426, 566, 648, 966, 1046, 1153)
- `internal/handler/webdav.go` — 2 处 (行 532, 584)
- `mobile/.../proxy_alist_api.go` — 5 处 (行 539, 609, 972, 1062, 1098)
- `mobile/.../play_v2.go` — 1 处 (行 725)
- `mobile/.../proxy.go` — 1 处 (行 4092)

共 15+ 处直接将请求体 `io.ReadAll` 读入内存，无大小限制。恶意客户端发送超大 body 即可 OOM。应统一使用 `io.LimitReader(r.Body, maxBytes)` 或类似 `readLimitedBody` 的方式。JSON API body 限制 1MB 足够。

**P1-2: `readLimitedBody` 调用方错误被忽略**

涉及文件: `internal/handler/webdav.go`, `internal/handler/alist.go`

之前修复中加入的 `readLimitedBody` 在很多调用处使用 `body, _ := readLimitedBody(...)` 丢弃错误。当 body 超限返回 nil 时，后续代码对 nil 解引用或返回空响应。应统一检查 error 并返回 502/413 响应。

**P1-3: MySQL 表缺少二级索引**

文件: `internal/storage/mysqlstore/schema.go`

当前只有 `key_hash` 主键索引。但清理查询按 `last_accessed` 过滤（全表扫描），`dir_snapshot.scope_key` 被 `GetSnapshot` 查询但无索引，`file_meta.provider_host + original_path` 做联合查询也无复合索引。数据量大时性能急剧下降。应添加：
- `CREATE INDEX idx_strategy_last_accessed ON strategy(last_accessed)`
- `CREATE INDEX idx_file_meta_last_accessed ON file_meta(last_accessed)`
- `CREATE INDEX idx_dir_snapshot_scope_key ON dir_snapshot(scope_key)`
- `CREATE INDEX idx_file_meta_provider_path ON file_meta(provider_host, original_path)`

**P1-4: CORS 通配符 `*` 应用于所有路由（含认证 API）**

文件: `internal/server/middleware.go:53`

`Access-Control-Allow-Origin: *` 全局生效，包括 `/enc-api/*` 管理接口。虽然浏览器不会对简单请求发送 Authorization 头，但 preflight 请求仍可被利用。应将 CORS 限制为特定 origin，或至少排除 `/enc-api` 路由。

**P1-5: FileDAO.Set() 静默丢弃 MySQL 写入错误**

文件: `internal/dao/file.go:176`

`_ = d.fileMetaWriter.UpsertFileMeta(info)` — MySQL 写入失败时错误被丢弃，调用方以为成功，但数据仅存在于内存缓存，重启后丢失。应至少记录 error 日志。

**P1-6: JWT Token 通过 URL 查询参数传递**

文件: `internal/server/middleware.go:98`

`strings.TrimSpace(c.Query("token"))` 允许通过 URL query 传递 JWT。URL 会出现在服务器访问日志、浏览器历史、代理日志和 Referer 头中，存在 token 泄露风险。应移除 query 参数支持，或仅限于只读端点。

**P1-7: JWT 过期时间设为 0（行为不确定）**

文件: `internal/server/middleware.go:86` → `NewJWTAuth(jwtSecret, 0)`

`expiration = 0` 时 `time.Now().Add(0)` 产生零值过期时间。根据 jwt/v5 库的行为，这可能导致 token 立即过期或永不过期（取决于零值处理）。应设置合理的默认值（如 24 小时）。

**P1-8: `streamBufferSize` 全局变量无同步保护**

文件: `internal/proxy/stream.go:54`, `mobile/.../proxy_server.go:195,551`

`streamBufferSize = effectiveKB * 1024` 直接写入包级全局变量，而多个流传输 goroutine 并发读取。存在数据竞争（torn write）。应使用 `atomic.StoreInt64` / `atomic.LoadInt64`。

**P1-9: PBKDF2 迭代次数 V1 仅 1000 次**

文件: `internal/encryption/chacha20.go:37`, `internal/encryption/aesctr.go`

OWASP 2023 推荐 PBKDF2-HMAC-SHA256 至少 600,000 次迭代。V1 使用 1000 次，差 600 倍。V2 已定义为 600,000 次（`content_v2.go` 中 `pbkdf2IterationsModern`），应确保 V2 实际使用该常量。V1 保持 1000 次兼容旧数据。

**P1-10: RC4-MD5 算法已被密码学社区废弃**

文件: `internal/encryption/rc4md5.go`

RC4 存在已知的密钥流偏差（Royal Holloway 攻击、NOMORE 攻击），在 TLS 中已被 RFC 7465 禁止。对于含有已知明文模式（如视频容器头部）的文件尤其危险。建议在配置中将 RC4-MD5 标记为 legacy，新上传不允许选择。

**P1-11: ChaCha20/AES-CTR 无 AEAD 认证**

文件: `internal/encryption/chacha20.go:54`, `internal/encryption/aesctr.go`

V1 和 V2 都使用纯流密码，无认证标签。密文可在传输中被篡改而不被检测（比特翻转攻击）。V2 应考虑使用 ChaCha20-Poly1305 或 AES-GCM 等 AEAD 模式。

**P1-12: mobile ProxyServer 结构体含 6+ 互斥锁，无锁定顺序文档**

文件: `mobile/.../proxy_server.go`

`ProxyServer` 包含 `mutex`, `sizeMapMu`, `rangeCompatMu`, `rangeProbeMu`, `upstreamMu`, `routingMu`, `webdavNegativeMu`, `uploadMetaMu`, `dbExportTokenMu` 等至少 9 个互斥锁。如果任何代码路径同时获取其中两个，就可能死锁。应文档化锁定顺序，或合并为更少的锁。

**P1-13: `ensureRuntimeCaches` 非线程安全**

文件: `mobile/.../proxy_server.go:88-104`

`ensureRuntimeCaches` 在无锁情况下做 nil 检查和初始化，并发调用时存在数据竞争。应使用 `sync.Once` 或确保仅在初始化阶段调用。

---

### P2 — 建议改进（代码质量/可维护性）

**P2-1: `setupRoutes` 超过 180 行**

文件: `internal/server/server.go:83-265`

该方法负责创建所有 handler、配置中间件、注册路由、启动后台 goroutine，违反单一职责。建议拆分为 `createHandlers()`, `registerRoutes()`, `startBackgroundTasks()` 三个方法。

**P2-2: 启动探测 goroutine 永不取消**

文件: `internal/server/server.go:145-173`

启动探测使用 `context.Background()` 的无限循环，服务器 Shutdown 时不会取消。应传入可取消的 context。

**P2-3: 两套重复的缓存实现**

文件: `internal/storage/cache.go` vs `internal/cache/filecache.go`

两者都实现了 TTL 缓存 + 清理 goroutine，但 `filecache.go` 额外有 maxSize、singleflight、eviction。应统一为一套实现。`storage/cache.go` 的 `Stop()` 也未被 `PasswdDAO` 调用，导致清理 goroutine 泄露。

**P2-4: `filecache.go` 的 `evictOne()` 在写锁下 O(n) 遍历**

文件: `internal/cache/filecache.go:84`

`SetWithTTL` 调用 `evictOne()` 时持有写锁，大缓存下遍历整个 map 阻塞所有并发读者。应改用 LRU 链表或概率驱逐（随机采样 N 个 key 驱逐最旧的）。

**P2-5: `fetchFsListContent` 无分页上限**

文件: `internal/handler/alist.go:272-313`

`for page := 1; ; page++` 无限制地从上游获取所有页面。如果上游有百万条目，会无限消耗内存和时间。应加最大页数或总条目限制。

**P2-6: `searchEncryptedTree` BFS 无深度/总量限制**

文件: `internal/handler/alist.go:316-393`

广度优先搜索加密目录树，无深度或总条目限制。深层嵌套或超大目录可能导致 OOM。应加可配置深度和总量限制。

**P2-7: `redirectInfo` 结构体明文存储密码**

文件: `internal/handler/proxy.go:57`

`redirectInfo` 在内存中保存 `Password` 字段长达 72 小时。进程内存 dump 或 redirect map 泄露会暴露所有活跃加密密码。应存储派生密钥或配置引用。

**P2-8: ProxyServer 45+ 字段的 God Object**

文件: `mobile/.../proxy_server.go:23-86`

约 45 个字段涵盖 HTTP 客户端、缓存、map、channel、互斥锁、统计计数器等。应提取为子组件（`CacheManager`, `RangeProbeManager`, `ProviderCatalog` 等）。

**P2-9: SQLite 迁移错误匹配依赖错误文本**

文件: `mobile/.../local_store.go:326`

`strings.Contains(err.Error(), "duplicate column name")` 依赖 SQLite 错误消息文本，不同版本/语言可能不同。应使用 `PRAGMA table_info` 检查列是否存在。

**P2-10: `readLimitedBody` 10MB 限制可能不够**

文件: `internal/handler/response.go:18`

对于超大目录的 PROPFIND 响应，10MB 可能不够。且 `io.ReadAll` 会预分配 `maxBytes+1` 大小的缓冲区。应可配置或根据场景调大，并使用 `bytes.NewBuffer` 初始容量提示。

**P2-11: `DeleteEncPathMapping` 仅删除加密路径索引**

文件: `internal/dao/file.go:231`

`d.pathCache.Delete(entry.EncryptedPath)` 只删了加密路径，display path 索引可能仍然残留。应同时删除两个索引。

**P2-12: `flushBatchAsync` 失败时固定 500ms 延迟**

文件: `mobile/.../local_store.go:528`

`time.Sleep(500 * time.Millisecond)` 在数据库持续不可用时会导致 goroutine 堆积。应使用指数退避，设最大延迟。

---

### 实施优先级建议

| 优先级 | 编号 | 问题 | 工作量 | 影响面 |
|--------|------|------|--------|--------|
| 立即修复 | P0-1 | admin 密码明文日志 | 小 | 安全 |
| 立即修复 | P0-2 | /redirect 无鉴权 | 小 | 安全 |
| 立即修复 | P0-3 | 缺少 ReadHeaderTimeout | 小 | 安全 |
| 立即修复 | P0-5 | MySQL flush 失败丢数据 | 中 | 数据 |
| 尽快修复 | P1-1 | io.ReadAll 请求体 OOM | 中 | 稳定 |
| 尽快修复 | P1-2 | readLimitedBody 错误忽略 | 小 | 稳定 |
| 尽快修复 | P1-3 | MySQL 缺少索引 | 小 | 性能 |
| 尽快修复 | P1-8 | streamBufferSize 数据竞争 | 小 | 稳定 |
| 本迭代内 | P0-4 | V1 加密 Nonce 重用 | 文档 | 安全(已知限制) |
| 本迭代内 | P1-4 | CORS 通配符 | 小 | 安全 |
| 本迭代内 | P1-5 | FileDAO 吞错误 | 小 | 可观测 |
| 本迭代内 | P1-6/7 | JWT 问题 | 中 | 安全 |
| 后续迭代 | P1-9~13 | 加密算法升级 | 大 | 安全 |
| 后续迭代 | P2-1~12 | 代码质量/架构 | 中~大 | 可维护性 |
