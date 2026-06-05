## alist-encrypt-go 性能分析报告

基于对请求热路径、缓存层、数据库层、并发模型和流式传输的全面分析，按影响力排序如下。

---

### HIGH — 必须优化

**H1: V2 PBKDF2 密钥派生未缓存 — 每次请求 200-1500ms**

文件: `internal/encryption/aesctr_v2.go:20`, `internal/encryption/chacha20_v2.go:19`

V2 模式下 `pbkdf2IterationsModern = 600000` 次 SHA256 迭代在**每个下载请求**时都会重新执行。V1 有 `passwdOutwardCache` 做 TTL 缓存（`flow.go:122-153`），V2 完全没有。在 J4125 NAS 上单次 PBKDF2 耗时约 1.5 秒，i7 约 200ms。视频播放器一次播放会产生数十个 range 请求，每次都重新派生密钥。

修复方案：以 `"password:encType:hex(nonceField)"` 为 key，TTL 30 分钟，复用 `passwdOutwardCache` 的模式。缓存命中时从 ~500ms 降到 ~1us。

**H2: WebDAV 每次请求创建新 HTTP Client — 10-50ms/req**

文件: `internal/handler/webdav.go` 行 350, 475, 556, 642, 736; `internal/handler/proxy_strategy.go` 行 159

至少 6 处调用 `proxy.NewHTTPClient(cfg, timeout)` 创建全新的 `http.Client + http.Transport`，完全绕过了连接池复用。每次 PROPFIND 都要重新做 TCP+TLS 握手。

修复方案：在 `NewWebDAVHandler` 中创建 1-2 个共享的 `*http.Client`，所有调用点替换为共享实例。

**H3: filecache.evictOne() O(n) 写锁扫描**

文件: `internal/cache/filecache.go:140-158`

`SetWithTTL` 在缓存满时调用 `evictOne()`，在持有写锁期间遍历整个 map（最多 maxSize 个条目）。10000 条目时延迟从 O(1) 退化到 O(n)。

修复方案：替换为 LRU 链表 + map，eviction 降到 O(1)。可考虑引入 `hashicorp/golang-lru` 依赖。

**H4: regex 在热路径中每次编译**

文件: `internal/proxy/stream.go:1713`

`rewriteContentDisposition` 每次下载都 `regexp.MustCompile`，重新编译 NFA 状态机。

修复方案：提取为包级变量 `var contentDispositionRe = regexp.MustCompile(...)`。

---

### MEDIUM — 建议优化

**M1: MySQL buffer.drain() 持锁 O(n)**

文件: `internal/storage/mysqlstore/buffer.go`

`drain()` 在持有 mutex 期间遍历 map + 分配 slice + 创建新 map。10000 条记录时阻塞所有并发 `upsert()` 约 1-2ms。

修复：在锁内仅做 map 指针交换（O(1)），锁外再遍历旧 map。

**M2: Probe JWT 未缓存 — 每个 probe 一次 HTTP 登录**

文件: `internal/handler/probe_scheduler.go:1013-1070`

`ensureAuth` 每次 probe 执行都调用 `fetchAlistJWT` 发起 HTTP POST 到 alist 登录接口。100 个 probe 项就发起 100 次登录请求。

修复：缓存 JWT token，TTL 2 小时或 401 时刷新。

**M3: discardBytes 未使用池化缓冲区**

文件: `internal/proxy/stream.go:1653-1659`

`io.CopyN(io.Discard, r, n)` 内部固定使用 32KB 缓冲区。对于 Full 策略的大偏移 seek（可达 MB 级），用 512KB 池化缓冲区可减少 16 倍 syscall。

修复：大 discard（> 4KB）使用 `getBuffer()`/`putBuffer()` + `io.CopyBuffer`。

**M4: playbackHintsMu 用互斥锁做读操作**

文件: `internal/proxy/stream.go:194-209`

`recentPlaybackStrategy` 是读多写少的热点，却用 `sync.Mutex` 而非 `sync.RWMutex`。高并发下成为瓶颈。

修复：改为 `sync.RWMutex`，读用 `RLock`，仅在删除过期条目时升级写锁。

**M5: FileDAO.Set() 总是先 Get()（读后写反模式）**

文件: `internal/dao/file.go:113`

每次 `Set()` 都触发完整的 `Get()` 查找（cache → BoltDB），用于合并 12 个字段。对于已有完整数据的调用方完全浪费。

修复：添加 `SetComplete(info)` 快速路径跳过合并。

**M6: InvalidateDisplayPath 冗余查找**

文件: `internal/dao/file.go:307-334`

单次 invalidate 触发 6 次 cache 操作 + 3 次 BoltDB 操作，两次 `Get` 可能返回同一个 `PathEntry` 指针导致重复工作。

修复：合并为单次查找 + 单次写入。

**M7: PROPFIND 响应 string↔byte 双重转换**

文件: `internal/handler/webdav.go:1056-1094`

`decryptPropfindResponse` 做 `string(body)` → 多轮字符串拼接 → `[]byte(result)`。大目录（200+ 文件）时 XML 达 500KB，两次全量拷贝。

修复：使用 `bytes.Buffer` 或 `strings.Builder` 一次性构建。

**M8: BoltDB GetJSON 冗余内存拷贝**

文件: `internal/storage/store.go:135`

`Get()` 行 81 已经从 BoltDB 的 mmap 区域拷贝了数据，`GetJSON()` 行 135 又做了一次 `append([]byte(nil), data...)`，完全多余。

修复：删除行 135 的冗余拷贝。

**M9: ListStrategies/ListRangeCompats 无 LIMIT**

文件: `internal/storage/mysqlstore/` 下 `strategy.go`, `range_compat.go`

`SELECT ... WHERE is_active=1` 无分页，百万行表会 OOM。

修复：添加 LIMIT 或 cursor 分页。

**M10: AES-CTR/ChaCha20 SetPosition 每次分配**

文件: `internal/encryption/aesctr.go:77-104`, `chacha20.go:78-111`

每次 seek 分配 IV slice + cipher 对象。视频 scrubbing 时每秒 10+ 次 seek，GC 压力累积。

修复：IV 改为 `[16]byte` 固定数组，ChaCha20 使用 `SetCounter(0)` 重置而非重建 cipher。

**M11: sniffDecrypted 用 map 做字节计数**

文件: `internal/proxy/stream.go:1804-1811`

`make(map[byte]bool, 256)` 分配一个 map 做唯一字节计数。改为 `[256]bool` 数组即可栈分配，零 GC。

**M12: CopyResponseHeaders 空 skip 时仍分配 map**

文件: `internal/httputil/httputil.go:122-136`

`skip` 为空时仍 `make(map[string]bool)`。改为 `len(skip) == 0` 时直接跳过 map 创建。

**M13: sync.Pool 配置更新时整体替换**

文件: `internal/proxy/stream.go:50-64`

`applyStreamBufferConfig` 替换整个 `sync.Pool`，旧池中正在使用的缓冲区变成垃圾。

修复：仅更新 `atomic.StoreInt64`，不替换池（`New` 函数已读取 atomic 值）。

---

### LOW — 当前表现良好

- **AES-CTR 硬件加速**：Go 的 `crypto/aes` 自动使用 AES-NI，吞吐 2-4 GB/s，瓶颈在网络而非加密。
- **流式管道效率**：`sync.Pool` + `io.CopyBuffer` 512KB 缓冲区 + 原地 XOR，架构正确。
- **PathCache 分片设计**：32 分片 FNV-1a + RWMutex，读多写少场景下表现良好。
- **MySQL 批量写入**：Write-Behind + map 去重 + `ON DUPLICATE KEY UPDATE`，设计合理。
- **Probe 不影响用户请求**：后台 worker pool 执行，不阻塞热路径。

---

### 优化优先级表

| 优先级 | 编号 | 预期提升 | 工作量 |
|--------|------|----------|--------|
| 立即 | H1 V2 PBKDF2 缓存 | 200-1500ms/req → 1us | 小（30 行） |
| 立即 | H2 WebDAV 共享 Client | 10-50ms/req | 小（20 行） |
| 立即 | H4 regex 包级编译 | 5-15us/req | 极小（1 行） |
| 本周 | M1 buffer drain 锁优化 | 锁持有 O(n)→O(1) | 小（15 行） |
| 本周 | M2 probe JWT 缓存 | 50-200ms/probe | 小（20 行） |
| 本周 | M3 discardBytes 池化 | 大 seek 30-50% 提升 | 小（10 行） |
| 本周 | M4 hints RWMutex | 高 QPS 锁竞争降低 | 小（5 行） |
| 本迭代 | M5-M8 缓存/DAO 优化 | 各 30-60% 延迟降低 | 中 |
| 后续 | H3 filecache LRU | O(n)→O(1) eviction | 中（需改数据结构） |
| 后续 | M7 PROPFIND 零拷贝 | 大目录 20-30% 提升 | 中 |
| 后续 | M9-M13 增量优化 | 各微小改善 | 小 |
