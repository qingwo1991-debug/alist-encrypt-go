# alist-encrypt-go 性能独立复审报告

本次复审直接对照当前源码，重点核验已有的 `PERFORMANCE_ANALYSIS_REPORT.md`，并补查缓存、统计、数据库和流式请求路径。结论按“源码事实 + 实际调用频率 + 影响范围”分类；没有把微小分配或只存在于旧版本的代码当成高优先级问题。

## 结论摘要

当前没有证据表明项目存在“所有下载每次都重新 PBKDF2”或“WebDAV 每请求都新建 HTTP Client”这类高危通用瓶颈。当前最值得处理的是：

1. `PathCache` 双索引在淘汰、过期清理和更新时的一致性问题，可能积累无效展示路径索引。
2. `FileDAO.Set` 在缓存冷或首次写入时的读后写，放大目录元数据入库的 BoltDB 事务数。
3. 统计持久化在事件落库/删除路径上反复全量读取 stats bucket；聚合器还会在持锁期间同步执行该 I/O。
4. RC4-MD5 是遗留模式，随机 seek 和持续解密都采用逐字节算法；只影响实际启用 RC4 的部署。
5. MySQL 元数据新记录写入前的 SELECT，以及无界的 handler 级去重 map；影响取决于元数据写入量和运行时长。

建议先通过 pprof/业务指标确认热点，再处理 1-3。当前不建议优先投入到 AES-CTR 的十几字节 discard 缓冲、重复计算短 cache key 等微优化。

## 当前确认存在的问题

### P1 — PathCache 双索引可能留下无效索引，且展示索引无容量约束

**位置：** `internal/dao/path_cache.go:88-115,224-280`

`Set` 将加密路径放入加密路径 shard，将展示路径放入展示路径 shard。两个路径通常 hash 到不同 shard。问题在于 `evictOldest` 和 `CleanExpired` 遍历 `byEncPath` 时，却直接对当前 shard 的 `byDispPath` 删除展示索引：

```go
delete(shard.byDispPath, entry.DisplayPath)
```

如果展示路径属于另一 shard，这个删除没有效果。于是加密索引已经被淘汰或过期，但展示索引仍然保留指向旧 `PathEntry` 的指针；后续 `GetByDispPath` 只能发现过期并返回 miss，不会清理它。`byDispPath` 也没有独立容量上限，因此大量不同路径持续淘汰后，展示索引可能比 `byEncPath` 大得多，形成长期内存增长。

另外，`Set` 用同一加密路径更新为新的展示路径时，没有删除旧展示路径索引；更新展示路径时也可能留下旧的加密索引。高频元数据更新会进一步放大无效索引数量。

缓存还把同一个可变 `*PathEntry` 返回给调用者。`FileDAO.SetFileSize`、`DeleteFileSize`、`InvalidateDisplayPath` 和 `SetEncPathMapping` 会在 PathCache 锁外直接修改该对象（`internal/dao/file.go:374-380,478-488,510-515,522-539`），而并发读者也在锁释放后访问其字段。这会形成数据竞争，并可能让读者看到字段组合不一致。它首先是并发正确性问题，也会降低缓存稳定性。

**影响：** 中高。通常不是立即的单请求 CPU 热点，但长期运行、路径数量大或频繁更新时会造成内存增长和低命中率；并发更新时还有数据竞争。它不应只作为淘汰扫描微优化处理。

**建议：** 让缓存内部持有不可变 entry，Get 返回值拷贝，更新通过统一方法生成新 entry；索引管理应成为一次可验证的跨 shard 操作。删除 entry 时按 `getShard(entry.DisplayPath)` 删除反向索引，并在 Set 更新前清理旧的 display/encrypted key。最好增加单独的 entry identity/删除辅助函数和测试；必要时对总 entry 数而不是单个 `byEncPath` 做容量控制。注意跨 shard 加锁需要固定锁顺序，避免死锁。

### P2 — FileDAO.Set 在元数据写入前无条件 Get

**位置：** `internal/dao/file.go:180-294`，调用方 `internal/handler/alist.go:893-906`、`internal/handler/webdav.go:1051-1057`

`FileDAO.Set` 首先调用 `d.Get(info.Path)`。缓存未命中时会执行一次 BoltDB `View` 和 JSON 反序列化，然后再执行 `SetJSON` 的写事务。`SetComplete` 已存在并能跳过读，但正常 Alist 元数据摄取仍主要走 `Set`。

**影响：** 中等，主要影响首次入库、缓存冷却后重新入库和大目录列表。它不会让每次写入都必然增加一次磁盘读：缓存命中时只是内存查找；MySQL writer 启用时后续写入也不是 BoltDB 写，但仍有读前合并和 MySQL 元数据处理。

**建议：** 对能证明字段完整的上游响应使用 `SetComplete`；需要合并时再读。若必须保证原子合并，可在同一个 BoltDB `Update` 事务内读取并写回，减少事务往返。

### P3 — stats bucket 在持久化事件路径上被反复全量读取

**位置：** `internal/handler/stats_store.go:86-155,212-239`，`internal/storage/store.go:159-173`

`RecordPlayback` 每次写入后调用 `pruneLockedIfNeeded`，该函数即使在未超过 `statsMaxEvents` 时也先执行 `GetAll(BucketStats)`，把整个 bucket 的 key/value 复制到内存。`RecordDeletion` 先调用 `lastPlayForPath` 再调用 prune，因此一次删除最多会全量读取两次。`GetAll` 会复制每个 value，而不是只读取 key。

播放请求并非全部直接落库：`stats_session.go:22-103` 会把同一路径 30 秒窗口内的 Range 请求聚合。但超窗会话的 flush 仍会进入该路径，删除请求则直接调用 `RecordDeletion`，所以长期运行后 stats bucket 越大，事件写入成本越高。

更严重的是，`serverPlaybackSessionAggregator.record` 在持有 `a.mu` 时调用 `flushLocked`，而 `flushLocked` 同步执行 `StatsStore.RecordPlayback`（`stats_session.go:78-125`）。当旧会话需要 flush 时，所有其它播放事件都会等待 BoltDB I/O 和全量扫描。

**影响：** 中高，取决于统计是否启用、事件量和 bucket 大小；删除接口和会话切换时更明显。它不是每个原始 Range 请求都触发的二次方热点，原报告对此表述过强。

**建议：** 维护内存中的 `path -> latest PlayedAt` 索引并在启动时一次重建，或增加按路径查询的专用 bucket/key；prune 改成低频定时任务或每 N 次写检查。聚合器应先在锁内摘出待 flush 会话，释放锁后执行 BoltDB 写入；`flushAll` 同样不要在全局会话锁内做 I/O。

### P4 — RC4-MD5 持续解密和随机 seek 都是逐字节处理

**位置：** `internal/encryption/rc4md5.go:109-173`

RC4 的 PRGA 每字节更新状态并执行取模。`SetPosition` 先重置 KSA，再用 `prgaAdvance` 从段起点逐字节推进，段内偏移最多约 1 MB。每到 1 MB 还会重新执行一次 KSA。

源码中确实有 `make([]byte, 4)`、hex 解码和 `make([]byte, 256)` 等段重置分配，但这些不是主要成本；主要成本是 RC4 本身的串行逐字节算法和 O(offset) seek。

**影响：** 中等但范围窄，只影响配置为 `rc4md5` 的 V1 遗留文件。AES-CTR/ChaCha20 V2 不受此项影响。若生产环境没有 RC4 文件，应降级处理，不应按通用下载瓶颈排序。

**建议：** 不要为新文件使用 RC4。若必须兼容旧文件，可先做基准测试，再考虑段状态/keystream checkpoint；简单池化三个小 buffer 不会改变主要复杂度。

### P5 — MySQL 元数据 Upsert 对新/变化记录先做同步 SELECT

**位置：** `internal/handler/mysql_store.go:487-524`，`internal/storage/mysqlstore/file_meta.go:19-80`

handler 层 `MySQLFileMetaStore.Upsert` 先用 `lastMetas` 做内存去重。只有新记录或元数据变化时，才调用 `GetFileMeta` SELECT，再把结果用于保留 V2 字段，最后调用写后缓冲的 `UpsertFileMeta`。因此“每次 Upsert 都 SELECT”不准确，但每个新/变化 key 确实多一次数据库往返。

`UpsertFileMeta` 只是入写后缓冲，额外 SELECT 仍然是同步路径，可能增加目录扫描或首次播放元数据解析的延迟。`lastMetas` 本身是无界 map（`mysql_store.go:419-430`），高基数路径长期运行还会造成内存增长。

**影响：** 中等，取决于元数据变更率和 MySQL RTT；相同值重复上报会被内存去重，不会重复 SELECT。无界 map 是独立的低到中优先级内存风险。

**建议：** 把 V2 字段保留逻辑完整地下沉到 `ON DUPLICATE KEY UPDATE`，或维护有界 TTL/LRU 的已知元数据缓存；给 `lastMetas` 设置容量和淘汰策略。

## 事实存在但优先级较低的问题

- **代理配置快照/排序：** `internal/proxy/client.go:193-256` 的 `Transport.Proxy` 回调确实在出站请求时调用 `ProxySnapshot` 和 `cloneProxyRules`，后者还会排序。它是每个 outbound request 的分配、锁和排序开销，但通常规则数量很小；当前证据不足以评为 HIGH。配置变更时预计算排序后的不可变快照可以优化。
- **raw URL resolver：** `internal/handler/raw_url_resolver.go:19-126` 在解析最终直链时每次 cache miss/刷新创建 client；解析结果随后会被缓存（`cacheResolvedRawURL`）。因此不是每次下载都额外握手，影响主要在直链缓存 miss、过期或重定向刷新时，评为 LOW。`internal/handler/prefetch.go:104` 每个后台预取任务也创建 client，是低优先级连接复用优化。
- **AES-CTR/ChaCha20 seek discard：** AES 在 `aesctr.go:77-103`、ChaCha20 在 `chacha20.go:78-105` 会创建很小的 partial-block discard slice；AES 还会重建 CTR stream。最多 15/63 字节，通常远小于网络和解密开销，评为 LOW。不要用“每次 seek 分配 IV”描述当前 AES 代码，IV slice 已复用。
- **decrypted block cache key：** `internal/proxy/stream_download.go:217-283,560-614` 在启用缓存且发生 GET Range cache miss 时会重复计算 base key。重复 SHA-256 和格式化确实存在，但只发生在特定路径，属于 LOW；同一请求内算一次即可。
- **ResolveBatch 外层协程数：** `internal/handler/filesize_resolver.go:154-185` 每个 item 启动一个 goroutine，内部 HTTP 工作另有 semaphore 限制。当前源码未找到生产调用方，属于潜在的批量输入放大问题，不应当描述为当前请求热路径瓶颈；若以后用于超大目录，应增加有界任务队列。

## 已核验为旧报告错误或当前已修复

| 旧结论 | 当前核验结果 |
|---|---|
| V2 PBKDF2 未缓存、每个下载请求重复派生 | **错误。** `internal/encryption/flow.go:56-170` 已有 TTL、singleflight 和最多 128 项的 `v2KeyCache`。V2 构造器仍会做小的 key/nonce 拷贝，但不是 PBKDF2 热点。 |
| WebDAV 每请求新建 HTTP Client | **错误/已修复。** `internal/handler/webdav.go:91-106` 创建共享 transport 和 client。 |
| filecache eviction 始终 O(n) 全表扫描 | **已修复。** `internal/cache/filecache.go:139-188` 使用最多 8 项的 bounded sampling。 |
| 每次 probe 都重新登录获取 JWT | **已修复。** probe JWT 有 2 小时缓存，401 会失效重取。 |
| discardBytes 完全未池化 | **已修复。** 大于 4 KB 的 discard 使用 buffer pool。 |
| playback hints 读路径使用普通 Mutex | **已修复。** `internal/proxy/stream.go:74` 为 `sync.RWMutex`。 |
| PROPFIND 必然做完整 string->byte 双重转换 | **已部分修复。** 当前使用 `bytes.Buffer` 单趟构建，但单条目仍有局部字符串转换。 |
| MySQL strategy/range 列表无 LIMIT | **已核验有 LIMIT。** |
| `GetJSON` 还有额外 `append([]byte(nil), data...)` 二次拷贝 | **错误。** `internal/storage/store.go:175-185` 的 `GetJSON` 只调用 `Get` 后直接反序列化；`Get` 内部的一次拷贝是 BoltDB 返回数据所需的正常拷贝。 |
| sync.Pool 配置更新整体替换 | **已修复。** 当前使用原子配置值创建 buffer，未整体替换正在使用的 pool。 |

## 当前设计中表现合理的部分

- `internal/proxy/client.go:85-113,274-305` 有共享 transport、连接池、连接/请求超时配置；流式 client 明确不设置总请求超时。
- `internal/handler/filesize_resolver.go:94,300-345,391-479` 对 HTTP 请求有 semaphore 限制，并支持多来源早返回和按 host 熔断；没有确认到串行 N+1 的生产热点。
- `internal/proxy/stream_download.go:590-592` 使用池化 buffer 和 `io.CopyBuffer`；调用方关闭 upstream body，未确认客户端断连后上游持续空转的泄漏。
- `internal/proxy/stream.go:148-168` 有 `MaxActiveStreams` 限制，避免解密流无限并发侵占内存和 CPU。
- MySQL 写后缓冲在 `internal/storage/mysqlstore/buffer.go` 中先交换 map、再锁外复制；旧报告关于持锁 O(n) 的结论已不适用。
- V2 使用标准 PBKDF2 缓存和标准 AES/ChaCha 实现；在常见硬件上，网络和上游响应通常比这些小对象拷贝更值得优先测量。

## 推荐处理顺序

1. 修复并测试 `PathCache` 跨 shard 删除、更新旧索引和展示索引容量问题。
2. 对 `FileDAO.Set` 的完整元数据入口使用 `SetComplete`，保留确实需要字段合并的读路径。
3. 将 stats flush/prune/last-play 查询从高频事件和聚合锁中移出；至少先把 prune 改为低频检查。
4. 如果生产仍有 RC4 文件，再针对 RC4 做 benchmark 和 checkpoint 设计；否则不优先改遗留算法。
5. MySQL 部署且元数据写入量大时，再处理预读 SELECT 和 `lastMetas` 的 TTL/LRU。
6. 只有 pprof 显示仍是热点时，才处理代理快照、cache key 和小 discard 分配。

建议验证时关注：`pprof` CPU/alloc、BoltDB `GetAll(BucketStats)` 调用耗时与次数、PathCache `byEncPath/byDispPath` 条目数、MySQL `GetFileMeta` QPS，以及按 `EncType` 区分的流式 CPU 占用。
