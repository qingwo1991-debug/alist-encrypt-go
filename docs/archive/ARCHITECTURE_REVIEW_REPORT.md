## alist-encrypt-go 综合架构评审报告

本报告基于对代码仓库的全面分析，覆盖客户端网络表现、首帧与拖动行为、预热机制、跨平台一致性、V2 完整性、加解密自洽性、学习系统设计评估以及应用场景总结。

---

### 一、客户端网络表现

#### 1.1 弱网环境

系统在弱网下的表现主要依赖三层机制协同：Retrier（指数退避重试）、Gate（全局熔断器）、Range 兼容性学习（自动降级策略）。

Retrier 配置为 3 次重试，退避序列 200ms → 400ms → 800ms → 2s（±25% Jitter），瞬态错误分类覆盖 timeout、connection refused/reset、broken pipe、DNS 失败和 TLS 握手超时。这套分类逻辑是合理的。但存在一个并发安全问题：`internal/backoff/retry.go:28` 中 `rand.New(rand.NewSource(time.Now().UnixNano()))` 返回的 `*rand.Rand` 不是线程安全的，多个 goroutine 并发调用 `backoff()` 时会触发 data race。在弱网环境下重试频率高，这个 race 更容易被触发。

Gate 熔断器设计为 5 次连续失败后熔断 30 秒。最大的问题是它是全局的而非 per-host。当代理服务器同时挂载多个 Alist 后端时，某一个后端的间歇性故障会导致所有后端的请求全部被拒绝 30 秒。这在多存储后端的部署场景中会造成不必要的服务降级。

另一个弱网下的隐患是流式管道缺乏 idle-read timeout。`streamDecryptResponse` 在 `io.CopyBuffer` 循环中读取上游响应体，如果上游在传输中途挂起（弱网常见的 half-open connection），当前没有 read deadline 保护，goroutine 会无限期阻塞，直到客户端主动断开或 TCP keepalive 超时（通常 15+ 分钟）。在高并发场景下会导致 goroutine 泄漏。

#### 1.2 强网环境

强网下系统表现良好。流式管道使用 `sync.Pool` 管理的 512KB 缓冲区 + `io.CopyBuffer` 做原地 XOR 解密，架构正确且高效。AES-CTR 自动利用 AES-NI 硬件加速，吞吐可达 2-4 GB/s，瓶颈完全在网络 IO 而非加密运算。

但有一个效率瑕疵：`applyStreamBufferConfig`（stream.go:50-64）在配置更新时整体替换 `sync.Pool`，导致旧池中正在使用的缓冲区归还后变成垃圾，触发不必要的 GC。实际上 `New` 函数已经通过 `atomic.LoadInt64` 读取动态大小，完全不需要替换池对象。

#### 1.3 代理表现不佳

当 Alist 上游响应缓慢或返回异常时，Range 兼容性学习机制会自动从 Range 策略降级到 Chunked（前 8MB 下载后丢弃）或 Full（完整下载 + SetPosition 跳转）。降级阈值为连续 2 次失败，恢复阈值为连续 3 次成功，并带有 reprobe 定时器定期尝试恢复。这套非对称阈值设计是正确的——降级快、恢复慢，避免了频繁的策略震荡。

不过策略选择器 `StrategySelector` 中存在一段死代码：cooldown 字段被写入（stream_strategy.go:208）但在 `Select()` 方法（lines 127-144）中从未被检查，意味着冷却期形同虚设。

---

### 二、首帧播放与拖动快进

#### 2.1 首帧优化

`classifyRequestRange`（stream.go:768-819）将 `bytes=0-` 或 `bytes=0-N`（N ≤ 2MB）的请求标记为 `IsFirstFrameHint`。当 Range 不兼容时，首帧请求优先选择 Chunked 策略（只下载前 8MB 而非完整文件），显著减少首帧延迟。

PlayBack Hints 机制为每个 URL 维护 2 分钟 TTL 的策略缓存。视频播放器在一次播放会话中会产生数十个 Range 请求，第一个请求经过完整的策略选择后记录 hint，后续请求直接复用，跳过了 Range 兼容性查找和策略决策树。这是播放场景下延迟最低的优化路径。

不足之处在于 `recentPlaybackStrategy`（stream.go:194-209）使用 `sync.Mutex` 而非 `sync.RWMutex`。这是一个读多写少的热点（高并发播放时大量读、偶尔写入新 hint），互斥锁会成为不必要的瓶颈。

#### 2.2 拖动快进

拖动到中间位置时，策略选择取决于 Range 兼容性和偏移量：支持 Range 时直接转发 Range 头（零延迟）；不支持 Range 时，偏移在 `chunkedSeekMaxDiscardBytes`（默认 8MB）以内用 Chunked（下载+丢弃），超过则用 Full（下载完整文件 + cipher.SetPosition）。

V2 格式下 Range 请求会自动加上 32 字节 header 偏移（`ContentMeta.UpstreamOffset`），这个转换是透明的。

`SetPosition` 在 AES-CTR 和 ChaCha20 上的实现有优化空间：每次 seek 都分配新的 IV slice 和 cipher 对象。视频 scrubbing 时每秒可能 10+ 次 seek，GC 压力会累积。AES-CTR 的 IV 可以改为 `[16]byte` 固定数组，ChaCha20 可以用 `SetCounter(0)` 重置而非重建整个 cipher。

---

### 三、预热功能与使用情况

#### 3.1 两套预热机制

代码中存在两套预热机制：`PrefetchManager`（prefetch.go）和 `ProbeScheduler`（probe_scheduler.go）。

PrefetchManager 是早期实现的遗留代码，功能简单：通过 HEAD 请求获取文件大小并缓存 24 小时。它的并发控制（信号量 + sync.Map 去重）设计合理，但功能已被 ProbeScheduler 完全覆盖。目前 PrefetchManager 仍然保留在代码中，增加了认知负担和维护成本。建议清理或标记为 deprecated。

#### 3.2 ProbeScheduler 设计评估

ProbeScheduler 是当前主力预热系统，1128 行代码，是代码库中最大的单个组件。核心功能包括：后台 worker pool 执行 probe 任务、per-provider 并发限制（信号量）、冷却期去重、最小/最大延迟控制、成功/失败统计环形缓冲区、CDN URL 预取等。

设计优点：worker pool + channel queue 的模型成熟可靠；per-provider semaphore 防止单个后端被 probe 流量淹没；`seen` map 带冷却期避免重复 probe 同一文件；观测性指标丰富（19 个 atomic 计数器 + 3 个环形缓冲区 + 6 个 map）。

值得关注的问题：`ensureAuth`（probe_scheduler.go:1013-1070）每次 probe 都调用 `fetchAlistJWT` 发起 HTTP 登录请求。100 个 probe 项就触发 100 次登录 HTTP POST。JWT token 应该缓存并在 401 时刷新，而非每次重新获取。

另外，1128 行的背景任务系统放在 handler 包内，职责边界模糊。ProbeScheduler 更接近一个独立的后台 job 系统，建议拆分为独立包（如 `internal/probe/`）。

---

### 四、跨平台逻辑一致性

#### 4.1 gomobilelib（Go Mobile Binding）

`gomobilelib/manager.go` 是服务端 `internal/server.Server` 的薄包装层，直接调用 `server.Start()` 和 `server.Stop()`。由于共享同一套代码，gomobilelib 与服务端具有 100% 的功能一致性，不存在逻辑分叉的可能。这是最理想的跨平台方案。

#### 4.2 Mobile OpenList（独立移动端代码）

`mobile/openlist-lib/openlistlib/encrypt/` 是一套完全独立的实现，有自己的 proxy、encryption、V2 支持、range learning、strategy selection。与服务端存在显著的功能差异：

**移动端有而服务端没有的**：Mix 混合加密模式、DB Export 同步、并行解密。

**服务端有而移动端没有的**：dir-sync 目录同步、JWT API 认证、HTTPS 支持、startup probe 启动预热、ProbeScheduler 后台预热。

最危险的差异在于 ChaCha20 V2 的位置溢出检查：服务端 `chacha20.go:88-92` 有 256 GiB 位置限制检查，移动端没有。超过 256 GiB 的位置在 ChaCha20 中会导致 counter 溢出，服务端会返回错误，移动端会静默回绕到流的开头，产生错误的解密输出。这是一个数据完整性风险。

V2 加密算法本身的实现（AES-CTR、ChaCha20、RC4-MD5）在三端之间保持了一致的参数选择（salt、nonce 长度、PBKDF2 迭代次数），密文格式互相兼容。但独立的代码库意味着未来任何修改都需要同步三处，代码分叉风险随时间线性增长。

#### 4.3 Docker 部署

Dockerfile 采用多阶段构建、CGO_ENABLED=0、Alpine 运行时，是标准的 Go 微服务镜像。但缺少 `HEALTHCHECK` 指令——尽管代码中已经实现了 `/health` 和 `/ready` 端点。容器编排平台（Docker Swarm、Kubernetes liveness probe 除外）无法自动检测服务健康状态。建议添加：

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q --spider http://localhost:PORT/health || exit 1
```

---

### 五、V2 vs V1 接口完整性

#### 5.1 V2 集成覆盖度

V2 格式在以下路径中正确集成：proxy 下载（`streamDecryptResponse` 自动检测 V2 header 并调整偏移）、proxy 上传（`NewLatestContentEncryptor` 生成 V2 header + 加密流）、WebDAV GET/PUT（通过 StreamProxy 走相同路径）、V2 Range 请求（`buildUpstreamRangeHeader` 自动加上 32 字节 header 偏移）。

文件名加密在 V1 和 V2 之间共享同一套逻辑，不存在分叉。

#### 5.2 PROPFIND 尺寸 bug（HIGH 严重度）

`webdav.go:1096-1157` 中的 `adjustPropfindContentLengthForV2` 在 PROPFIND 响应中对所有文件盲目减去 32 字节（V2 header 大小），包括 V1 格式的文件。V1 文件没有 header，不应该调整尺寸。这会导致 WebDAV 客户端（如 RaiDrive、Mountain Duck）显示 V1 文件大小时少 32 字节，影响文件校验和同步工具的判断。

修复方式：需要先检测文件是否为 V2 格式（可通过查询 DAO 中的加密元数据或检查是否有 V2 magic prefix），仅对 V2 文件减去 header 大小。

#### 5.3 V2 空文件上传拒绝

`content_v2.go:90` 中 `BuildV2Header` 拒绝 `plainSize <= 0`，导致无法创建 V2 格式的空文件。虽然空文件加密后只有 32 字节 header 没有实际数据，但这是一个合法的边界情况。应该允许 `plainSize == 0` 并生成只包含 header 的 V2 文件。

#### 5.4 V2 解析边界情况

`ParseContentHeader`（content_v2.go:114-116）在 magic 匹配但 prefix 不足 32 字节时返回 error。更合理的做法是 fallback 到 V1 处理——因为 magic 碰撞（前 6 字节恰好匹配）在加密数据中概率极低，如果确实发生了，返回 error 会中断请求，而 fallback 到 V1 至少能保证数据可读（虽然解密结果会是乱码，但用户体验上优于硬报错）。

---

### 六、加解密逻辑自洽性

#### 6.1 算法选择与参数

三种算法（AES-CTR、ChaCha20、RC4-MD5）均为 XOR 流密码，天然支持加解密对称性——同一段数据用相同密钥和位置做 XOR 运算即可加/解密。这是架构能实现透明加解密的基础，设计正确。

V1 参数：PBKDF2 1000 次迭代 + MD5 派生 IV（从 fileSize 确定性计算）。IV 确定性意味着相同密码 + 相同文件大小的文件会使用相同的密钥流，存在 nonce reuse 风险。在实际部署中，由于文件名已加密且文件大小分布通常较分散，这个风险是可接受的。

V2 参数：PBKDF2 600K 次迭代 + 16 字节随机 nonce + 32 字节二进制 header。安全性大幅提升，每次加密产生唯一的密钥流。600K 次迭代在 J4125 NAS 上约 1.5 秒，i7 约 200ms。

#### 6.2 V1 缓存 vs V2 无缓存

V1 在 `flow.go` 中通过 `passwdOutwardCache` 实现了 PBKDF2 结果缓存（30 分钟 TTL，以 password + encType 为 key）。V2 完全没有缓存——每个请求都重新执行 600K 次 PBKDF2 迭代。这是当前系统最严重的性能瓶颈（详见性能报告 H1），但不影响加解密的正确性。

#### 6.3 V2 header 格式

32 字节 header 布局：6 字节 magic + 1 字节 version + 1 字节 reserved + 16 字节 nonce + 8 字节 plainSize（big-endian uint64）。格式紧凑且自描述，magic 区分算法类型，version 支持未来升级，nonce 保证唯一性，plainSize 记录明文大小用于精确的 Range 计算。

设计上的一个小缺陷：reserved 字节当前固定为 0，但没有定义升级路径。如果未来需要使用 reserved 字节（比如存储加密算法参数），需要定义向后兼容策略。

#### 6.4 代码中的 V3 TODO

`content_v2.go:23-25` 有一条 TODO 注释建议 V3 迁移到 AEAD 模式（ChaCha20-Poly1305 或 AES-GCM）。这是正确的前瞻性思考——当前 V2 使用普通流密码，无法检测密文篡改。在云存储场景中，如果存储提供商出现问题（数据损坏、恶意篡改），当前方案无法感知。

---

### 七、学习系统设计评估

#### 7.1 总体判断

**略微过度工程化，但意图正确。** 核心学习模型（非对称连续计数器 + 多后端持久化 + reprobe 机制）设计合理且实用。过度工程化主要体现在外围的观测性基础设施和代码组织上。

#### 7.2 核心模型评价

Range 兼容性学习的核心是一个简洁的状态机：每个 host::storagePath 组合维护一个 `RangeCompatState`，包含 `Incompatible` 标志、连续失败/成功计数器、下次 probe 时间。连续 2 次失败降级，连续 3 次成功恢复，reprobe 定时器定期尝试。

这个设计的优点：非对称阈值（降级快、恢复慢）避免了策略震荡；多级持久化（内存 → BoltDB → MySQL）保证了重启后状态不丢失；per-host + per-storagePath 的粒度合理，不会将一个后端的特性错误推广到另一个后端。

#### 7.3 过度工程化的部分

ProbeScheduler 1128 行代码对于一个"预热文件大小和 Range 兼容性"的功能来说偏重。它实质上是一个完整的后台 job 调度系统（worker pool + queue + 并发控制 + 统计 + 重试 + 冷却 + per-provider 限流），却嵌入在 handler 包中。如果拆分为独立的 `internal/probe/` 包并精简到 500-600 行，可维护性会显著提高。

观测性指标数量庞大：19 个 atomic 计数器、3 个环形缓冲区、6 个统计 map。对于一个内部子系统来说，这个级别的观测性投入产出比不高。保留关键的 5-6 个计数器（成功/失败/跳过/队列深度/延迟）即可满足运维需求。

StrategySelector 的 cooldown 机制是死代码——写入但从未检查，说明设计中考虑了但实现未完成或测试未覆盖。

#### 7.4 缺失的部分

缺乏带宽/延迟感知的策略选择。当前策略决策树完全不考虑网络质量指标（RTT、吞吐量），一个高速宽带和一个高延迟卫星链路在系统看来没有区别。可以考虑引入 EWMA 延迟跟踪，在延迟高于阈值时主动从 Range 降级到 Chunked。

缺乏 per-host 熔断。全局 Gate 在多后端场景下过于粗放。

---

### 八、应用场景总结

alist-encrypt-go 的核心定位是 Alist 云存储代理的透明加密层，典型应用场景包括：

**家庭 NAS 远程访问**：通过 Alist 挂载百度网盘、阿里云盘等，alist-encrypt-go 在上行时加密、下行时解密，网盘提供商只能看到密文。视频播放是最主要的使用场景，对首帧延迟和拖动响应有较高要求。

**多用户共享加密存储**：不同路径配置不同密码，支持 WebDAV 协议供 RaiDrive、Mountain Duck 等客户端挂载。PROPFIND 的正确性直接影响客户端体验。

**移动端离线/在线播放**：通过 gomobilelib 嵌入 iOS/Android 应用，或通过独立的 OpenList 实现。需要关注与服务端的加密格式兼容性。

**企业文档加密存储**：将企业网盘作为后端，通过 alist-encrypt-go 提供透明加密。V2 的 600K PBKDF2 迭代提供了更强的密码暴力破解防护。

---

### 九、关键发现汇总

| 类别 | 发现 | 严重度 | 位置 |
|------|------|--------|------|
| Bug | PROPFIND 对 V1 文件错误减去 32 字节 | HIGH | webdav.go:1096 |
| Bug | Retrier `*rand.Rand` 并发 data race | HIGH | retry.go:28 |
| Bug | ChaCha20 移动端缺少 256GiB 溢出检查 | HIGH | mobile encrypt |
| 性能 | V2 PBKDF2 未缓存（200-1500ms/req） | HIGH | *_v2.go |
| 性能 | WebDAV 每次创建新 HTTP Client | HIGH | webdav.go 多处 |
| 设计 | 全局熔断器不适配多后端场景 | MEDIUM | backoff.go |
| 设计 | 流式管道缺少 idle-read timeout | MEDIUM | stream.go |
| 设计 | ProbeScheduler 1128行嵌入 handler 包 | MEDIUM | probe_scheduler.go |
| 设计 | prefetch.go 遗留死代码 | LOW | prefetch.go |
| 设计 | StrategySelector cooldown 死代码 | LOW | stream_strategy.go |
| 安全 | V1 确定性 IV（nonce reuse 风险） | LOW | aesctr.go |
| 兼容性 | V2 空文件上传被拒绝 | LOW | content_v2.go:90 |
| 部署 | Dockerfile 缺少 HEALTHCHECK | LOW | Dockerfile |

---

### 十、建议优先级

第一优先级应处理三个实际 bug：PROPFIND V1 尺寸错误（影响所有 WebDAV 客户端的文件大小显示）、Retrier data race（生产环境稳定性风险）、ChaCha20 移动端溢出（数据完整性风险）。

第二优先级实施 V2 PBKDF2 缓存和 WebDAV 共享 HTTP Client——这两项对用户体验的影响最直接，且改动量小（合计约 50 行）。

第三优先级考虑架构层面的改进：per-host 熔断器、idle-read timeout、ProbeScheduler 拆包。这些不影响正确性但提升系统的健壮性和可维护性。
