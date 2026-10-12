# 播放工程满分验收路线

本路线对应用户批准的七阶段计划。安全不计入本次评分；不以 CI 全绿等同实际播放器首帧，也不承诺任意网络条件无卡顿。

## 当前基线与交付方式

基线为 PR #66 / main `848555676271d1e4b978354c2e81a929f5ceef89`。所有阶段使用独立 `agent/*` 分支、Draft PR、GitHub Actions；必需检查全部成功后合并，再验证 main 构建与发布。禁止仅为验证手动触发带发布副作用的 workflow_dispatch。本机仅执行格式、语法、diff 和轻量检查。

## 阶段状态

| 阶段 | 目标 | 当前状态 | 必须的完成证据 |
| --- | --- | --- | --- |
| 1 | 可重复故障上游、准确指标与播放测量 | 工程交付完成，真机未测 | 字节一致性矩阵、取消/关闭回归、结构化结果、浏览器帧测量工具；注明真机未测 |
| 2 | 移动端共享 V3 核心 | 工程交付与 main 发布完成，真机未测 | 所有移动播放入口 V3 正确读取；现有 V1/V2 兼容；云端绑定/APK 编译 |
| 3 | V3 小块配置、认证缓存、受控回退 | 工程交付与 main 发布完成，真机未测 | 下载放大与缓存收益对比；身份/版本隔离；有界资源；旧格式兼容 |
| 4 | 切集兴趣调度与有界 KDF | 工程交付与 main 发布完成，真机未测 | 旧任务收敛、最终目标优先、取消等待者、不产生派生风暴 |
| 5 | 驱动取消、控制面路由、原生选网 | 工程交付与 main 发布完成，真机未测 | 可取消真实传输与退避；固定路由分池；Android 平台支持桥；设备能力边界 |
| 6 | 非 UI 文件写入、统计锁外、同步维护 | PR #72 最终全绿已合并，main 完整发布待核验；真机未测 | 文件逐字节正确、取消与隔离、资源稳定、源码覆盖冲突检测 |
| 7 | 完整云端及真机验收矩阵 | 验收交付文档已编写，待云端与 main 发布收口；设备待人工验证 | main 全绿、发布产物；设备测试通过或明确标注待人工验证 |

每阶段完成时填写 PR、最终提交、Actions 链接和残留项，不提前标记。

## 阶段 1 实现与证据入口

- `internal/playbacktest`：仅 loopback 的上游，支持 Range accept/ignore/reject、重定向、HTTP 状态、截断、响应头/正文 gate、延迟和带宽限制，Close 能释放故障等待。
- `internal/proxy/playback_acceptance*_test.go`：V1/V2/V3 共 36 个精确正文与范围组合、6 个下载取消、12 个重定向/错误场景和 2 个元数据取消场景。`PLAYBACK_ACCEPTANCE_REPORT` 指定绝对路径输出 JSON；量化的是上游 Write 接受字节，不是 TCP 流量或播放器渲染。
- `tools/playback-probe`：独立 HTML 工具，使用 requestVideoFrameCallback 测首帧/seek 的 compositor submission 延迟，隔离过期回调、来源与缓存标签，API 不支持时明确 unsupported。不会自动绕过授权或清理缓存；不是应用内外部播放器的测量代理。
- 统计页面区分响应头与正文首字节，不以历史响应头代替新指标。移动重定向直读/解密缓存路径增加 handler 开始至首次成功正文写出的计时、SQLite 兼容迁移与会话保留，旧记录没有该字段即未知；legacy 路由及原密文下载未据此宣称完整播放遥测。真实渲染指标只来自测量工具/未来播放器事件。
- Actions 添加 fault acceptance artifact 和独立 Node 测量语义测试；新增测试也作为后续构建发布依赖。首阶段 [PR #67](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/67) 全绿合并，main `2374ca3` 的 [Actions 38197844019](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38197844019) 测试、竞态、Docker、跨平台二进制、三 ABI AAR/APK 与发布全部成功。未宣称真机测试通过。
- 后续实现设计：`docs/MOBILE_V3_IMPLEMENTATION.md`、`docs/NETWORK_ROUTING_IMPLEMENTATION.md`。

## 阶段 2 云端证据

- [PR #68](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/68) 已全绿合并至 main `78aff12`：共享 V3 header/trailer/认证 record 读取、完整 metadata 缓存及 SQLite/sync 字段，覆盖移动下载、DAV 和播放 token 入口；有界 record 内存及 Range 忽略回退，保留显式 raw 下载。
- 最终 [Actions 38200886879](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38200886879) 的根/共享/移动 Go、竞态、故障基线、MySQL、两个 Web UI、Flutter、probe、Docker 及三 ABI Android binding 全部成功；actual/src readonly 模块覆盖和同步源码测试通过。main 完整发布 [Actions 38201569198](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38201569198) 已全绿，包括跨平台二进制、Docker、三 ABI AAR 和 APK、核心及移动发布；版本 [v2026.10.12.371](https://github.com/qingwo1991-debug/alist-encrypt-go/releases/tag/v2026.10.12.371)。
- 修复正常 fs/get 重复播放的 V3 metadata 降级、响应前一次签名 URL 刷新、disabled/raw 表示、DAV 选定目标重新确认和 request 内 metadata 复用。warm cache key 补齐算法字段；云端另发现调度 FIFO 在扫描中释放 provider slot 的生产问题，采用原子释放修复，保留严格 FIFO 断言并在云端连续运行 32 次通过。
- 真机首帧和弱网收益仍未验证；后续认证缓存、KDF 排队、路由平台桥和目录生命周期按阶段 3–6 实施。

## 阶段 3 实施与云端证据

- [PR #69](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/69) 经独立审查补修后，全绿合并至 main `0d47488`。最终 [Actions 38203768488](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38203768488) 包括根/共享/移动测试及竞态、故障/放大验收、MySQL、Web、Flutter、Docker、三 ABI binding 全部成功；main [Actions 38204243215](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38204243215) 完整 AAR/APK 与核心发布成功，版本 [v2026.10.12.375](https://github.com/qingwo1991-debug/alist-encrypt-go/releases/tag/v2026.10.12.375)。

- 新文件 CLI/API/UI 增加 opt-in 1 MiB V3 chunk；省略/0 保留 16 MiB，最大 32 MiB，V2 和旧文件读写不会继承新文件配置。UI focused tests 8/8 本地通过，新增 Go 回归已在上述云端通过。
- 共享整 record 认证缓存采用不可变 lease 与 resident/pinned/inflight 加权预算；root/mobile 各 64 MiB，与既有 256 MiB 传输 record admission 分开计数。无可信 revision 时 identity 保留完整 URL，不能宣称签名轮换复用。
- root/mobile 实现 warm tiny seek 和 bounded prefix + 单个冷 tail HTTP 连接；首个冷 record 认证后才提交缓存前缀。root 的 Full/Chunked discard budget 在取正文/KDF/成功响应之前终止，不对超预算窗口换 URL 再下载。
- 云端放大报告：同样 4096 字节 tiny seek，1 MiB/16 MiB chunk 的冷请求分别读取 1,048,592 / 16,777,232 字节（整认证 record 加 16 字节 tag），同块另一区间的热请求均零上游请求、零正文读取。fixture KDF iterations=1，只比较正文放大，不衡量生产 KDF CPU 或 TCP/播放器延迟。
- 审查补修：4096 条目上限包括 resident、reserved 和 evicted-but-pinned；移动 scope 保守绑定完整原始/存储请求头，custom provider token 和 representation selector 不得跨身份复用。

## 阶段 4 实施与云端证据

- [PR #70](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/70) 经独立复审与补修后全绿合并至 main `fa8ee6b`。最终 [Actions 38210123567](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38210123567) 根/共享/移动测试、竞态、故障验收、MySQL、Web、Flutter、Docker 及三 ABI binding 全绿；main [Actions 38210664342](https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/38210664342) 完整二进制、Docker、三 ABI AAR/APK 与发布成功，版本 [v2026.10.12.381](https://github.com/qingwo1991-debug/alist-encrypt-go/releases/tag/v2026.10.12.381)。
- 接入固定 worker、有界队列及可取消等待的 V3 KDF service，保留原 256 项/sliding TTL/copy 缓存；不创建逐 flight/waiter 的 goroutine。已启动的 PBKDF2 不可抢占，最后 waiter 取消也不会提前释放真实 CPU slot。
- root/mobile context-aware foreground 派生成功后才持有 record buffer admission；HEAD 和整 record 热命中保持零 KDF。speculative admission 为前台留 queue/waiter 名额；尚未启动的 queued promotion 在最后 foreground 引用撤销后恢复 speculative，运行中的分类保持不变。
- 可信 session/provider/scope/generation 调度及鉴权 explicit-intent API 已实施，详见 `PLAYBACK_INTEREST_API.md`。任务绑定 endpoint 验证时的同一份完整配置快照；排队期间切换 provider 凭据/origin 不改变旧任务，登录与 metadata 的真实传输使用任务 context。多 session 共享引用、最后兴趣撤销与真实转移结束后的资源归还均有回归。
- 不凭 IP、Range 或猜集识别用户会话，不将 generation context 挂到活跃 HTTP media 请求。现有管理页面没有嵌入式播放器 session；这是显式客户端接口，不是外部播放器自动切集报告，也未据此宣称真机性能改善。

## 评分与硬性门槛

- 播放正确性/跨端一致性：25；首帧/拖动/切集：25；网络隔离/恢复：20；资源性能：15；代码质量/验证：15。
- 错误明文、下载损坏、无界等待、持续资源泄漏任一存在，不满足接近满分验收。
- 验证支持能力，而不是将明确拒绝等同完整支持；PR #66 的移动 V3 基线为 415，阶段 2 已通过移动共享认证读取的云端入口回归，仍不能据此声称所有真机播放器已通过验收。
- 实际媒体首帧需播放器渲染事件；服务端响应头和正文首字节只代表相应传输阶段。
- 时间阈值先记录分网络档位基线，再定义可实现的验收阈值；不能以大于物理带宽的速度作为门禁。

## 阶段 5 云端与发布证据

- PR #71 最终提交 `aff4172` 的 Actions `38222901370` 全绿：真实 MEGA context/Close/backoff 回归、driver client 与路由竞态、三 ABI gobind、Docker，以及使用实际 AAR 的 Kotlin release APK 编译。
- 合并 main `64aab3c` 后 Actions `38224427891` 全绿，发布 `v2026.10.12.388`，包含跨平台二进制、Docker、三 ABI AAR/APK。临时阶段五分支已删除。
- 实际新 driver factory 集成仅 MEGA；其他全局 Resty 驱动不宣称已迁移。原生 DNS/socket、API/OEM/VPN 转换仍需真机验证。实现与能力边界详见 `NATIVE_ROUTING_ACCEPTANCE.md`。

## 阶段 6 实施与云端证据

- PR #72 最终 `d8ebcad` Actions `38228847370` 全绿并合并 main `780e221`；main Actions `38230426917` 正在核验。
- 实例统一生命周期 context 与准入 fence，未 Start/监听失败也清理构造资源；catalog/range/meta/目录预热/预取真正取消并 join，HTTP handler 实际退出后才关闭 SQLite。启动备份纳入 store 自有 join，并发 Close 等同一次真实完成；关闭前刷新播放 session。备份主文件复制仍为 best-effort，不声称在线 WAL 一致性。
- Flutter 下载完整异步 seek/write 事务串行化，最多四笔 pending 私有缓冲区；取消时等待真实写入与全部 worker，之后才关文件/删除/fallback。通知与回调入口同步预约文件路径避免尚未创建文件时重名。完整 10 MiB + 7 bytes 交错字节验证保持。
- 26 个上游维护路径 pristine 固定指纹、新文件冲突、tag/commit 变更拒绝与 actual/src 一致性门禁已通过；覆盖边界见 `mobile/openlist-lib/scripts/SOURCE_OVERLAY.md`。统计锁外持久化已有实现保留，未重复重构。
- 工程与设备验收分层矩阵、指标语义和签收门槛见 `PLAYBACK_FINAL_ACCEPTANCE.md`。

## 已确定的实现约束

### 移动共享 V3

移动加密代码是独立实现，不能导入根 `internal/proxy`。适配独立 `shared/encryptcore` 模块的公开接口，显式映射类型：移动 AES 名称为 `aes-ctr`，共享名称为 `aesctr`。不能未经迁移直接给 ContentMeta 作别名。覆盖 `/d`、`/p`、`/dav`、`/dav2` 与重定向入口，不允许 V3 落入旧 cipher 或明文密文透传 fallback。模块覆盖初始化必须保留共享依赖及固定 gomobile 版本，不能让 reclone 恢复旧 go.mod。

### 后台目录生命周期（阶段 1 云端竞态新增证据）

首阶段缓存路由测试在构建 ProxyServer 后替换/关闭 localStore 时暴露 provider catalog 后台刷新与 localStore 关闭的竞态。缓存计时 fixture 应禁用无关后台任务，而不是以隔离测试宣称生产生命周期已解决。阶段 6 PR #72 已将 catalog 的真实 HTTP context、后台准入及 join 纳入实例生命周期，localStore 初始化先于消费者，关闭时不再清空公开指针，并等待后台与 handler 实际完成。上述原始缺口已通过真实取消/关库顺序回归修复；设备资源稳态仍待人工验证。

### Android 与驱动

支持式 socket 绑定应通过平台 Network API，不能把 network handle 推算成 SO_MARK。路由决定必须不可变、DNS 与 socket 同网络、连接池按路由隔离；不能依靠全局 host hint。API 及权限不支持时明示 default-only。HTTP proxy bypass 不等于 VPN/TUN bypass。

原始 MEGA 依赖虽有 SetClient，但缺少 session poller、重试等待和 WaitEvents 的取消生命周期。阶段 5 已以保留原模块身份/license/源码的固定 fork 实现真实 context/Close、取消退避、poller join，并接入固定 driver client；不能把这项已完成的实现归为未解决，也不能据此声称所有驱动或真实账号/OEM/VPN 已验收。

## 真机验收记录要求

至少记录设备型号、Android/API、播放器/codec、应用版本、文件格式/chunk 配置、云盘类型、冷/热缓存、网络 RTT/限速与 VPN 模式。记录播放器首帧、seek 恢复、连续切集的 p50/p95；同时记录下载放大、取消后请求、峰值内存和连接数。

矩阵包含：国内可达/海外不可达、坏 HTTP 代理、系统 VPN 正常/失效、Wi-Fi/蜂窝切换、Private DNS/IPv6-only、权限拒绝、锁屏后恢复、配置热更新、首段/尾段/随机 seek、快速十次切集。工具输出不能替代外部播放器行为测量。没有设备证据时只标记代码及云端验证完成。
