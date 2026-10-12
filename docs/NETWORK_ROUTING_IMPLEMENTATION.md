# 阶段 5：Android 网络路由与 MEGA 取消实现设计

本报告为只读源码研究后的设计交付，不代表功能已实施。研究期间已读取根目录及 `mobile/AGENTS.md`，未修改代码、构建脚本或依赖，未运行 build，未下载依赖。唯一新增产物为本设计文档。以下接口名称是建议，不是当前已有 API。

## 8 个关键点

### 1. 实际基线与桥接边界

- `mobile/android/app/src/main/kotlin/com/openlist/mobile/OpenListService.kt:265–345` 缓存 WiFi/cellular `Network`，但始终调用 `setEncryptDualNetworkMarks(0, 0, false)`，保留 Android 默认系统路由（包含 VPN/TUN）。Network handle 是 opaque 值，不可转换为 SO_MARK。
- 当前检索未发现名为 `networkdefault` / `systemrouting` 的包或符号；“system default routing”是现有行为，不是已存在的统一策略模块。
- `mobile/openlist-lib/openlistlib/server.go` 的 `Event` / `LogCallback`，以及 Android `model/openlist/OpenList.kt` 的实现，提供了现成的 gomobile callback 模式。官方 gobind 文档确认导出 interface 可由 Java 实现，方法应仅使用受支持类型，如 signed integers、string、boolean、byte slice、末尾 error。不要导出 `context.Context`、`syscall.RawConn`、`uintptr`、channel 或 `[]net.IP`。
- `mobile/pigeons/pigeon.dart` 是 Flutter→Android 配置面。它不应转发每次 socket bind 或 DNS 查询；数据面应直接 Go→gomobile→Kotlin。

### 2. 可实施的 Network bridge 与 FD 契约

建议在 `openlistlib/network.go` 导出以下 primitive-only 接口，再由内部适配器处理 Go 类型：

```go
type NetworkBridge interface {
    BindSocket(fd int64, routeID int64) int64
    StartDNS(queryID int64, routeID int64, host string, timeoutMs int64) int64
    PollDNS(queryID int64) string
    CancelDNS(queryID int64)
}
// SetNetworkBridge 安装或卸载服务生命周期内的桥。
```

`routeID` 为 Android registry 分配的 opaque token，对应固定 Network 实例及 topology generation；不是 netId/fwmark 位运算。旧 token 不可重指向新网络，失效返回明确错误。

- API23+ 使用 public `Network.bindSocket(FileDescriptor)`；API21–22 保持 default-only，不使用隐藏 API。
- Go 在 `net.Dialer.ControlContext` 中串接已有 ControlContext/Control，然后仅在 `RawConn.Control` 回调内同步调用 bridge。优先检查 context，不排队、不保存 fd、不异步绑定。显式设置 ControlContext 时需手动保留旧 Control 行为，因为 Go 不会再自动调用 Control。
- Kotlin 检查 fd 数值范围后执行 `ParcelFileDescriptor.fromFd(fd.toInt()).use { network.bindSocket(it.fileDescriptor) }`。`fromFd` 创建 dup：Go 拥有原 fd；Java 只关闭副本；两个 fd 共享同一底层 socket，绑定副本会作用于原 socket。禁止对原 fd `adoptFd`，禁止延迟持有 raw fd，禁止返回一个接管原 ownership 的 descriptor。
- bind 必须发生在 connect 之前，不关闭 Go 原 fd、不切换阻塞状态。返回值约定为 0 成功或正 errno；Go 转为 `syscall.Errno` 和 typed bind error。异常沿 cause 寻找 `ErrnoException`；SecurityException→EPERM，unsupported→ENOSYS，无法保真的异常→EIO；不能通过解析本地化异常字符串猜 errno。
- callback 可由多个 Go dial 线程并发调用：不依赖 main looper，不持 Go 全局锁进入 Java，先取不可变 registry snapshot 再出锁调用。bridge 用 application context，不持 Activity/Go proxy 引用环。service teardown 卸载桥并使 token 失效；只 retire idle connections，不强关正在播放的响应体。

### 3. DNS 必须与选中的 Network 一致，并明确系统版本限制

当前 `internal/net/prefer_v4.go` 和 `openlistlib/encrypt/dial_prefer_v4.go` 使用 `net.DefaultResolver`，并不保证和物理选网一致。新 route dialer 应先用该 route 的 resolver，再按地址族拨 IP，保留原 URL hostname / HTTP Host / TLS SNI。

- API29+ 可采用 `DnsResolver.query(network, host, A/AAAA, ..., CancellationSignal, executor, callback)`：StartDNS 注册查询，PollDNS 返回 pending/terminal 的受限结构化结果，CancelDNS 真正触发两个查询的 CancellationSignal。Go 用原 caller deadline，等待 context 取消时调用 CancelDNS，而不是遗弃一个阻塞 lookup goroutine。
- registry 必须有总量上限、并发上限、native deadline、终态消费/TTL、重复 cancel 幂等语义；executor 不得承担等待同 executor 的阻塞操作。deadline/cancel 后的迟到 callback 不得重新发布结果。应保留 API 的 DNS error category，不能把 DNS rcode 当成 errno。
- API23–28 `Network.getAllByName` 能进行 network-specific DNS，但没有本设计所需的强取消钩子。第一实施版本建议保持 default-only，或另设明确标注“不可强取消”的兼容模式；不能用 worker + select/Future.cancel 声称底层解析被取消。
- default route 保持系统 resolver 与 VPN/Private DNS 行为。显式选网失败不得偷偷用 default DNS 再继续绑定物理网络；如允许 fallback，应整体切换到另一个完整 route decision。

### 4. 先修 route 传递和连接池，不能只替换 SO_MARK

`openlistlib/encrypt/proxy_server.go:412` 的 IPv4 wrapper 先把 hostname 改为 IP，随后 `dual_network.go:640` 按拨号地址查询原 hostname→mark，常规域名请求可能因此丢失选网 hint。即使修复这一点，全局 host hint 在“同 host、不同 provider、并发请求”场景仍会串策略，HTTP keep-alive / HTTP2 复用也不会因下一次请求的 context 自动切换网络。

建议 RoundTripper 在每次请求前 Evaluate，然后选择有容量上限的 transport pool。pool key 至少包含 `{proxyEndpointRef, networkToken, generation, TLSprofile}`；池内 Proxy / Dial / DNS 闭包固定同一 decision。不要依赖全局 host→mark，也不要仅给 request context 塞 route 后期待共享 Transport 拨号与复用严格遵循。

配置或 topology 变化 retire idle，active streams 自然结束。fallback 仅在策略允许时、原预算内最多一次完整 default-route 尝试；探测失败不可把 default fallback RTT 归因到指定 WiFi/cellular。

### 5. 后端、控制面和 provider 统一策略，但分清 proxy 与 network 两个轴

建议新增无重依赖的 `internal/systemrouting` 或 `pkg/systemrouting`，提供 immutable `Evaluate(Purpose, originHost, provider, driver)` → `{proxyEndpointRef, networkToken, dnsMode, reason, generation}`。

优先级：控制面/loopback/local 的安全约束 → 显式 host/domain_suffix/provider/driver 规则（统一 priority）→ builtin → unmatched。HTTP `direct/proxy` 与 `default/wifi/cellular` 是正交轴；“禁 HTTP proxy”不等于“绕过 VPN”。默认不绕 VPN，显式 physical route 必须由用户明确允许。

当前入口并不统一：

- `openlistlib/encrypt/proxy_path.go:197–205` 控制 host 强制 direct，只取消 HTTP proxy；provider rules 在此生效。
- backend `internal/net/serve.go` 用 environment proxy；`internal/net/util.go` 用 `conf.Conf.ProxyAddress` 覆盖；`drivers/base/client.go` 的共享 Resty clients 不具备 provider-scoped routing。
- 后端应采用 driver-scoped clients 或内部 Go context metadata，不通过 URL 猜 provider，不在请求中动态修改全局共享 client 的 Proxy。
- 专用 transports（例如 WebDAV 等）须逐项接入；不能把修改 base client 当成所有 driver 已覆盖。
- 根目录 `internal/proxy/client.go` 属于另一个 Go module，已有 host rules；不能跨模块直接导入受 internal 边界保护的实现。应选择独立轻模块，或同步 policy schema 与一致性测试。

proxy 请求的 socket 实际连接 proxy endpoint，应解析/绑定该 endpoint，不预先解析 origin 来决定物理出口；HTTPS CONNECT / SOCKS remote DNS 保留 origin 的远端解析语义。endpoint credentials 仅留安全配置/内存，decision/pool key 使用 opaque reference。日志和 status 仅展示 reason、code、route kind；不要输出完整 proxy URL、userinfo、query、签名地址、原始 `url.Error` 或请求 token。控制面 Authorization 不得随跨 origin redirect 泄漏。

### 6. Android topology/lifecycle 仍需补齐

物理 WiFi/cellular callback 不能替代 default/VPN 变化监听。需分别监听 default route 与可用物理网络，generation 更新包含 VPN 开关、default 切换、同类型网络替换及服务重启。现 `OpenListService.kt` 的 API<24 分支调用 `registerDefaultNetworkCallback`，该方法需要 API24，必须修正 API gate。

`registerNetworkCallback` 是观察，不保证蜂窝在 WiFi 生效时持续可用。用户启用显式双网络时，如需要 `requestNetwork` 保持蜂窝，应单独持有并及时释放 request，检查权限、可用能力及错误，披露潜在蜂窝计费/电量影响。网络 lost 后不得让旧 token 指向别的 Network；新请求可按显式 fallback policy 重选，已有连接不能假装已经迁移。

### 7. go-mega 真源码有 HTTP 注入钩子，但没有完整生命周期取消

已通过公开 raw GitHub 源码确认 `go.mod` 锁定版本 `a19cff0ec7b5`：

- 存在 `SetClient(*http.Client)`，可注入携带 context 的 RoundTripper，真实取消 HTTP headers/body I/O；也存在 `SetRetries`、`SetTimeOut`。
- `SetTimeOut` 只更新 config 字段；`New` 已创建 client，不能把 setter 视为自动更新既有 HTTP client 超时。
- `api_request` 以 mutex 串行，使用 `client.Post`，默认多次 retry 和不可取消 `time.Sleep`。
- `MultiFactorLogin` → `getFileSystem` 无条件启动 `go pollEvents()`；pollEvents 无限循环，无 Close/ctx/退出分支。
- 登录最后 `WaitEvents(..., 5*time.Second)` 固定等待，不接受取消。

因此“依赖没有任何 transport hook”不准确；但“SetClient 即完成整体 3 秒预算与清理”同样不准确。取消 HTTP 后 poller 仍可无限失败重试，固定等待和 CPU 工作仍可超预算。当前 `drivers/mega/driver.go` 同步登录、前后检查 context 仅防止晚成功发布，不能证明 in-flight cancellation 或 cleanup。

### 8. MEGA 真正 bounded cancellable 实现需小型固定版本 fork

后续实现阶段建议固定 commit 的小 fork，而非 go+select 假超时：

- 增加 `MultiFactorLoginContext`、context-aware API request / NewDownload / DownloadChunk；HTTP 使用 request context；retry timer、队列/锁等待、WaitEvents 都响应 context/deadline，不叠加独立新预算。
- session context 与单次 operation context 分离。成功发布后才启动唯一 session poller；失败不发布且清理。`Close` 取消 session、退出并 join poller、关闭 idle；driver `Drop` 调用 Close。不能把 init deadline 永久绑定到后续所有操作。
- `SetClient` 继续用于统一 route policy、真实 HTTP cancellation 和网络 timeout，但不为每个操作改写共享 client。
- `drivers/mega/util.go` 目前 Read 持 mutex 调用 DownloadChunk，Close 会等待同一 mutex，不能中止正在阻塞的 I/O。reader 应持有专属 cancel，Close 先 cancel 再锁；真正调用 DownloadChunkContext；外层 `utils.Retry` 也应改为 context-aware。
- 密码派生/密码学调用不能任意硬抢占；在可分段循环/FS 解析处检查 context，并明确不可中断短 CPU 段可造成 overshoot。不能承诺硬实时精确 3 秒。
- 离线测试覆盖挂住 headers/body、backoff、event wait、poller Close/join、reader concurrent Close、未发布失败 session；仅 pre-cancelled 测试不足。

## 文件边界与实施顺序

1. **先定义 policy 与 route pool，离线测试先行。** 新轻量 evaluator、schema、安全 proxy endpoint reference；mobile backend 与 encrypt 各写 adapter，根 module 决定复用方式；测试规则优先级、控制面/default VPN 语义、跨 route pool 隔离及敏感信息 redaction。
2. **定义 gomobile primitive interface 与内部 dial/DNS adapter。** `mobile/openlist-lib/openlistlib/network.go`；新内部 registry/route dialer；修复 `encrypt/dual_network.go`、`encrypt/dial_prefer_v4.go`、`internal/net/prefer_v4.go` 的 hostname/route 传递。mock FD ownership、bind errno、generation 和 DNS cancel。
3. **新增 Android bridge，并接服务生命周期。** `android/.../bridge/` 新类、`OpenListService.kt`、`model/openlist/OpenList.kt`；补 API gate、default/VPN callback、opaque token registry、DnsResolver registry。Pigeon 仅有需要时扩配置/能力 status：改 `pigeons/pigeon.dart` 再生成，不能手改 generated outputs。
4. **逐入口接入统一策略。** `encrypt/proxy_path.go`、`encrypt/proxy_server.go`、backend `internal/net/serve.go` / `util.go`、`drivers/base/client.go`，以及专用 driver transports；明确实际覆盖清单。
5. **MEGA 固定版本 fork 与 driver adapter。** 后续才修改依赖声明；`drivers/mega/driver.go` / `util.go` 接 operation/session lifecycle；按仓库现有 source/build overlay 机制保持 `src` 镜像一致，避免重新初始化覆盖改动。此报告不修改构建脚本。
6. **CI 和设备验证。** 廉价格式/静态差异门禁之后，用 Draft PR CI 验证 gomobile 导出、Android 编译/lint、Go focused/race tests；不要反复本地重建重依赖图。

## 验证限定

本次没有执行测试、构建、bindings 生成或真机验证。源码分析和设计不等于 runtime 已支持。

必须人工/有设备的集成验证：API23/28/29+ 能力与 fallback；WiFi 与蜂窝同时可用；VPN/Private DNS/IPv6-only；权限拒绝；同类型网络替换；锁屏、lost/reconnect、service destroy/restart；fd 数量与 DNS registry 泄漏；跨 route HTTP2 复用隔离；active stream 不被 topology 通知强关。普通 host 测试不能自动证明这些 Android/OEM/运营商行为。

## 公开源码依据

- [gomobile/gobind 导出接口、受支持类型与引用环说明](https://raw.githubusercontent.com/golang/mobile/master/cmd/gobind/doc.go)
- [go-mega 锁定版本 a19cff0ec7b5：SetClient、登录、retry、pollEvents、下载](https://raw.githubusercontent.com/t3rm1n4l/go-mega/a19cff0ec7b5/mega.go)
- [AOSP Network 源码镜像：network-specific DNS、bindSocket、dup ownership、negative errno](https://raw.githubusercontent.com/msft-mirror-aosp/platform.packages.modules.Connectivity/main/framework/src/android/net/Network.java)

Android DnsResolver API29 cancellation 与各 API gate 在实施时还应依据目标 SDK 的公开 Android SDK 声明/官方文档复核；本次未编译验证 proposed interface signatures。
