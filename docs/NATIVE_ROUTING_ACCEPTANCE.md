# 阶段五原生路由实现与验收边界

实施入口：[Draft PR #71](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/71)。本文件描述已提交的实现，不提前宣称阶段完成或真机性能通过。

## 路由所有权

- Go 在 `RawConn.Control` 内同步调用 Android `Network.bindSocket`；Kotlin `ParcelFileDescriptor.fromFd(...).use` 只关闭 duplicate，不接管原 Go descriptor。
- Android 网络实例使用唯一 opaque token，native generation 不重指向其他 Network。桥更换另有 `BridgeEpoch`，使旧连接身份失效；不与 Kotlin generation 抢计数。
- control/probe/media 请求选取 immutable transport，key 包含代理身份摘要、token、generation、bridge epoch、profile。每个 proxy pool 最多 32 项；每个实际接入的 MEGA storage session 另有最多 32 项池，不应把后者描述为所有 storage 合计只有 32 项。
- Proxy/Dial/DNS 从同一份决定捕获，网络变化退休 idle，活动 body 在 EOF/Close 后释放。没有按新的请求 context 强行改已有连接的网络。
- HTTP proxy bypass 和 physical network selection 是两个轴。国内 direct 不自动等于绕 VPN；只有启用 dual-network 的显式决策才能请求 physical token，缺失时拒绝，不伪装默认路由成功。
- 同 route 的 H2C 仅用于启动探测已确认支持的配置 backend、direct control/probe；media 保留响应头预算。代理流量不能借 H2C 绕过代理。配置 reload 不复用旧 backend 的 H2C 探测，重启后重新探测。

## DNS 与 Android 能力

- API29+ 用被选 Network 的 `DnsResolver` A/AAAA 查询及两个真实 `CancellationSignal`。最多 64 registry entries、固定两个 callback worker、64 callback queue；deadline 最长 15 秒、未消费终态保留最多 30 秒。
- Go 在 caller 内轮询，不遗弃 lookup worker；取消触发 native cancel。终态消费、记录 identity 和取消防止迟到回调使旧查询复活。
- 原生连接保留 HTTP hostname/TLS SNI，按地址族过滤、IPv4 优先并给多个地址分配整体 deadline 内的子预算。实现是有界串行回退，**不是并行 Happy Eyeballs**。
- API23 具 public FD binding，但 API23–28 缺少本实现所需的强可取消 selected DNS，因此不发布 selected tokens。普通请求仍可默认系统路由；用户显式请求 physical route 时不应据此认定已支持。
- API21–23 不调用 API24 `registerDefaultNetworkCallback`；同 Service backend 重启幂等重装 monitoring，旧 callback 不能修改新 bridge。

## 驱动与固定 fork

- `shared/go-mega` 基于固定 upstream `a19cff0ec7b5ccca340d51f4b71e01266c92bb24`，保留模块身份、原始 MIT LICENSE 和上游测试；actual/src 用受控相对 replacement，不拉取 latest 或自动 tidy。
- 登录、metadata、chunk、upload 的真实 HTTP 请求使用 context；API 等待及 retry/backoff timer 可取消。session 生命周期不从成功登录的短 caller deadline 继承，Drop 显式取消并 join 实际 operations/poller。
- reader Close 先取消传输再等待 Read 锁；MAC Finish 只运行一次，不重试一个已改变累积状态的验证器。
- MEGA 固定身份客户端使用 private typed context；策略计算的 detached headers 不发给 provider，也不从 URL 猜 driver。工厂在 storage bootstrap 前注册。
- 每个 storage session 配置快照不可变，配置更新只影响新客户端；已有 MEGA 客户端须 reinit 才获取新 policy。此接入**不是所有 driver 的全局 Resty/control-plane 已被迁移**。

## 自动与人工验收

自动：Go loopback 实际 HTTP 取消、Close join、provider direct/proxy 隔离、same-Network DNS/bind fake bridge、generation/bridge retirement、容量/活动 body 所有权、H2C 不绕代理、actual/src readonly overlay；cloud race、三 ABI gobind、真实 Kotlin APK 编译。Node 契约测试仅检查源码结构，不是 Android instrumentation。

真机待人工：

| 场景 | 需记录证据 |
| --- | --- |
| API29+ default VPN 与 physical WiFi/cellular | 实际出口、DNS 网络、FD 数稳定；非 handle/fwmark 推测 |
| 断开 VPN、Private DNS、IPv6 黑洞 | 国内/海外 provider 各自行为、取消回收、错误码与恢复时间 |
| WiFi↔cellular、VPN onLost、Service 停止/重启 | token 更新、无旧 idle 复用、活动 body 行为、DNS callback 不复活 |
| API21/23/24/28 | unsupported/default-only 明确，无隐藏 API 崩溃或假 selected 成功 |
| 各 OEM 与外部播放器 | 首帧 compositor submission、seek 与快速切集；服务端响应头不能替代这些指标 |

没有可访问的真实 Android 设备和用户云盘账户，因此上述真机结果当前是 **未验证**，不得将 CI 全绿转换为设备网络支持或播放评分。
