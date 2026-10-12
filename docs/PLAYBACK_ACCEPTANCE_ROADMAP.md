# 播放工程满分验收路线

本路线对应用户批准的七阶段计划。安全不计入本次评分；不以 CI 全绿等同实际播放器首帧，也不承诺任意网络条件无卡顿。

## 当前基线与交付方式

基线为 PR #66 / main `848555676271d1e4b978354c2e81a929f5ceef89`。所有阶段使用独立 `agent/*` 分支、Draft PR、GitHub Actions；必需检查全部成功后合并，再验证 main 构建与发布。禁止仅为验证手动触发带发布副作用的 workflow_dispatch。本机仅执行格式、语法、diff 和轻量检查。

## 阶段状态

| 阶段 | 目标 | 当前状态 | 必须的完成证据 |
| --- | --- | --- | --- |
| 1 | 可重复故障上游、准确指标与播放测量 | 实施中 | 字节一致性矩阵、取消/关闭回归、结构化结果、浏览器帧测量工具；注明真机未测 |
| 2 | 移动端共享 V3 核心 | 未开始 | 所有移动播放入口 V3 正确读取；现有 V1/V2 兼容；云端绑定/APK 编译 |
| 3 | V3 小块配置、认证缓存、受控回退 | 未开始 | 下载放大与缓存收益对比；身份/版本隔离；有界资源；旧格式兼容 |
| 4 | 切集兴趣调度与有界 KDF | 未开始 | 旧任务收敛、最终目标优先、取消等待者、不产生派生风暴 |
| 5 | 驱动取消、控制面路由、原生选网 | 未开始 | 可取消真实传输与退避；固定路由分池；Android 平台支持桥；设备能力边界 |
| 6 | 非 UI 文件写入、统计锁外、同步维护 | 未开始 | 文件逐字节正确、取消与隔离、资源稳定、源码覆盖冲突检测 |
| 7 | 完整云端及真机验收矩阵 | 未开始 | main 全绿、发布产物；设备测试通过或明确标注待人工验证 |

每阶段完成时填写 PR、最终提交、Actions 链接和残留项，不提前标记。

## 阶段 1 实现与证据入口

- `internal/playbacktest`：仅 loopback 的上游，支持 Range accept/ignore/reject、重定向、HTTP 状态、截断、响应头/正文 gate、延迟和带宽限制，Close 能释放故障等待。
- `internal/proxy/playback_acceptance*_test.go`：V1/V2/V3 共 36 个精确正文与范围组合、6 个下载取消、12 个重定向/错误场景和 2 个元数据取消场景。`PLAYBACK_ACCEPTANCE_REPORT` 指定绝对路径输出 JSON；量化的是上游 Write 接受字节，不是 TCP 流量或播放器渲染。
- `tools/playback-probe`：独立 HTML 工具，使用 requestVideoFrameCallback 测首帧/seek 的 compositor submission 延迟，隔离过期回调、来源与缓存标签，API 不支持时明确 unsupported。不会自动绕过授权或清理缓存；不是应用内外部播放器的测量代理。
- 统计页面区分响应头与正文首字节，不以历史响应头代替新指标。移动重定向直读/解密缓存路径增加 handler 开始至首次成功正文写出的计时、SQLite 兼容迁移与会话保留，旧记录没有该字段即未知；legacy 路由及原密文下载未据此宣称完整播放遥测。真实渲染指标只来自测量工具/未来播放器事件。
- Actions 添加 fault acceptance artifact 和独立 Node 测量语义测试；新增测试也作为后续构建发布依赖。当前尚待首阶段云端运行，未宣称真机测试通过。
- 后续实现设计：`docs/MOBILE_V3_IMPLEMENTATION.md`、`docs/NETWORK_ROUTING_IMPLEMENTATION.md`。

## 评分与硬性门槛

- 播放正确性/跨端一致性：25；首帧/拖动/切集：25；网络隔离/恢复：20；资源性能：15；代码质量/验证：15。
- 错误明文、下载损坏、无界等待、持续资源泄漏任一存在，不满足接近满分验收。
- 验证支持能力，而不是将明确拒绝等同完整支持；移动 V3 当前基线仍返回 415。
- 实际媒体首帧需播放器渲染事件；服务端响应头和正文首字节只代表相应传输阶段。
- 时间阈值先记录分网络档位基线，再定义可实现的验收阈值；不能以大于物理带宽的速度作为门禁。

## 已确定的实现约束

### 移动共享 V3

移动加密代码是独立实现，不能导入根 `internal/proxy`。适配独立 `shared/encryptcore` 模块的公开接口，显式映射类型：移动 AES 名称为 `aes-ctr`，共享名称为 `aesctr`。不能未经迁移直接给 ContentMeta 作别名。覆盖 `/d`、`/p`、`/dav`、`/dav2` 与重定向入口，不允许 V3 落入旧 cipher 或明文密文透传 fallback。模块覆盖初始化必须保留共享依赖及固定 gomobile 版本，不能让 reclone 恢复旧 go.mod。

### 后台目录生命周期（阶段 1 云端竞态新增证据）

首阶段缓存路由测试在构建 ProxyServer 后替换/关闭 localStore 时暴露 provider catalog 后台刷新与 localStore 关闭的竞态。缓存计时 fixture 应禁用无关后台任务，但生产目录刷新采用 context.Background 且缺少 shutdown join 的现状仍需阶段 6 明确修复，不以隔离测试宣称该生命周期已解决。证据：`provider_catalog.go` 的 async refresh 和 `local_integration.go` 的 closeLocalStore。

### Android 与驱动

支持式 socket 绑定应通过平台 Network API，不能把 network handle 推算成 SO_MARK。路由决定必须不可变、DNS 与 socket 同网络、连接池按路由隔离；不能依靠全局 host hint。API 及权限不支持时明示 default-only。HTTP proxy bypass 不等于 VPN/TUN bypass。

MEGA 依赖虽有 SetClient，但其 session poller、重试等待和 WaitEvents 缺少取消生命周期。真实解决需要可审查固定版本的 context/Close 改造，不能用遗弃 goroutine 的假超时，也不能仅注入 RoundTripper 就声称完整取消。

## 真机验收记录要求

至少记录设备型号、Android/API、播放器/codec、应用版本、文件格式/chunk 配置、云盘类型、冷/热缓存、网络 RTT/限速与 VPN 模式。记录播放器首帧、seek 恢复、连续切集的 p50/p95；同时记录下载放大、取消后请求、峰值内存和连接数。

矩阵包含：国内可达/海外不可达、坏 HTTP 代理、系统 VPN 正常/失效、Wi-Fi/蜂窝切换、Private DNS/IPv6-only、权限拒绝、锁屏后恢复、配置热更新、首段/尾段/随机 seek、快速十次切集。工具输出不能替代外部播放器行为测量。没有设备证据时只标记代码及云端验证完成。
