# 播放优化最终验收：工程证据与设备待测项

## 结论边界

阶段 1–6 的实现与回归已通过分阶段 PR 云端验证。阶段 6 PR #72 最终 `d8ebcad` 的 Actions `38228847370` 全绿，合并 main `780e221`；合并后的完整发布 Actions `38230426917` 正在核验，不能将尚未结束的发布标为通过。

**本文件不是已完成的真机测试报告。** 当前没有真实 Android 设备、生产网盘账号及不同 VPN/OEM 环境的实测结果；下表设备项均为待人工验证。不能据云端编译、字节正确性或服务端首字节声称真实首帧改善、所有驱动隔离、所有 VPN 绕行或“100 分”。安全不纳入本轮评分。

## 已有工程证据

| 阶段 | 合并 PR / main | 最终 PR Actions | main 发布 Actions / 版本 |
| --- | --- | --- | --- |
| 1：测量与故障基础 | #67 / `2374ca3` | 见该 PR 检查记录 | `38197844019` / `v2026.10.12.361` |
| 2：移动共享 V3 | #68 / `78aff12` | `38200886879` | `38201569198` / `v2026.10.12.371` |
| 3：chunk、认证缓存与有界回退 | #69 / `0d47488` | `38203768488` | `38204243215` / `v2026.10.12.375` |
| 4：可信兴趣与 KDF | #70 / `fa8ee6b` | `38210123567` | `38210664342` / `v2026.10.12.381` |
| 5：原生路由与驱动取消 | #71 / `64aab3c` | `38222901370` | `38224427891` / `v2026.10.12.388` |
| 6：资源生命周期与维护 | #72 / `780e221` | `38228847370` | `38230426917` / 待完成后记录 |

Actions 可按编号打开 `https://github.com/qingwo1991-debug/alist-encrypt-go/actions/runs/<编号>`。PR/main 的编译、race、Docker、三 ABI AAR/APK 验证不是网络设备测试。阶段 6 的最终 PR 另有使用真实 AAR 编译 Kotlin release APK 的检查。

自动门禁覆盖：

- 根/移动 V3 认证读取、V1/V2 兼容、范围/后缀/跨记录与受控非 Range 回退的字节正确性；小块配置、认证缓存身份和预算、KDF 排队/取消等待者。
- 真实 loopback 上游故障、请求 context 取消、读取空闲预算、驱动重试退避、MEGA session Close 与 poller join；MEGA 凭据集成测试没有账号时跳过，不等于真实网盘已测。
- 实例后台准入/停止 fence、未 Start/监听失败清理、catalog/range 实际 HTTP 取消、真实 handler 结束后 SQLite 关闭、备份构造失败与并发 Close 的 join、停止前播放统计持久化。
- Flutter 四路交错下载完整 **10 MiB + 7 bytes** 字节比较；有界异步 seek/write 原子事务、私有缓冲区、兄弟请求取消后全 worker join、关闭/删除/fallback 顺序、尚未创建文件时的路径预约。
- 固定 OpenList `v4.2.2` commit `b28208bd76ee19c49dabc7f68c1f4e863f571fc6` 的 26 个维护路径 pristine 指纹、新增文件碰撞拒绝、actual/src 一致性。不是全源码树三方合并；覆盖边界见 `mobile/openlist-lib/scripts/SOURCE_OVERLAY.md`。

## 指标不能混用

1. 服务端 `first_byte_latency_ms`：handler 入口到第一次成功正文写入。响应头准备与上游响应头指标分别记录，不替代播放器帧事件。
2. 独立浏览器 probe 的 `firstRenderedFrameMs` / `seekRenderedFrameMs`：当前操作起点到 `requestVideoFrameCallback` 的 `metadata.presentationTime`。代表提交给 compositor，**不证明物理屏幕显示**；仅测它自己的 `<video>`，不是另一个 App/WebView/外部播放器。
3. probe JSON 用 `status=success/failure/cancelled/unsupported`、`cacheCondition=cold/warm/consecutive` 分组；p50/p95 为 nearest-rank，仅使用该组成功、有限、非负样本。缓存标签需操作者独立验证，工具不清缓存。失败/取消/unsupported 另计，不能填成 0 或丢弃以美化成功率。
4. 生产播放器没有可用帧事件时，播放器首帧与 seek 渲染填“未测”，保留请求级数据；不能将 `playing`、`seeked` 或肉眼计时伪装成同一精确指标。

工具使用步骤与 JSON 语义见 `tools/playback-probe/README.md`。本轮不启动额外服务，也不自动访问生产媒体。

## 设备验收准备

- 安装对应 ABI 的发布 APK，保存 APK hash、版本、main commit、Android API/OEM、设备型号、播放器及版本。
- 选取获授权的固定素材：V1、V2、旧 16 MiB V3、新小块 V3；包含跨记录 seek、末尾 seek 与音视频容器前/后置索引。保存原明文长度/hash，以下载或可比较的范围字节核验，不能只看“能播”。
- 各选一个实际可达国内挂载、一个海外挂载；另设不可达海外挂载。记录具体 driver、route/proxy 设置、原生选网是否 opt-in、API 支持与真实物理网络可用性。不要在共享报告暴露账号或 signed URL。
- 固定网络档位后分别记录冷/热/连续操作；建议每个延迟组至少 30 次，样本数不足明确标注。先保存基线，再预先约定同条件目标；不得用超过带宽/认证记录物理下限的阈值。

## 手工设备矩阵（所有结果待人工验证）

| 项目 | 操作 | 必须观察与通过条件 |
| --- | --- | --- |
| 格式与入口 | 各格式分别经 `/d`、`/p`、`/dav`、`/dav2` 和实际播放器入口播放、下载与范围核验；冷/热各测 | 明文字节/长度正确，格式拒绝明确；不将旧缓存或 V2 解析当作 V3 成功 |
| 首次打开 | 同素材固定档位分别冷打开、热重开；不混淆缓存标签 | 请求首字节、可用的播放器帧指标独立分布；错误/超时/unsupported 单列 |
| 拖动 | 前/中/尾部、跨 V3 chunk、快速前后 seek；使用真实目标帧事件（可用时） | 最终目标正确，无旧帧误计；请求/下载放大与缓存命中记录；错误字节为零 |
| 连续切集 | 连续切换 10 次并停在最终目标，重复一组；另一 session 同时读旧目标 | 最终播放正确；旧兴趣任务收敛，不取消另一 session 的共享工作；资源在实际任务结束后归还 |
| 可信兴趣 API | 用有鉴权的 adapter 显式提交 session/provider/generation 并撤销旧兴趣；与不接 adapter 的播放器分组 | 验证显式 API 的去重、最后引用取消与最终目标优先；未接入的外部播放器不声称自动上报逻辑切集 |
| 国内/海外混合 | 国内挂载持续打开/seek，同时不可达海外初始化与访问；恢复海外后再试 | 国内请求不被统一等待屏障拖住；海外真实取消/退避有界，恢复明确；对具体 driver 单独记录 |
| 弱网 | 正常网络及 1/2/5 MiB/s、100/300 ms RTT、可控丢包；依次 header/body blackhole | 分类错误与预算一致，无无限重试/后台遗弃；不能把客户端暂停或慢下游写入算成上游空闲超时 |
| VPN/TUN | VPN 关闭、健康、断链、黑洞；各测默认路线与显式物理路线 | 实际 DNS/socket 选中同一 Network（平台支持时）；无可用物理 token 明确失败，不能静默默认回退；记录 VPN 策略限制 |
| 网络切换 | Wi-Fi↔蜂窝、断网重连、默认/物理网络丢失及再次出现；重复切换 | 新请求用新不可复用 token/路由池；旧活动请求按真实 EOF/Close 释放；无 FD/DNS registry 持续增长 |
| API/OEM 边界 | API <29 与 API≥29、至少两种 OEM；受限权限/Private DNS 场景 | 不支持时记录 default-only；数值 errno/选网失败明确。编译通过不替代平台实测 |
| 取消与下载 | 四路下载中取消、队列中取消、header/body stall；通知/回调入口同时同名下载 | 文件定位正确、各任务路径不碰撞；实际 worker/write 结束后才关闭/删文件/改用 fallback |
| 配置/重启 | 活跃播放和 metadata 时更新配置；停止/启动；监听端口占用导致启动失败 | 停止准入、取消并 join，SQLite 不提前关闭，统计落库；新存储 client 才应用新 driver factory 配置 |
| 稳态资源 | 上述操作循环 100 次，含取消、切集和服务重启；每次停止后采样 | RSS/FD/goroutine/CPU/网络请求回到已约定稳态区间，无单调泄漏；固定 KDF worker 正在执行的非可中断 CPU 工作单独解释 |

## 记录模板

每行保留：测试 ID、时间、release/commit/APK hash、设备/API/OEM/播放器、driver、格式/chunk 配置、缓存状态、网络限速/RTT/丢包、VPN/代理/原生选网配置、目标操作与 generation（若可信 adapter 存在）、结果与固定错误分类、请求首字节、可用帧指标及其语义、样本数/p50/p95、明文错误数、下载字节/消费明文字节、取消后实际 pending 数、峰值与停止后 RSS/FD/goroutine/CPU、日志证据路径。

没有观测来源的字段填 `未测`，不是 0。失败与取消样本保留在原始报告。比较版本时同时保存基线、实验版本和相同环境参数。

## 已知能力边界与最终签收

- 真正接入新 driver factory 的驱动目前仅 MEGA；其它全局 Resty 或专有传输仍保守使用既有策略，不能给所有驱动打“隔离完成”。
- Android 显式选网为 opt-in，API <29 无选中 token；HTTP proxy bypass 不等于 TUN/VPN bypass。原生拨号是有界顺序候选回退，不是并行 Happy Eyeballs。
- H2C 仅启动探测过的确切 direct 控制面 origin，配置 reload 后不沿用旧探测结果；媒体保留响应头预算，显式代理不绕过。
- raw SQLite 主文件备份为 best-effort，不是在线 WAL 一致快照。同步存在性等小型文件 metadata 操作仍有遗留；改为异步的是下载批量磁盘写入，不宣称所有 UI 操作均已移出 isolate。
- 浏览器 probe 与可信兴趣 API 都不是对任意外部播放器的自动 instrumentation。

工程签收条件：最终 PR 所需检查全绿、main 完整发布全绿、产物可用、临时分支删除、文档证据与上述边界一致。设备签收条件：填写设备矩阵实际报告、字节错误为零、无无界等待或持续资源泄漏、同条件性能指标满足事先约定目标；无设备结果时只能写“工程交付完成，设备验收待人工验证”，不能宣称接近满分。
