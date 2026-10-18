# LP1：原名反查索引与可信本地快读

## 范围与行为

基线：`b6f2f1bbe02a0d1df2fa8ae411de163f3efde7a2`。独立工作树 `lp1-local-fastread`，分支 `agent/lp1-local-fastread`。不修改生产配置、数据库、容器或网盘，不发现场请求；无 push/PR/部署。

- 原名 durable Store 是本地 Bolt，不是文件元数据可能使用的 MySQL。新增独立版本桶 `filename_read_candidates_v1`，以 `(origin, originalPath)` 哈希前缀加 primary ID 保存所有候选，不复用含 auth/rule 的写索引，不复制审计为新的真相。
- 读查询仅 prefix seek、至多检查两个候选、唯一时 primary 点查；重名返回歧义错误，绝不选 first，也无 fullscan fallback。
- `NewStore` 在对外发布前执行一次事务重建，每次启动均重建，兼容旧 binary 回滚期间写过 primary 的情况。重建不改 primary 审计。状态提供 notready/building/ready/rebuild，进度带扫描数/总数/时间，日志每 10000 条报告，不含路径或凭据。
- Reserve、Finish、通用 Store Set/Delete/UpdateBucket 的 primary mutation 与读索引保持同事务。最多 256 个正/负热点项，Store 写事务同步失效且禁止旧读结果在 mutation 后重新发布；正常写 auth/rule 唯一索引和占位 token 约束未放宽。
- `alistServer.playbackProfile`: `standard` 默认，`trusted_local` 显式启用。parser、保存、完整配置替换和运行更新处理此字段；非法显式值不能保存/运行更新，启动非法字符串安全降级 standard 并记录错误。UI 提供选项和当前 profile 可见说明。模式更新走已有 RuntimeRevision，因此规则/配置换代检查仍生效。
- trusted_local 在 complete/current-rule 唯一原名候选上直接请求本地 raw binding，跳过额外 Depth:0 preflight；standard 保持该验证。实际 PROPFIND 仍携带当前请求凭据，实际 GET/HEAD 仍走现有播放链路。上传完成核验 helper 未删除、未更改。
- request-local binding 改名为 `filenameRawPath`，显式 `remoteAuthorized` 布尔：只有 standard 本次远端 preflight 成功才 true；trusted_local 和仅有历史媒体签名 provenance 的 alias 皆 false。后续原名 overlay 依据实际响应内 exact raw href，不把本地 binding 误称远端鉴权，也不发布到全局原名缓存。
- 索引未就绪/损坏读失败为 503 + Retry-After，不能当作不存在返回 false/miss。规则删除后同样查有界索引，避免未缓存历史原名绕过规则拒绝。

## 新增验收夹具（尚待可执行环境运行）

- storage：真实序列化 1000/10000/100000 条 Bolt primary records，一次 fixture 事务后真实重建；首尾候选、miss、重复原名，读事务计数和热正/负 cache 事务预算。benchmark 同规模输出 read-tx/op 与 allocation。
- storage：旧 binary 修改 primary 但保留旧 READY 派生索引后重启重建；primary 字节不变、literal `%2f`、Reserve/Finish/删除失效、损坏状态 fail closed、并发 Finish/读。
- handler：真实 loopback TCP，standard GET/HEAD/PROPFIND guard preflight=1，trusted_local=0；完整非缓存单文件 PROPFIND 总数分别 2/1；当前 Basic 读凭据与不同上传 scope；GET/HEAD 的 raw binding 和语义标志；literal 百分号保持原样，response 恢复原名。未完成/失败/错规则拒绝、索引不可用 GET/HEAD/PROPFIND 503+重试。
- config：默认/legacy/parser、合法 profile 保存/替换/更新、非法 profile、revision；UI 最小 profile 可见性契约。

## 实际本地验证与限制

- `/usr/local/go/bin/gofmt`、`git diff --check`：通过。
- 尝试离线 focused Go tests：`GOPROXY=off GOSUMDB=off go test ./internal/handler -run '^Test(ProtectedFilename|TrustedLocalFilename)' -count=1`，以及 config focused tests。未进入编译/测试：受委派 workspace-write 沙箱限制，`/root/.cache/go-build`、`/root/go/pkg/mod` 为只读，另缺 gin/zerolog/xsync 缓存；approval disabled，不升级权限、不绕过限制、不下载依赖。需要父代理或 CI 给出真实编译/test/race 信号；不得将此结果写成已通过。
- 未执行性能 benchmark、设备 p95、手机播放或现场 upstream 验收，无首帧/秒开结论。

## 明确边界 / 父代理后续集成

- 启动重建线性耗时在启动窗口内，采用一次事务（用户允许）；不是后台渐进发布。显式运行中修复调用 `RebuildFilenameReadIndex` 时返回 retry 而不是维持旧代索引持续服务。暂无管理 HTTP 自动修复入口；可通过重启重建。未就绪不伪装 miss。
- cache 为小容量、全 Store 写失效，偏保守；非精细每-key 失效策略。
- LP2/3 主逻辑未改：未重写 raw URL/content identity、缓存 HEAD、解密/KDF；父代理集成后新增的 cachedHEAD/readAuthorization gate 必须依据 playbackProfile，在 trusted_local 下不得重加等价远端 preflight，也不能把 remoteAuthorized=false 当作拒绝本地模式的理由。现有 raw URL auth scope 留给 LP2 统一。
- 对手工篡改派生桶且不经 Store API 的缺项，不做每请求全库指纹检查；支持缺失桶/标记、坏 primary 检测 fail closed 和重启重建。正常生命周期所有真实 mutation 事务维护；旧二进制再升级每次重建。
- 仍需云端完整 matrix、race/并发回归、固定机器 benchmark，随后才由父代理决定集成发布。上传防覆盖、原名审计与规则冲突策略未降级。
