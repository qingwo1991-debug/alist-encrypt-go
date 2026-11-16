# LP3/LP4 前台优先与解密测量交付说明

状态：代码已实施，待云端编译、race、bench及本机验收，不代表性能目标已通过。

## 实施范围

- `ForegroundTracker` 在可信本地模式登记实际 GET/HEAD 媒体请求，server middleware 在请求进入原名恢复/上游查询前运行，仅覆盖已配置加密路径的 `/dav/`、`/d/`、`/p/` 及 `/redirect/`，不登记普通 API、UI 和 PROPFIND。
- trusted_local 停止普通 bulk probe 入队，缺失几何由实际播放按需解析；显式 playback-interest 的独立入队路径保留。standard 默认维持已有入队行为。
- 后台目录扫描、异步目录快照刷新、启动 DAV 目录扫描，在新网络工作前等待前台结束。不取消已经运行的共享前台任务或假装抢占 PBKDF2/网络。
- scheduler 预热重探测 delay 移至调度资格阶段，不占 provider slot 或 worker 睡眠；显式前台任务不加随机延迟。实际执行仍在 worker 真正返回后释放 slot。
- 可信模式下 scheduler 给显式前台保留一个 provider 槽（provider 容量大于1时）；这不是为独立实际播放 HTTP 请求提供硬连接预留的承诺。
- 快照刷新先按 scope 去重、再占有界槽、再启动 goroutine；重复同 scope 不再先生成大量等待 goroutine/占满8槽。Stop 拒绝新任务，并等待实际 worker 释放 pending 与槽。
- tracker 与 dispatcher 对运行时 trusted_local→standard 切换至多约250ms重查，无永久 polling goroutine，不会等完整长视频结束才恢复扫描。

## LP3 测量而非重复建设

现有完成 key cache、KDF service、64MiB/30s authenticated record cache 继续复用；未修改算法、迭代次数、文件格式、tag 校验、原名审计或内存容量。

增加基准：

- `BenchmarkLocalPlaybackV2KDFCounts`：实际生产 PBKDF2 冷/热，报告真实 deriver 调用 `derivations/op`；冷测逐轮删除固定测试 key，避免假冷和无限增大缓存。
- `BenchmarkLocalPlaybackV3Record`：64/256/1024KiB 合成容器 record，报告 loader 次数、alloc/bytes，热命中以 nil loader/cipher 验证不再次获取或认证；认证次数指标明确为成功 fixture 的预期逻辑次数，而非底层 AEAD instrumentation。
- `BenchmarkLocalPlaybackV3IdentityHash`：报告逻辑 cache key 构建次数，不把它误报为底层 SHA 调用次数。
- 复用已有 AESCTR 64/256/1024KiB 解密吞吐基准，不为测量改实际 V3 chunk。
- Actions 原 performance job 追加 LocalPlayback bench 匹配，并输出 filename read index 1k/10k/100k 基准到 performance artifact；不使用 workflow_dispatch。

## 定向测试

新增 tracker 嵌套/幂等释放、标准模式 no-op、取消、模式切换、foreground priority、bulk 不再入队、delay 不占 provider 槽、前台预留槽、快照刷新100次同scope只占1槽且 Stop 真实回收、server 实际请求 middleware 登记/释放与非媒体排除。

验证：gofmt 与 git diff --check 通过。本地 Go 测试此前因只读/缺失 Go cache/module 被拒，接手后没有重试、下载或绕过。尚无编译/test/race/benchmark通过声明，须父提交 Draft PR 取得云端实际信号。

## 边界

- 已运行后台请求不会被硬抢占；tracker admission 检查与前台新到达之间允许有限竞态，不能宣称严格抢占资源。
- 没有改 negative cache TTL，也没有实现全驱动网络连接硬预留。需结合 LP0 404修复、LP1快读及 LP2冷请求合并后的最终服务端实测判断。
- 无本机容器改动、配置启用、云盘写操作或设备首帧测量；p95≤10%回退目标和真机体验仍待部署验证。
