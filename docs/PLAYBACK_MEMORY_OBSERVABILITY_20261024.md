# 长时观测中止后的内存解释与数字观测补强（2026-10-24）

## 不能由守护触顶直接认定泄漏

`PRODUCTION_REALTIME_600_SECOND_SOAK_20261024.md` 的失败事实不变：连续三次 Go Alloc 超过 256 MiB，在 439.012 秒中止，未完成 600 秒。没有提高阈值、强制 GC、重试或启动一小时任务。

只读源码及实际非秘密配置字段核对发现：**明文块 LRU 本身配置为 256 MiB，块为 256 KiB**，而此前守护以**整个 Go Alloc >256 MiB**为阈值，未把进程其他基线分配纳入缓存预算。因而现有条件可能在有界缓存逐渐填充时就触发，不能据此证明缓存无界或对象永久泄漏，也不能因此直接忽略这次告警。

- 服务只共享一个 StreamProxy，不是每路复制一个 256 MiB 缓存。
- `decrypted_block_cache.go` 以明文字节记账并按 LRU 淘汰，`getRange` 另做有界响应复制；关闭前的上游 read-ahead 可以填入未全部消费的块，旧块 / 临时副本仍需自然 GC。
- V2 key cache 仅有界的小密钥条目，不支持“每次请求保留几十 MiB KDF 结果”的推测。
- 原 `/health` 只有舍入后的 `m.Alloc`，包含已分配但尚未回收的对象，不是 retained-live-heap 或严格 RSS。现有采样已有多次自然下降，不能称完全单调上涨。

约 78 秒后 heap 366 MiB 的历史复核仍保留；随后独立只读单次健康读取于 **2026-10-24 03:49:48.539768 UTC** 得到 HTTP 200、goroutine 21、heap **199 MiB**。未强制 GC。这证明后来有下降，但既不能证明无泄漏，也不是严格受控 idle 基线；上传器期间曾因准入风险被暂停 / 重启，属于并行负载混杂因素。

## 已实现但未部署的观测代码

独立分支 `agent/playback-memory-observability-20261024`，精确提交：

`add46c9f4e6a777303a9021153d094ce328ebe12`

[Draft PR115](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/115)，完整矩阵 `40060310355` 运行中。只改 `internal/server/health.go`、`health_test.go` 和 server 路由注入，**不是内存修复、没有提高守护或部署**。

- 保留旧健康字段，增加 exact-byte Alloc / TotalAlloc / HeapInuse / HeapSys / HeapIdle / HeapReleased，以及 NumGC / NextGC / LastGC 等纯数值。
- 将已有 StreamProxy 的缓存统计通过九项严格类型白名单投影：是否启用、条目数、used / max / block bytes、hit / miss / put / eviction counters。未知省略，已知禁用明确为 false；不暴露路径、缓存键、token、对象名或任意 provider map 字段。
- 只读已有短 mutex 下的 O(1) 快照，不创建第二个缓存，不触发 SQL、权限查询、网络、驱逐、重置、profiling 或强制 GC。
- 编写者健康定向测试通过 0.008 秒；独立审查三项健康测试通过 0.009 秒，真实缓存统计 / LRU / 范围测试通过 0.005 秒，精确头无 P0/P1。完整云矩阵仍是合并前门槛。

## 下一步必须区分的指标

待精确头全矩阵、main 发行以及安全升级容量 / 备份门槛满足后，才可部署此观测补强。随后在不改保护阈值、不强制 GC 的有界观测中，关联缓存 used / evictions 与自然 NumGC / NextGC / Alloc，区分：缓存工作集增长、有界池和待 GC 分配，或真正无法由已知容量解释的持续保留。

现有管理 getStats 虽有缓存统计，但需要合法管理员登录；未借用上游扫描凭据伪造管理 JWT。没有访问可能包含秘密的 heap dump。不得为凑齐一小时提高缓存 / 内存预算、制造缓存夹具来代替生产证据，或把本次数字观测代码称成性能问题已经修复。
