# Docker / Android 预热与播放元数据复用评估

评估基线：main `b475f4e`（包含 MX WebDAV 修复 PR #74），只读源码检查，未检查用户实际 Docker 镜像，未进行真机性能测试。

## 结论

两端“预热”没有实现相同契约。Docker 的预热可以获取并持久化完整内容元数据，播放直接消费；Android 启动预热主要唤醒上游目录，丢弃列表正文。Android 已有元数据持久化设施及 redirect 缓存消费逻辑，但 legacy WebDAV 入口仍做请求内确认，不跨播放复用。PR #74 修正了明文响应语义，没有满足“确认一次、后续播放复用”的性能要求。

## 源码证据

| 项目 | Docker/root | Android/mobile |
| --- | --- | --- |
| 目录预热 | `internal/handler/snapshot_prewarm.go:65-110` 从目录快照构造文件任务，异步交给 ProbeScheduler | `mobile/openlist-lib/openlistlib/encrypt/proxy_dir_warm.go:129-165` 请求内部后端 Depth:1，读取受限正文后丢弃；不写完整内容元数据 |
| 文件内容元数据 | `internal/handler/probe_scheduler.go:754-791` 获取下载地址、确认内容头，写明文大小、密文大小、版本、header、nonce、V3 chunk/KDF | `proxy_prefetch.go:225-236` 子目录预取只写 name/size/path；`proxy_dir_persist.go:181-183` 目录落盘只提供 name/size，不证明格式或 nonce |
| 播放消费 | `internal/handler/playback_orchestrator.go:99-139` 完整缓存命中直接注入 ContentMeta，miss/incomplete 才探测；`:142-150` 大小优先缓存 | `proxy_download.go:88-117` inspectLegacyContentMeta 只做请求内缓存，每个新的 HTTP 请求、不同目标 URL 都可能探测 |
| 已有可复用能力 | stream 从 context 消费 metadata，无须再次探头 | `play_v2.go:1106-1126` redirect 元数据/文件缓存可直接消费；但 legacy WebDAV 在进入编排前已重新探测（`proxy.go` inspectLegacyContentMeta 调用点） |
| 持久化/URL边界 | 完整元数据可从 BoltDB 恢复；下载 URL 另有时效和授权范围 | `proxy_cache.go:509-590` 可以读内存/SQLite 元数据；V1/V3 部分消费还与原始 URL 绑定，URL变化会影响命中 |

## 大小不是可随便猜测的数据

V1 AES-CTR/RC4 的 fileSize 参与 sizeSalt（mobile `crypto.go:180-181,301-302`），错误大小可能直接导致解密错误。V2/V3 除大小还需要版本、nonce、header；V3 需要 chunk 和 KDF 参数。只有列表 size 不等同于完整且已确认的解密元数据。

## 应采用的契约（建议，尚未实现）

1. 内容元数据按稳定文件身份缓存和持久化：后端/存储范围、授权边界、真实对象路径、加密规则指纹。不要仅以短期签名 CDN URL 为文件身份。
2. 保存完整且已确认的 V1/V2/V3 元数据；目录观察的 raw size 与 confirmed plain size 分字段，普通列目录不能覆盖或伪造确认状态。
3. 热 HEAD/GET/seek 首先消费同一元数据；命中时不新增 HEAD、prefix Range、PROPFIND 或 fs/get 元数据确认请求（实际媒体请求与必要的过期地址刷新另计）。
4. 冷缓存或记录不完整才做一次有界探测；同对象并发使用 singleflight，并将结论回填内存及持久化。
5. 原始下载地址独立到期/刷新，不因地址过期、VPN切换、播放器取消或普通网络超时删除稳定解密元数据。
6. 明确文件替换/上传/删除、加密规则变化、上游观察大小或对象版本变化及确定的解密/表示冲突才失效内容元数据。每次响应可校验现有长度/Range信息，不必新增探头。
7. 同路径同大小替换不能只靠大小识别；能获得 ETag/mtime/version 时记录比较，否则说明稳定对象假设和手动刷新途径，而不是声称永久可靠。
8. 保留 PR #74 的明文 CL/CR、bounded reader、快照来源与失败确认保护；不能恢复旧的 ambiguous size 缓存来省请求。

## 验收必须可计数

- 一次冷确认后，重复 GET、HEAD、seek 不增加内容探测计数。
- 重启后完整可信元数据仍能复用。
- 签名 URL 更新不触发内容头重探；不同授权/后端/加密规则不串缓存。
- 并发冷请求只产生一次确认流程；失败结果不保存为 confirmed V1。
- 文件大小/版本/规则变化正确失效；不因客户端取消或普通网络失败误删。
- 所有冷热路径保留正确明文正文、CL/CR和EOF。

## Docker 实现也有需注意的边界

完整 metadata 消费没有统一的 ETag/mtime 或加密规则指纹检查；热缓存 TTL 不等于持久化内容 metadata 的可信时效。`internal/handler/alist.go` 的 contentMetaOrProbe 失败 fallback 可返回 LegacyContentMeta，而调用方有持久化路径；不能把所有 version>0 都等同于已经确认。应复用“稳定元数据与短期URL分离”的设计，而不是机械复制这些边界问题。

本评估未修改生产代码。新增探测消除和预热对齐需要独立候选、自动化零新增探测断言、完整云端验证和同文件 MX 真机复测。
