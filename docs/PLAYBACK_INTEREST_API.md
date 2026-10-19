# 显式播放兴趣与 V3 KDF：阶段四实施契约

> 历史基础来自 PR #70；本批 P7 增加 root v2 clear/capability 与可复用客户端契约，尚待候选 head 云端验证。不是所有播放器自动切集支持、移动 endpoint 完成或真机时延证明。

## V3 KDF

保留原有 256 项、滑动 TTL、独立 key copy 的缓存。`DeriveV3KeyContext` 使用同 key registry、固定 `min(2,GOMAXPROCS)` workers、32 queued flights 和 128 registered waiters。后台准入为前台保留一个 queue/waiter 名额；两个 worker 时后台最多占一个执行槽。单 worker 不能物理保留第二槽。

取消只撤销 caller 的引用。最后引用撤销时，尚未运行的任务退出队列；已启动 PBKDF2 无法中断，仍保留 flight 和真实 CPU slot，完成后才释放。同 key 其他引用不会被首个 caller 取消。尚未运行的任务随 foreground 引用变化提升/降级；运行中的执行分类不变。旧同步 API 不绕过 CPU 上限，但其 legacy caller stack 在准入外等待，不能宣称限制所有第三方 caller goroutine。

root/mobile 成功派生后才持有 record 内存预算。移动端保留立即 acquire/release 的过载 preflight，但不会在等待 HTTP headers 或 KDF 时持有 record lease。Busy 返回终止、NoLearning 的 503，不刷新签名 URL。HEAD 和整 record 缓存命中不派生。

## 可信兴趣入口

`POST /enc-api/playbackInterest` 由现有登录 JWT middleware 保护。服务端从已经验证的 token 和配置快照生成 opaque scope，从已配置上游生成 provider；客户端不能提交 scope、provider 或任意目标 URL。

```json
{
  "session": "explicit-player-session",
  "generation": 1,
  "path": "/known-file.mp4",
  "speculativePaths": ["/known-next-file.mp4"]
}
```

- 仅在应用明确知道当前播放目标时调用；同一 session 的 generation 单调递增。不能依据 IP、Range offset、HEAD 或推测的下一集自动调用。
- JSON 最多 4096 bytes，session 最多 128 bytes，generation 大于零，speculativePaths 最多 4 个。所有路径必须 canonical absolute 且已在 DAO 中；整批先验证，再更新 intent。
- 第一版保守要求 DAO RawURL 与配置上游同 origin；外部签名 CDN URL 暂不支持，返回 400。这不是已支持海外/所有云盘路由的证明。
- 202 表示 intent 接受，并返回 generation、advanced、warmAccepted、warmRejected；有界 warming 拒绝不回滚已接受的 generation，也不表示媒体流已经打开。
- stale generation 返回 409，非法输入 400，未知文件 404，registry 满 429，scheduler 停止/未启用 503。服务端 JWT 不转发给上游；配置 provider 认证必须通过任务 context 的实际登录请求解析。

## 所有权与取消边界

Registry 按 scope/session/provider 隔离，最多 256 sessions、每 session 32 interests、TTL 5 分钟。任务由 scheduler context 和固定 workers 所有；多个 session 可以引用同一 scope 下同一任务。旧 generation 退出只撤销其自己的引用，最后引用离开才取消该后台 warm transfer。WarmForeground 仅代表当前目标 metadata 的队列优先级；它也仍是后台预热，并不代表正在播放的 HTTP 请求。

真实 media HTTP context 从未附到 generation；第三方播放器没有可信兴趣提供器时维持原来的保守行为。原有不带兴趣的目录/常规预热不被某个 session 撤销。取消不假释放 provider slot：必须等实际 transfer 返回才退还，Stop 要真实 join。

## v2 capability 与 clear（root actual）

`GET /enc-api/playbackInterest/capabilities` 同样受 JWT middleware 保护并 `no-store`。返回 data `{version:2, available, clear:true, canonicalPathsOnly:true, signedCDN:false, events:"explicit-launch-intent-only"}`。scheduler 未启用/已 Stop 时 available=false；404/旧版/鉴权或网络失败应回退普通播放，不能阻断 launcher。

`POST /enc-api/playbackInterest` 支持 `{session:"explicit-player-session", generation:2, clear:true}`。clear 不允许 path/speculativePaths；不依赖文件仍在 DAO，因此对象删除后仍可释放兴趣。clear 只释放对应 JWT/config scope、provider、session 的后台任务 refs，不删除 session：保留 generation tombstone 至现有五分钟 TTL。clear 接受等于当前 generation（条件释放当前兴趣，不预占未来 generation）或更高 generation（兼容旧 next-generation clear 客户端）；相同 clear 重试幂等，equal clear 返回 advanced=false。低于当前 generation 的 clear 返回 409，不能擦除后来的 launch。已 clear generation 的 launch/所有 enqueue 返回 stale，不能复活；活动同 generation 改 target 仍不允许。Flutter chooser 失败只提交该失败 launch 的 exact generation，dispose/明确退出 clear 当前 generation，不通过递增 clear 预占下一次 launch。最后引用才取消实际后台请求，provider slot 在 worker 真正返回后归还，Stop join 不变；真实 media context 从未绑定此 registry。TTL 后会话过期，客户端需使用新 session，不能宣称无限期持久化单调性。

共享 Go DTO 在 `shared/encryptcore/playbackprotocol`，移动后续 endpoint 可复用，不代表已经接入。

## CDN 与非 canonical 的明确边界

本批仍 **unsupported signed-CDN / noncanonical URL**。DAO 里存在 RawURL 不证明当前 caller 的 fs/get 授权、规则 epoch 或 CDN 对象绑定；当前 root API 无法安全完成该证明，不据任意 URL、query stripping、IP 或 basename 猜身份。未来支持仅可从当前 caller canonical fs/get 的已确认对象、当前规则/auth scope、当前 rawURL 建立绑定并验证旋转；不能仅放宽同 origin 检查。客户端不提交 rawURL/provider/scope。

## 移动与 chooser：本批延期范围

移动 encrypt 包 **没有实际同等 endpoint/capability**；P2 owner/lifecycle 未合并，本批不复制其任务所有权。`mobile/lib/utils/playback_interest.dart` 提供 transport-injected 明确 confirmed-choice adapter 与 mock tests：旧服务 fallback、上报失败不阻断 launch、快速 chooser 失败不撤销新 generation、dispose/明确取消只 clear 自己、foreign origin/URL-only 不上报。transport 必须由实际认证服务器和 caller fs/get confirmation owner 注入，目前没有生产 transport。

实际 `mobile/lib/pages/web/web.dart` 下载 chooser 仅收到 URL/suggestedFilename，没有 canonical fs/get 身份，因此 **未接入兴趣上报**，普通打开保持原样；不伪造 raw URL 到 canonical 的映射。Flutter launch 只证明打开请求，不是 MX actual play/frame/exit。App resume 不触发 clear；未引入 Pigeon battery bridge。邻集预热默认保守关闭，adapter 不发 speculativePaths，未知计费/电量/网络输入不启用新 warm。

## 验证状态

新增 root TCP/JWT capability/clear/expired-token wire tests、clear exact-owner/shared-ref/rapid/stale registry tests；existing 实际上游取消/join测试改为 clear 触发，保留队列满/Stop拒绝测试。Flutter mock adapter tests 待云端执行。本地 root focused test 在首次依赖下载 60s 后终止（未获得通过信号）；Flutter/Dart 工具本机不可用。shared DTO 单包 test 因 `/root/.cache/go-build` 只读沙箱拒绝未运行（不绕过/提权）。gofmt 与 git diff --check 通过。真机切集、首帧、耗电与生产 CDN 均未验收。
