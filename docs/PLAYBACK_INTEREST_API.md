# 显式播放兴趣与 V3 KDF：阶段四实施契约

> 当前为 Draft PR #70 实施契约；新增兴趣调度和 endpoint 尚待完整云端验证。不是所有播放器自动切集支持或真机时延证明。

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

## 尚待验证与接入

仓库根 Web UI 是管理页，没有已知的内置播放器会话入口；移动 WebView/外部 app 的普通下载 URL 也不提供可靠的逻辑对象/session 映射。新增 endpoint 是显式客户端接入契约，不宣称这些入口已自动上报兴趣。需支持此契约的真实客户端明确发出 intent 才有 generation 效果；真机切集收敛和首帧时延仍待验收。
