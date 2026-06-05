## alist-encrypt-go 安卓端 WebDAV 播放失败 & 首帧慢 分析报告

### 一、问题总览

根据日志和代码分析，安卓端存在两个核心问题：WebDAV 无法播放视频，以及所有协议首帧加载都偏慢（WebDAV 尤其明显）。以下是详细的根因分析和优化建议。

---

### 二、WebDAV 播放失败的根因

#### 2.1 存储加载超时导致初始 PROPFIND 失败

日志开头可以看到，服务启动后存储尚未加载完成时，WebDAV 客户端已经开始发起请求：

```
PROPFIND /dav/ status=502 duration=8.001s   ← 后端未就绪，超时 8 秒
PROPFIND /dav/ status=502 duration=8.009s   ← 同上
PROPFIND /dav/ status=401 duration=5.684s   ← 认证失败（存储未就绪）
```

同时 unicom_cloud 存储完全无法加载：
```
dial tcp [2408:8706:0:f405::1c2]:443: connect: no route to host
PROPFIND /dav/unicom_cloud/ status=404 duration=7.198s
```

**影响**：WebDAV 播放器在启动时会扫描根目录，遇到 502/401 后可能直接放弃或进入错误状态。虽然之后存储加载完毕（207 响应正常），但播放器可能已经放弃了连接。

#### 2.2 V2 内容检测每次全部失败 — 这是关键瓶颈

每次 `/redirect/` 端点被调用时，都会执行 V2 内容检测（`inspectPlaybackContentMeta`），发送 3 次探测请求。**日志中显示每一次检测都失败了**：

```
[v2-inspect] upstream returned error status: target=https://...cmecloud.cn/...?response-content-disposition=attac status=400
[v2-inspect] header not detected: target=http://127.0.0.1:5244/dav/... status=302 first6=3c6120687265
[v2-inspect] upstream returned error status: target=http://127.0.0.1:5244/d/... status=401
[v2-diag] inspection result: isV2=false version=1 plainSize=1833849240 cipherSize=1833849240 headerLen=0
```

三个探测 URL 的失败原因：

**探测 1 — CDN 签名 URL（status=400）**：`response-content-disposition=attac` 是 URL 被截断后发送的，S3 签名验证失败。V2 检测代码可能把 Range 请求附加到了已签名的 CDN URL 上，而 S3 预签名 URL 不允许修改请求头或参数。

**探测 2 — 本地 /dav/ 路径（status=302, first6=3c6120687265）**：`3c6120687265` 解码为 `<a hre`（HTML 标签开头），说明请求被重定向后返回了 HTML 页面而非文件数据。`first6` 不是 V2 magic bytes，所以检测失败。

**探测 3 — 本地 /d/ 路径（status=401）**：内部探测请求没有携带认证信息，被 alist 服务拒绝了。

**影响**：每次 V2 检测耗时约 2-3 秒，且每次都失败，然后 fallback 到 V1 模式。由于文件确实是 V1 格式（`isV2=false`），最终能播放，但白白浪费了 2-3 秒。

#### 2.3 WebDAV 重定向链路过长

WebDAV 播放一个加密文件的完整请求链：

```
① PROPFIND (获取文件元数据) → ~1ms（缓存命中后很快）
② GET /dav/file.mp4 → 调用 /api/fs/get → 后端返回 302 → 重写为 /redirect/key → ~150-400ms
③ GET /redirect/key → V2 检测（3次探测全部失败）→ ~2-3 秒
④ V2 检测后开始流式传输 → 实际数据开始传输
```

总计从请求到首字节：**3-5 秒**（WebDAV）。而 HTTP 直接走 `/d/` 路径，链路更短，所以更快。

#### 2.4 客户端反复断开重连（broken pipe / context canceled）

日志中大量出现流传输中断：

```
V2 redirect stream copy failed: written=32595968 err=write tcp ... broken pipe
V2 redirect stream copy failed: written=2588672 err=context canceled
V2 redirect strategy failed: reason=stream_error retryable=true
```

这是因为：
- 播放器因为首帧太慢，不断放弃当前连接并重新发起请求
- 每次放弃都导致代理端写入失败（broken pipe）
- 新的请求又触发新的 V2 检测，形成恶性循环
- 日志中可以看到同一个文件在短时间内被请求了 6-8 次

---

### 三、首帧加载慢的根因

#### 3.1 V2 检测开销（最大瓶颈）

即使文件是 V1 格式，每次冷启动都要做 3 次探测请求：
- 探测 1：CDN URL Range 请求 → 等待响应 → 400 错误
- 探测 2：本地 /dav/ → 302 重定向 → 读到 HTML → 失败
- 探测 3：本地 /d/ → 401 错误 → 失败

这 3 次探测是串行执行的，总耗时约 2-3 秒。如果 `fileDAO` 有缓存，可以跳过这一步，但冷启动或新文件时没有缓存。

#### 3.2 /api/fs/get 调用开销

WebDAV GET 需要先调用 alist 的 `/api/fs/get` 获取 CDN 签名 URL。这是一次同步的 HTTP API 调用，通常耗时 100-400ms。

#### 3.3 WebDAV 302 重定向的额外开销

WebDAV 的 GET 返回 302 指向 `/redirect/key`，播放器收到 302 后再发起新请求。这增加了一个完整的请求-响应周期（约 100-200ms）。

#### 3.4 内部探测缺少认证

`/d/` 路径的内部探测返回 401，说明 probeClient 没有携带认证 token。这不仅是检测失败的原因，也浪费了等待响应的时间。

---

### 四、具体优化建议

#### 优化 1：缓存 V2 检测结果（优先级最高）

当前代码中 `fileDAO` 支持缓存 V2 元数据（ContentVersion, NonceField），但安卓端似乎没有有效利用。建议：

- 对 V1 文件（`isV2=false`），也应缓存 "此文件是 V1" 这个结论，后续请求直接跳过 V2 检测
- 设置合理的 TTL（如 24 小时），避免每次都做 3 次探测
- 可以用文件的 size + mtime 作为缓存 key

**预期效果**：冷启动后首次播放慢 2-3 秒，后续请求直接跳过检测，首帧时间从 5-8 秒降到 2-3 秒。

#### 优化 2：内部探测请求携带认证

`/d/` 路径探测返回 401，说明内部请求没有带 auth header。需要在 `inspectEncryptedContentWithFallback` 的内部请求中注入 JWT token 或 session cookie。

**预期效果**：探测 3 能正确工作，如果 CDN URL 探测失败，至少本地路径可以成功检测。

#### 优化 3：CDN URL 探测优化

当前对 S3 预签名 URL 发送 Range 请求返回 400。建议：
- 不修改原始签名 URL 的参数，直接发送 `Range: bytes=0-31` 的 GET 请求（大多数 S3 兼容服务支持在预签名 URL 上加 Range header）
- 或者直接使用已获取到的 `raw_url`（从 `/api/fs/get` 返回的），避免重新构造 URL
- 如果 CDN 明确不支持 Range，跳过探测 1，直接用本地路径探测

#### 优化 4：减少 WebDAV 重定向层级

当前 WebDAV GET 的路径是：
```
GET /dav/file.mp4 → 302 → /redirect/key → 200（流式传输）
```

建议考虑：
- 对 WebDAV GET 请求，直接在第一个请求中就开始流式传输（返回 200 + streaming body），而不是先返回 302 再让客户端重连
- 这样可以省掉一个完整的请求-响应周期（约 100-200ms）
- 对于不支持 302 的 WebDAV 客户端尤其重要

#### 优化 5：存储加载顺序优化

当前所有存储是并行加载的，但 WebDAV 客户端可能在存储加载完成前就发起请求。建议：
- 对 WebDAV 请求增加一个 `StoragesLoaded` 中间件的快速路径：如果目标路径对应的存储已加载，直接处理，不等所有存储
- 或者在 PROPFIND 响应中，对尚未加载的存储路径返回空集合而非 502

#### 优化 6：失败存储快速跳过

unicom_cloud因为 `no route to host` 导致超时 8 秒。建议：
- 对已知不可用的存储设置熔断器（circuit breaker），失败后短时间内直接返回空结果
- 当前代码中已有 circuit breaker 机制（5 次失败后 30 秒冷却），但首次失败仍需等待完整超时

---

### 五、日志中发现的其他问题

1. **aria2 / qBittorrent / Transmission 离线下载工具未启动**：这些不影响播放功能，但如果需要离线下载功能需单独启动。

2. **H2C 连接测试失败**：`H2C connection test failed quickly: http2: frame too large`，回退到 HTTP/1.1。这在本地回环连接上是正常的，不影响性能。

3. **encrypt proxy 初始化告警**：`加密代理服务不可用` — 这是 sync 任务的日志，不影响主服务。

---

### 六、优先级排序

| 优先级 | 优化项 | 预期收益 | 复杂度 |
|--------|--------|----------|--------|
| P0 | 缓存 V2 检测结果（包括 V1 结论） | 首帧减少 2-3 秒 | 低 |
| P0 | 内部探测请求携带认证 | 探测成功率提升 | 低 |
| P1 | 减少 WebDAV 重定向层级 | 首帧减少 100-200ms | 中 |
| P1 | CDN URL Range 探测优化 | 探测更快或更早 fallback | 低 |
| P2 | 存储加载中间件优化 | 减少初始 PROPFIND 失败 | 中 |
| P2 | 失败存储快速跳过 | 减少 8 秒超时等待 | 低 |
