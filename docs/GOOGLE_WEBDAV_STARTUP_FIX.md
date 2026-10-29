# Google Drive WebDAV 启动等待调查与修复

## 已取得的运行证据

本轮只读检查本机 `alist-encrypt` 和 `openalist`，没有修改容器、代理、服务或运行配置，没有读取实际账号/加密密码，也没有下载整部媒体。

- 加密容器镜像 ID：`sha256:6e4d35e9a5b8f5e542fb2610f2badf47a0d446905842e31b2b7248dc4a2560a1`，OCI revision `698ae60091cd624c5289aa2c69d7ec3ec7b5b8b2`，本轮查看时 healthy、RestartCount 0。
- OpenList 容器镜像 ID：`sha256:660a850dc9df6bcbf77104dd8e6b45593857002e03f1242f68030d28ec608866`，OCI revision `3b28270a4066ea52943a69ecddd850d83f7e8bdc`。这些是本轮查询时的信息，不是未来部署来源证明。
- 所选近期窗口中，目标 Google 挂载有 24 次播放 GET 和 24 次 `raw_url warmup failed`，全为 `status=200 reason=raw_url_empty source=fs_link`。按同 request ID 的秒级日志时间，Processing → warmup failed 为 1～3 秒，中位数 2 秒。日志时钟精度不足以当毫秒分段性能测量。
- 24 次 GET 的完整请求耗时中位数约 5653.545 ms；两个仅返回 12 字节的尾部请求耗时 3114.459 / 2336.545 ms。**这些数字不是云盘吞吐率**：它们包含取链、上游等待、客户端背压或提前关闭。
- 同一所选播放窗口有 7 次 WebDAV `unexpected EOF`、`failure=network_error`。没有因此断言 Google 限速或文件损坏。其他更宽日志计数会同时包含底层/handler 的重复错误记录，不能将其当独立断流次数。
- 观察到完整 V1 几何和文件大小缓存命中；最初资源采样 CPU 约 0.2%，后续约 5%。这不支持明显 CPU 满载假设，但不是长期性能基准。

## 定位

### 可选直链探测串行挡住实际播放

旧 WebDAV 实现对无 Range 启动 GET、首帧 Range 和 trusted-local 请求，在没命中正直链缓存时同步尝试：

```text
/api/fs/get → /api/fs/link → /d HEAD/GET → /dav HEAD/GET
                                                   ↓
                               失败后才开始实际 /dav 取流
```

只有成功 URL 会缓存；完成后的 singleflight 会移除。因此同一对象后续请求可能反复支付失败探测成本。冷几何确认的元数据探测仍需保持独立，不能为了减少等待而跳过明文长度或解密验证。

### HTTP 200 不等于鉴权成功

旧 `fetchRawURLViaAPI` 把 JSON `code != 200` 和真正的空 `raw_url` 合并为 `raw_url_empty`，日志中的 status 只是 HTTP 状态，随后可能继续 fallback。

本轮仅使用**明确无效的合成 Basic 凭据**，向本机 5244 的 `/api/fs/get` 和 `/api/fs/link` 发送不存在诊断路径：两次均返回 HTTP 200、业务码 401，分别约 14.27 / 1.27 ms。请求在鉴权层失败，没有访问真实云对象；未读取或试用实际凭据。该结果证实本机错误形态可触发旧误分类，**不能证明先前真实播放请求的业务码就是 401**。

bundled OpenList 的 metadata middleware 解析 Authorization 为 token，WebDAV 的 Basic 不能在这里直接当 JWT 使用。GoogleDrive 驱动 `OnlyProxy=true`，媒体链接还依赖服务端 Bearer header；成功的 FsGet 对必须代理的驱动可以返回本地 `/p` 地址。因此 **OnlyProxy 本身并不证明 raw_url 一定为空**，也不能拿一个裸 Google URL 绕过服务端代理鉴权。修复不兑换或借用管理员/扫描 JWT。

### EOF 原因混淆

旧流复制没有保留上游 Read 与下游 Write 错误来源。`io.CopyBuffer` 直接返回 `io.ErrUnexpectedEOF` 时走通用 network_error 分支；copy 成功但实际字节不足时则另标 upstream_truncated。请求取消竞态也可能被粗粒度错误覆盖。

响应已经开始后不能偷偷重新取完整流或拼接未验证字节；`fresh_retry=false` 在该边界是安全要求，不应当作重试失效。

## 本轮修复与自动化验收

1. 冷 WebDAV 读不再同步等待可选直链探测；继续使用已有正常鉴权的内部 DAV 路径，命中有效正缓存仍复用。Basic 请求不再预热不兼容的 metadata API，不进行 Basic→JWT 兑换或借用后台扫描账号。
2. 后台取链归 WebDAV handler 生命周期所有：最多 4 个活动任务、零排队；按 origin、显示/真实路径、显式 Authorization+Cookie 摘要、epoch 和配置 revision 去重。请求取消、3 秒超时和 Stop 会取消实际 I/O，Stop 等待任务退出。不引入负缓存，鉴权/网络失败不会成为驱动能力结论。
3. HTTP 与 JSON 业务码分别记录；非成功 HTTP 或业务错误不再被当空 URL 继续 fs/link/redirect fallback。日志只添加 phase、status、business_code、是否有 URL、duration_ms，不添加凭据、URL 或上游错误正文。
4. 保留明文大小、Range、加密几何和对象身份校验。后台发布沿用 epoch 原子围栏与取消校验，并使用 `Config.PublishIfRevision` 将最终本地发布与配置更新串行化，关闭 revision 检查和写入之间的窗口；不用 transport length 覆盖已确认的明文几何。
5. 流复制按 Read/Write 来源及请求取消状态分类：已明确的上游 Read UnexpectedEOF → upstream_truncated；下游写 EOF/短写不冒充上游断流；请求取消优先为 client_disconnect，deadline 仍 timeout。真实失败不变成功，响应提交后 Retryable=false、NoLearning=true，不重新拼接流。

新增自动化覆盖：

- `internal/handler/webdav_raw_transport_safety_test.go`：HTTP 200 业务失败不能触发备用取链或写正缓存、HTTP/redirect 权限拒绝、后台上限与跨凭据隔离、Basic 无 metadata 请求、取消/Stop/epoch/revision 围栏。冷启动时序用阻塞 metadata 的 barrier 断言实际 DAV 能先开始/结束，而非 sleep 后猜测性能；Basic 连续 24 次冷读及 24 次正缓存读均无 metadata 请求。这里的“冷”指无直链缓存，解密几何仍已确认。
- `internal/proxy/newstream_eof_test.go`：同一次 Read 的 data+error、相同 EOF 来自 Write 的优先级、WriterTo/ReaderFrom 不绕过来源检查、取消竞争、deadline、短读及完整字节仍报错；本地 loopback V1/V2/V3 短响应、正确明文、下游写 EOF/短写，每次只发起一次媒体请求，V3 不泄漏未认证记录。
- 已有 `stream_integrity_test.go` 的短读断言改为与已提交响应的终止契约一致；不是删除截断失败判断。

本地最终联合 focused gates 通过：`internal/handler` 1.227s、`internal/proxy` 3.192s，包含以上新增测试和已有 raw URL、scope、确认元数据、响应开始后终止/V3 截断回归；gofmt 检查和 `git diff --check` 通过。测试使用离线缓存依赖，没有安装依赖或构建移动端。完整 Go/race/MySQL/Web/mobile/Android/container 验证由正常 Draft PR 事件触发，不使用 workflow_dispatch；最终 CI 结果随交付记录补充。

## 未测边界

- 未重新播放真实 Google 对象或实测出口吞吐、物理设备首帧、完整解码、长期播放与 seek 体验。
- 未改变 OpenList 代理出口，也未证明 Google 或中间代理是 EOF 的唯一来源。
- 未部署、重启或替换本机容器；代码与 CI 成功不等于运行服务已生效。
- `device_unverified` 保留。后续运行验收应分开记录前置取链、首个上游字节、客户端首帧及取消事件，不记录签名 URL、Bearer、Cookie 或文件内容。
