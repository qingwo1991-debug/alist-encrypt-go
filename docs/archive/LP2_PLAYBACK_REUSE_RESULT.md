# LP2 confirmed geometry 与传输复用实施记录

状态：实施与云验证中；本文件不是测试通过、发布或部署声明。主计划为 `LOCAL_PLAYBACK_PERFORMANCE_PLAN.md`。

## 实现

- `trusted_local` 且请求具有完整 raw/display/rule 身份时：确认几何按 origin/raw/rule/profile 身份复用，本地 token 不参与；标准模式保留既有完整元数据复用行为，不强迫所有旧记录升级探测。
- 独立 Bolt `playback_confirmed_v1` 可重建缓存负责重启复用，不依赖 MySQL 字段回读；24h 几何 TTL，内存和持久记录各最多2048项。旧记录缺完整参数时按需检查，不补默认 chunk/KDF。
- FileDAO 所有权下的有界 loader（最多128个不同 key，15s工作超时）合并 metadata 与 transport 各自工作。一个 waiter 取消不影响其他 waiter；最后 waiter 取消后保留 flight 到真实 worker 退出；FileDAO.Stop 取消并 join。
- 进程 epoch 围栏拒绝失效前发布。WebDAV 写入口在操作前及返回后保守失效（失败也可清缓存）；URL失效只换代在途工作、保留有效确认几何。
- raw URL 使用独立身份与授权 scope，当前实际请求仍携原调用者凭据；URL解析大小不得覆盖明文大小和确认的容器几何。签名到期用已有 expiry/TTL 检查，单对象并发换签共享。
- trusted WebDAV 任意 Range 可复用有效 URL；冷请求不先做额外串行 size HEAD；健康冷路径先检查选中目标一次，失败再走既有兼容候选。V3补完整头/尾仍可需多个必要 Range。
- trusted hot HEAD 可直接返回完整已确认明文长度，不联网；cold HEAD 经共有确认后返回。

## 已编写夹具（未本地运行）

- DAO确认缓存重开、失效后旧epoch拒绝发布、返回nonce不共享、16 waiters合并/取消单waiter、最后取消后真实退出才释放、Stop join。
- HTTP真实V2 header冷16请求一组探测及warm0；非默认V3 chunk73/KDF1234冷16请求两段必要头探测及warm0。
- 16请求共享过期签名URL的一次fs/get，几何保持；传输size不能污染明文/容器大小；旧transport epoch不得发布。
- trusted confirmed HEAD 零上游请求；实际DAV PUT/DELETE 204后的确认缓存清除及旧发布拒绝。
- 原名hot routing夹具已改为显式完整确认，不用旧 `Set` 缺身份记录冒充新confirmed contract。

验证：gofmt 与 `git diff --check` 通过。遵循已有沙箱缓存拒绝，不重复本地Go测试/下载；所有Go测试以父会话的确切PR head云端结果为准。早期云失败暴露的显式origin与配置origin混用、standard无谓重新探测、mock缺确认等已按根因修正，仍需最终head完整门禁。

## 边界及后续集成

- LP0 cold Depth:0 应接共同确认服务，而非只对DAV GET检查；待父合并LP0后定向接线。当前无生产修改。
- 持久失效失败会报error日志并禁用本进程持久确认读取，直到成功清理。现有公开 `InvalidateDisplayPath` 为void，无法把错误反向传给已完成的远端写入；底层存储故障后必须修复/清缓存再重启，不能宣称坏盘情形仍绝对零旧值。此故障边界需执行报告明确，不吞错误。
- 对象同路径同大小外部替换、无可靠validator时仍是TTL稳定性假设；不是实时内容未变证明。
- 物理手机首帧/60分钟播放、正式镜像部署、main发布验证均由父阶段处理，本分支未测、不宣称完成。
