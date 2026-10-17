# 本地播放性能优化执行记录

> 对应已批准计划：`LOCAL_PLAYBACK_PERFORMANCE_PLAN.md`。状态：执行中，不代表整体完成。
> 原 `REMAINING_ENGINEERING_PLAN.md` 的未完成项目保留历史，不冒充本轮已交付。

## 1. 基线与验证口径

- 实际运行修订：`b6f2f1bbe02a0d1df2fa8ae411de163f3efde7a2`，发布 `v2026.10.17.472`。
- 用户选择：可信本地、单用户、性能和体验第一；允许取消读取前的额外权限验证，但保留不丢文件、不误覆盖、格式正确和回滚。
- 仅对已存在文件执行只读 PROPFIND/HEAD/GET；没有创建、覆盖、改名或删除云盘对象。
- 服务端探针不是播放器首帧测量；样本未强制清理网盘/CDN缓存，不宣称物理冷启动。

## 2. LP0 现场基线

工具：`tools/local_playback_probe.py`；离线测试 `tools/test_local_playback_probe.py`（2/2通过）。
详细报告保留本机 `.local-backup/lp0-baseline-b6f2f1b.json`、`.local-backup/lp0-hot30-b6f2f1b.json`，含响应头、正文摘要及逐请求耗时，不含凭据或签名 URL。

对象：`/dav/156联通云盘/encrypt/4k688.com@WA-596.part003.mp4`。

### 三十样本顺序访问

| 类型 | n | p50 | p95 | 备注 |
|---|---:|---:|---:|---|
| 单文件 PROPFIND | 30 | 9.362ms | 18.065ms | 207；第一条暴露密文长度，之后热缓存正常 |
| HEAD | 30 | 251.268ms | 299.755ms | 200；仍有明显网络成本，待分解 |
| 前1024字节 Range GET | 30 | 8.734ms | 96.627ms | 206；顺序测试会预热缓存，非手机首帧 |

现场确认问题：

1. **长度会随缓存状态变化。** 首条 PROPFIND XML 长度 `2036812728`；同组 GET 的明文 total 为 `2036812696`，差32字节。后续29次 PROPFIND 为正确明文长度。不能因热请求正常就否认首次错误，也不能一律重复减32。
2. **明文EOF Range返回错误。** `Range: bytes=2036812696-` 返回206与尾部32字节 `bytes 2036812664-2036812695/2036812696`，而不是416 `bytes */2036812696`。LP0优先修复，核对V2兼容偏移逻辑。
3. **目录尾斜杠差异。** `/dav/156联通云盘/encrypt` 返回404；同路径带末尾`/`返回207。LP0按资源类型修兼容，不盲目重写全部路径。
4. 中段与suffix尾段各1024字节均206，只证明这些请求读取成功；本轮没有可信完整明文 reference，因此暂不称逐字节解密全片通过。

基线容器瞬时采样：RSS 53.34MiB、CPU40.17%（刚完成请求组的瞬时值，不代表长期平均或CPU瓶颈结论）。

## 3. 批次进度

| 阶段 | 工作分支 | 状态 | 下一门槛 |
|---|---|---|---|
| LP0 协议及测量 | `agent/lp0-protocol` | PR #97最终head `dfc160f` 完整矩阵成功，已合main `2c586df97089828397dbaf979caec738c9935a91` | 最终PR run `38992365077`、main发布run `38993294613` 均success |
| LP1 索引/本地快读 | `agent/lp1-local-fastread` | PR #96最终head `0607d59`完整矩阵成功，已合并main `4f6ad1aa9c708f7516273238ce8ad698cecc69cb` | PR run `38991083213`、main发布run `38991991650` 均success；尚未部署 |
| LP2 元数据/直链复用 | `agent/lp2-playback-reuse` | PR #99；独立复审要求修URL失效scope、恢复分支epoch旁路及DAV写入失效，正在补HTTP并发计数与旧夹具适配 | 首轮及后续失败已按根因修复；head `36cc6c2`、run `38993019446` 完整矩阵success。最终集成head `8d71514`（含LP0/LP34、显式刷新、共同Depth:0/probe、目标选择expected epoch/revision保护）；修复run `38994512889` 新probe字段编译错以及独立复审的HEAD快返/跨代换签旧nonce阻断。复审已确认撤回两项阻断；run `38994780077` 再定位probe对具体DAO错误type assertion，已修 `499e8fe`；最终run `38994970817` 核心Go/race/移动Go/MySQL/Web/Flutter/探针全部success，仍待余下AAR/native/container全绿 |
| LP3/LP4 解密热点/前台优先 | `agent/lp34-foreground` | PR #98最终head `4eaebca` 全矩阵成功后合main `822de416ac4784b400f2e4965c20a9a9833f26ef`；含可信负缓存最长2秒、revision/epoch失效及2048容量 | 最终PR run `38993342962` success且基准已分析；main发布run `38994347614` success；现场仍未切镜像 |
| LP5 发布与本机验收 | — | 待前置验证 | 固定digest、备份、仅重建本服务、复测和回滚 |

## 4. LP3 真实云基准与取舍

PR #98 head `c2f60b4`、run `38992104158` 的 race/performance job 已成功并产出 `performance-baselines`；全矩阵仍待完成。产物已只读下载到本机 `.local-backup/lp34-c2f60b4-performance/`。

- V2 KDF：冷80ms量级、每次1次真实派生；已有缓存热路径约368–399ns、每次0次派生。**不另造key cache、不降低KDF参数。** 该绝对时间来自云runner，不当作本机首帧数字。
- V3已认证record缓存：64/256/1024KiB热路径均0次loader调用，nil cipher/loader仍成功读取；分别约0.75/2.03/24.7µs。冷路径约20/94/442µs，每次1次record load；认证次数指标明确是成功fixture预期逻辑次数，不是生产AEAD仪表。几何是合成已有文件参数，不是修改旧文件chunk。
- record cache热路径24B/op、1alloc/op；key构建约436ns、32B/op。当前证据不支持为本轮增加新缓存、重写加密格式或盲目调大内存。
- 原名索引1千/1万/10万条：暖正/负缓存100次样本约349–777ns/op，0 Bolt读事务/op；歧义保留，每次1次索引读事务，约1.3–3.9µs。该100次微基准不是本机p95；支持消除热全表扫描，但部署后仍需固定主机测量。

## 5. 当前明确未完成项

- 本轮尚未部署新镜像、启用可信本地模式或改变生产配置。
- LP0/LP1 已按最终head完整云门禁合并；LP2/LP3/LP4 最终集成仍在验证，不能把旧head成功当成本机已更新。
- 手机帧事件、完整60分钟播放、真实拖动恢复、Android对照：`device_unverified`。
- 后续每批记录确切head、PR run、main run及部署digest；不得把旧绿结果算作新代码验证。
- 部署前只读核对：本服务仍为基线latest镜像；Watchtower容器运行中，24h轮询且没有发现label-only启用约束。最终compose仅本服务固定digest并加显式自动更新排除标签，避免验收中漂移，不停止/升级其他服务。
