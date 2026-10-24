# 本地播放性能优化执行记录

> 对应已批准计划：`LOCAL_PLAYBACK_PERFORMANCE_PLAN.md`。状态：执行中，不代表整体完成。
> 原 `REMAINING_ENGINEERING_PLAN.md` 的未完成项目保留历史，不冒充本轮已交付。

## 当前进度更新（2026-10-24）

生产现为固定摘要 v2026.10.24.521（image ID `6e4d35e9`），不是下面历史的 4f1668e。当前完整交付后安全冷备份、82 条预留保留、五表 SQL 归档及单服务切换记录见 `CURRENT_COLD_UPGRADE_WINDOW_20261024.md`；媒体盘 Unix 权限不生效的问题已按该记录实际加密认证加固，不把创建请求 0600 当有效权限。

- 实际生产 Ctrl+K 浏览器业务 200，旧 guest 错误消失，见 `CTRLK_PRODUCTION_ACCEPTANCE_20261024.md`。
- 新完整收据对象明文 1,602,702,460 字节，30 组 PF0 / HEAD / prefix、32 个最多 16 并发请求及 EOF 416 通过；暖 prefix p50 / p95 为 3.343 / 7.063 ms，见 `PRODUCTION_PLAYBACK_30_SAMPLE_20261024.md`。这是新对象暖态样本，不与旧 WA / IPZZ 不同对象的数字作严格回归比值。
- 该对象前 30 秒实际音视频解码通过：900 帧、输出 30.000 秒、无错误，转发器实际读取约 94.3 MB；不是全片或长时播放，见 `PRODUCTION_30_SECOND_DECODE_20261024.md`。短测后 Go heap 从 30 至 70 / 76 MiB，未声称内存不增长；长时稳态仍待测。
- 已知 WA 逻辑 404 定位到 failed + 无 additive recovery；精确物理路径元数据 207 且密文长度一致，但没有内容头 / 解密证据，合法管理员恢复未执行，见 `WA596_COLD_CLAIM_DIAGNOSIS_20261024.md`。
- 目录首次带斜杠只返回自身的证据仍保留，暖后两入口 1823 项；另有缺失 / null content 被当空目录的独立可复现缺陷，PR111 已在精确头全矩阵通过后合并，main 发行也完整成功，仍未部署、不冒认原事故根因，见 `DAV_SNAPSHOT_SHAPE_GUARD_20261024.md`。
- 同一收据对象的实时 60 秒预检通过：1800 帧，首次读取 117,768,268 字节；修正私有监督器后，限速版 60 秒读取 31,637,580 字节、14 GET，69.906 秒墙钟，清理完整，见 `PRODUCTION_REALTIME_60_SECOND_PREFLIGHT_20261024.md` 与 `PRODUCTION_REALTIME_LIMITED_60_SECOND_PREFLIGHT_20261024.md`。两轮不是严格 A/B，不宣称长期无泄漏，1 GiB / 512 请求也未被证明足够一小时。
- SNOS229 找到 10-21 完整明文 SHA 收据和 10-22 本地 DeletionEvent；一次历史官方 URL HEAD 为 519，不证明永久删除，见 `SNOS229_OFFLINE_IDENTITY_TRACE_20261024.md`。IPZZ172 仍在隔离下载，完成后 984 个完整分片及目标 SHA256 验证器仅通过合成回归，见 `IPZZ172_COMPLETION_VERIFICATION_READY_20261024.md`，没有提前读取在途候选载荷。
- **60 分钟连续播放、后台扫描对照、实际设备首帧 / seek 仍 `device_unverified`**。SNOS229、IPZZ172 的保护、完整来源 / 读回 / 删源门槛和旧源保留不变。

## 历史进度更新（2026-10-18）

当前已部署main `4f1668e`，完整PR及main发布均success，固定镜像digest和现场证据见`LOCAL_PLAYBACK_DEPLOYMENT_ACCEPTANCE.md`。以下b6f2f1b是历史基线，不是当前运行镜像。

- 同IPZZ对象100组305请求混合协议全部正确，首块p50/p95为3.688/8.648ms，对照273a1fe缓存开启时419.451/507.687ms；首中尾采样SHA一致，不将损坏媒体对象的HTTP正确性称影片恢复。
- 实际重启后30组95请求正确，暖首块p50/p95为3.868/11.624ms；冷首次prefix1862.343ms单独保留，不冒称持久数据块或零上游探测。
- 单次PF未知长度异常尚未证明根因。独立追加200次Depth0 PF全部正确；其911字节形状与未知长度404-propstat分支精确+70字节吻合，但未保存当时XML不能定案，不擅自改保护。
- 坏媒体验收本机55项回归通过，主机真实选择下载完成位图及metadata父子关系兼容已部署；SNOS720p新名成品与保留源还在，完整解码执行中；IPZZ真实载荷继续下载。
- 仍待恢复件完整云回读/播放、60分钟实际播放、后台扫描对照、物理设备首帧和seek（`device_unverified`）。原WA failed filename审计继续隔离，未删记录或放宽读。

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
| LP1 索引/本地快读 | `agent/lp1-local-fastread` | PR #96最终head `0607d59`完整矩阵成功，已合并main `4f6ad1aa9c708f7516273238ce8ad698cecc69cb` | PR run `38991083213`、main发布run `38991991650` 均success；已随最终628424f固定镜像部署 |
| LP2 元数据/直链复用 | `agent/lp2-playback-reuse` | PR #99；独立复审要求修URL失效scope、恢复分支epoch旁路及DAV写入失效，正在补HTTP并发计数与旧夹具适配 | 首轮及后续失败已按根因修复；head `36cc6c2`、run `38993019446` 完整矩阵success。最终head `499e8fe` 完整矩阵run `38994970817` success；独立复审已确认HEAD快返及跨代换签旧nonce阻断修复。PR #99 已合main `628424f48298fdde808ac7536151972ce3547a32`；最终main发布run `38995940238` success，已固定摘要部署，详见 `LOCAL_PLAYBACK_DEPLOYMENT_ACCEPTANCE.md` |
| LP3/LP4 解密热点/前台优先 | `agent/lp34-foreground` | PR #98最终head `4eaebca` 全矩阵成功后合main `822de416ac4784b400f2e4965c20a9a9833f26ef`；含可信负缓存最长2秒、revision/epoch失效及2048容量 | 最终PR run `38993342962` success且基准已分析；main发布run `38994347614` success；已随628424f固定镜像部署 |
| LP5 发布与本机验收 | `agent/lp5-acceptance-fixes` | 最终main完整成功后备份并固定digest、启用trusted_local；现场两轮30样本未通过 | EOF404与302缓存身份不一致导致GET回退已定位，正在修复并补针对性夹具 |

## 4. LP3 真实云基准与取舍

PR #98 head `c2f60b4`、run `38992104158` 的 race/performance job 已成功并产出 `performance-baselines`；全矩阵仍待完成。产物已只读下载到本机 `.local-backup/lp34-c2f60b4-performance/`。

- V2 KDF：冷80ms量级、每次1次真实派生；已有缓存热路径约368–399ns、每次0次派生。**不另造key cache、不降低KDF参数。** 该绝对时间来自云runner，不当作本机首帧数字。
- V3已认证record缓存：64/256/1024KiB热路径均0次loader调用，nil cipher/loader仍成功读取；分别约0.75/2.03/24.7µs。冷路径约20/94/442µs，每次1次record load；认证次数指标明确是成功fixture预期逻辑次数，不是生产AEAD仪表。几何是合成已有文件参数，不是修改旧文件chunk。
- record cache热路径24B/op、1alloc/op；key构建约436ns、32B/op。当前证据不支持为本轮增加新缓存、重写加密格式或盲目调大内存。
- 原名索引1千/1万/10万条：暖正/负缓存100次样本约349–777ns/op，0 Bolt读事务/op；歧义保留，每次1次索引读事务，约1.3–3.9µs。该100次微基准不是本机p95；支持消除热全表扫描，但部署后仍需固定主机测量。

## 5. 当前明确未完成项

- LP0–LP4已按最终head完整云门禁合并，最终main发布亦成功；已部署固定digest并启用trusted_local，仅该服务排除Watchtower自动更新。
- 现场验收仍未通过：热HEAD降至毫秒，但热GET因302缓存身份错位稳定回退，EOF404未达416；正在独立分支修复，不宣称整体完成。
- 手机帧事件、完整60分钟播放、真实拖动恢复、Android对照：`device_unverified`。
- 后续每批记录确切head、PR run、main run及部署digest；不得把旧绿结果算作新代码验证。
- 部署前只读核对：本服务仍为基线latest镜像；Watchtower容器运行中，24h轮询且没有发现label-only启用约束。最终compose仅本服务固定digest并加显式自动更新排除标签，避免验收中漂移，不停止/升级其他服务。
