# 本地播放优化：部署与验收记录

状态：**下列 10 月 18 日固定摘要部署和性能数据是历史验收。10 月 24 日已核实生产运行后续 parentproof 定制镜像；PR104 / PR102 / PR105 已分别完整云门禁通过并合并，但尚未把这些新功能部署到生产。长时播放、IPZZ-172 完整恢复及 device_unverified 仍保留未完成状态。**

## 2026-10-24 状态纠正（只读核对）

- 当前运行 `alist-encrypt-go:parentproof-20261020`，镜像 ID `sha256:667dc643322e637414feed77b2df470c0ff31dd3cb5337b91ea6250822444147`，不能沿用下文旧 OCI revision 作为当前二进制来源证明。
- 当前容器 Watchtower 标签为 true；下文历史 false 标签不能当作当前状态。升级仍需固定镜像、明确处理非受控更新和保留一致性回滚数据。
- PR104 最终 `56a5b07` / 运行 `40043521157` 完整成功并合并 `9c9d7ab`；PR102 最终 `15f8988` / 运行 `40044285507` 完整成功并合并 `3bc9209`；PR105 最终 `8c46704` / 运行 `40044179950` 完整成功并合并 `ff61f18`。各主线发布及集成保护仍须单独验证。
- SNOS-397 后续完整明文 SHA 交付收据及经过验证的删源记录已覆盖较早辅助上传失败结论，不能再称原件仍在本地；本轮未重新回读云对象。IPZZ-172 的旧 GID 已不存在，遗留源是大小不符的稀疏文件，未证明完整交付。详见 `MEDIA_RECOVERY_STATUS_20261024.md`。
- 定制维护释放发现物理命名空间及目录证据不足，安全集成保持失败关闭。没有释放真实 claim、清空回收站、重启生产或覆盖云对象。升级清单见 `CONTROLLED_UPGRADE_ACCEPTANCE.md`。

## 历史部署与现场验收（2026-10-18）

- PR101最终head `fefe617`完整云run `39091310626` success；main `4f1668e25b09435c227c8dab9d2d33561e7839b9`发布run `39092090767`完整success，release `v2026.10.18.503`。
- 按成功build-docker日志固定digest `sha256:298029c63cd9fc22a9d4372a2ffb0a801df8f1902ba61895058c2ddb9f59b0a2`，已部署，OCI revision一致。发行版本不是同名OCI tag，不依赖浮动latest。
- 配置trusted_local，enableDecryptedBlockCache=true，256MiB/256KiB有界。PF重写映射保留同对象身份，观察到路径/类型/大小变化时失效持久confirmation及epoch，不移除鉴权与对象隔离。
- 原WA-596因既存failed reservation隔离，保留审计未放宽读取；改用IPZZ-172同一对象比较HTTP协议。该对象媒体索引损坏，以下不证明影片可播放或手机首帧。

| 同IPZZ对象 p50/p95 ms | 273a1fe缓存开启 | 4f1668e 30组 | 4f1668e 100组 |
|---|---:|---:|---:|
| PROPFIND | 7.705 / 22.374 | 6.949 / 27.245 | 7.020 / 13.903 |
| HEAD | 3.348 / 28.468 | 2.951 / 8.160 | 3.171 / 8.680 |
| 首1024字节 | 419.451 / 507.687 | 3.340 / 5.970 | 3.688 / 8.648 |

- 30组中一次PF207未解析出目标长度，保留该异常；后续100组305请求全部预期状态，单文件PF全部明文长度2061432089、HEAD200、prefix/middle/tail206、EOF416、两种目录207且目标长度正确。不能以后续成功抹掉前一次事件，继续监测。
- 与旧镜像同对象prefix/middle/tail各1024字节SHA256一致。无秘密报告保存在`.local-backup/lp-final-mixed30-4f1668e.json`及`lp-final-mixed100-4f1668e.json`。
- 保留原回滚镜像及备份，旧云文件未覆盖删除。SNOS720p替代成品已入库，全解码仍执行；IPZZ重下载继续。入库timer已恢复active，独立保留源未删。

### 实际重启复验

已对最终镜像执行`docker restart alist-encrypt`，随后30组95请求全部符合协议、所有单文件PF明文长度正确。PF p50/p95为7.312/17.745ms，HEAD为3.264/10.202ms，prefix为3.868/11.624ms。首个数据块在重启后冷填充耗时1862.343ms，不能拿暖p50掩盖首次网络成本；PF首请求19.630ms、HEAD3.873ms。仅凭客户端时延不能证明上游探测计数为0，不冒称完整持久几何命中审计。

重启前100组和重启后30组各自所有prefix SHA256唯一且相同。现场空闲采样65.2MiB、CPU0.14%、11 PIDs，无意外重启；这只是采样，不是60分钟稳定内存结论。回滚镜像`alist-encrypt-go:rollback-b6f2f1b`仍可inspect，image ID为`556d8bd3996d4568fec22fec8369369feb352cee4451d8e041caebbf2cab3932`。偶发PF缺长度另开只读专项调查，不改写原异常。

以下为第一轮历史记录，不代表当前仍运行628424f。

## 发布与部署

- PR #96 / #97 / #98 / #99 各最终提交完整云门禁成功后合并。
- 最终主线：`628424f48298fdde808ac7536151972ce3547a32`。
- main 完整发布 run `38995940238`：success，发布 `v2026.10.17.493`。
- 实际镜像清单：`ghcr.io/qingwo1991-debug/alist-encrypt-go@sha256:3673b703e50471c86535c3ebc82050579e122f49c7f697bc2b622a26f4dac355`。
- 本机镜像 ID：`sha256:266218a7aa68d1b573289f40d2ea6ef2b562da0e6fcc00f2a7f1e469a54bc5f4`；OCI revision 与最终主线一致。
- compose 已固定摘要，仅该服务增加 `com.centurylinklabs.watchtower.enable=false`；其他服务未重建。
- 生产配置仅新增 `alistServer.playbackProfile=trusted_local`，不改原规则、凭据或缓存容量。
- 原名索引启动重建12条，ready，耗时1.43ms；MySQL连接成功。

## 回滚准备

- 旧镜像固定本机标签 `alist-encrypt-go:rollback-b6f2f1b`，ID `sha256:556d8bd3996d4568fec22fec8369369feb352cee4451d8e041caebbf2cab3932`。
- 旧清单摘要：`sha256:62c06672c5b15783f324c5f518662608596140b64614d63b3ddcc5b68cc7c7c1`。
- 部署前备份 `.local-backup/pre-local-playback-20261017T024347Z.tar.gz` 包含compose/conf/configs/data；可能含敏感信息，不作为公开交付附件。
- 若需回滚：将该服务镜像恢复旧摘要，保留Watchtower排除标签；配置恢复standard或删除新增profile；只执行该服务的 `docker compose up -d --no-deps alist-encrypt`。本轮没有云端对象写入，不需要云盘回滚。
- 备份运行中取得，不夸称数据库一致性快照；旧镜像可读同一Bolt primary审计，读派生索引会在新版本启动时重建。

## 同源现场测量（每组30次顺序PF/HEAD/前1024字节GET）

对象及探针与基线保持一致；不清CDN缓存，非手机首帧。

| 指标 p50/p95 ms | 基线 b6f2f1b | 集成628424f 第一轮 | 集成628424f 复测 |
|---|---:|---:|---:|
| PROPFIND | 9.362 / 18.065 | 7.244 / 14.008 | 6.658 / 142.476 |
| HEAD | 251.268 / 299.755 | 2.509 / 7.213 | 2.416 / 3.869 |
| 前1024字节GET | 8.734 / 96.627 | 426.551 / 707.262 | 419.568 / 480.995 |

**结论：HEAD明显减少往返，但GET有稳定可复现回退，不能用HEAD改善宣称整体优化成功。**

协议：

- 第一条及其后单文件PROPFIND均为正确明文长度 `2036812696`；HEAD200、prefix/middle/tail206。
- 无斜杠/有斜杠目录PROPFIND均207，目标长度正确。
- EOF `bytes=2036812696-` 两轮均404，而非要求416；仍是验收阻断。
- 已实际比较基线与复测的前缀首/末样本、中段及尾段：各1024字节的SHA-256全部一致；这证明这些采样范围字节未变，不冒充完整2GB文件逐字节校验。

原始逐请求报告在本机 `.local-backup/lp-final-trusted30-628424f.json` 与 `.local-backup/lp-final-trusted30-repeat-628424f.json`；不含读凭据或直链。

## 资源与未测边界

- 部署早期瞬时RSS约91.42MiB，CPU54.87%；后续空闲采样145.9MiB、CPU1.44%、11 PIDs，容器0次意外重启。前后有缓存填充与后台生命周期差异，不能将两点当稳定内存上限或泄漏结论。
- `device_unverified`：无物理手机/播放器首帧和拖动结论。
- 真实驱动后台扫描开关对照、60分钟播放、100次混合压力、重启持久复用仍待完成；不以CI微基准冒充这些现场结果。
- 已定位热GET回退：302入口用初始locator查块缓存，redirect输出却用最终CDN locator写缓存，导致命中身份不一致。修复将保持同一入口身份而不删除来源隔离。
- 已定位EOF404：越界请求先到CDN，CDN404在本地Range校验前被透传；旧fixture上游给416所以漏检。修复将对已知完整几何先本地验证合法越界并直接416，不把任意上游404硬改416，不使合法EOF请求清空对象缓存。
- 后续修复分支 `agent/lp5-acceptance-fixes`、Draft PR #100。首轮head `e98ed43`、run `39030521871` 发现第二入口参数误用 `r` 而非 `req` 的编译错误，已修 `6171867`；另补本地合法416不清暖状态、不计解密失败的终结响应处理，最终head `385b2b4`、run `39030728005` 等待完整门禁。
- `385b2b4` 实际云测试已运行：redirect复用/不同locator隔离无失败；余下失败为旧空V3夹具仍要求1次上游（新契约应0次），以及新越界夹具误把LP0明确保留的V2 bounded ciphertext-tail兼容区间要求为416。修夹具保留该兼容边界，验证真正open-ended EOF与超过完整密文几何的bounded EOF；不改变协议成功断言掩盖错误。
- V2边界：无歧义open-ended明文EOF必须416；旧播放器的容器尾部bounded坐标兼容仍保留，不承诺所有歧义bounded请求都按明文EOF拒绝。
- 夹具修订head `286474c`、run `39031359943` 检出空V3测试计数器 `int64` 与期望变量 `int32` 不匹配，测试未执行；继续原PR修正静态类型，不冒充协议回归失败或成功。
- 最新head `a111f97`、run `39031847066` **完整矩阵success**（含AAR/native/container）；PR #100 已合main `273a1fe027fcb559be20fd56bf63584dc2f07d32`，main发布run `39032821681` 正在执行，未拿PR绿替代发布验证。
- 下一步：修后最终head完整矩阵→main发布→更新固定摘要，再重新验收。
