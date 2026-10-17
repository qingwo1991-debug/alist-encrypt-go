# 本地播放优化：部署与验收记录

状态：**已部署第一轮最终集成，但现场验收未通过，不能称计划完成。**

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
- 下一步：修后最终head完整矩阵→main发布→更新固定摘要，再重新验收。
