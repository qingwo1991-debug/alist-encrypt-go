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
- 内容摘要与分段一致性仍须后续比较，不能只凭206判定全部正确。

原始逐请求报告在本机 `.local-backup/lp-final-trusted30-628424f.json` 与 `.local-backup/lp-final-trusted30-repeat-628424f.json`；不含读凭据或直链。

## 资源与未测边界

- 部署早期瞬时RSS约91.42MiB，CPU54.87%，不是稳定内存上限或长时间泄漏结论。
- `device_unverified`：无物理手机/播放器首帧和拖动结论。
- 真实驱动后台扫描开关对照、60分钟播放、100次混合压力、重启持久复用仍待完成；不以CI微基准冒充这些现场结果。
- 下一步：定位并修复EOF404与热GET回退，独立agent分支Draft PR完整矩阵→main发布→更新固定摘要，再重新验收。
