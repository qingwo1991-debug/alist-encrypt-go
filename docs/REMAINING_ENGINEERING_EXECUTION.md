# 非真机工程计划执行台账

计划：`REMAINING_ENGINEERING_PLAN.md`；批准：用户“完成这个plan”。基线 `b5d84da` / `v2026.10.14.414`。

## 采用的默认范围

- 先P0正确性、统一守卫、媒体worker生命周期及导出，再P1一致备份。
- 单写者默认；未知上游CAS能力不承诺严格HA。断点续传、跨规则迁移、新容器版本、独立Docker OpenList后端升级不未经评审自动启用。
- mutation未实现安全审计迁移前，受保护范围明确拒绝，不改已有网盘对象。
- 兼容缓存默认、严格新鲜策略opt-in，V3目录识别保守预算。
- 可信App launch适配，不推断第三方播放器自动切集；排除真机体验验收。

## 当前状态

| 阶段 | 状态 | 分支/PR/发布证据 | 待完成 |
|---|---|---|---|
| P0-A 操作守卫、worker生命周期 | 已交付验证（安全mutation实现仍属P8） | `agent/p0-write-lifecycle` / Draft PR #78；首head `aec6c3f`完整PR矩阵成功（run 38543191485） | review发现catchall/orig_转换绕过及literal百分号误判已补修；33d4032全矩阵成功（38545112340）。再review发现outbound二次URL解释，bef8581修URL Path编码并加真实上游路径回归，run38546687503发现DAV测试nil transport并修夹具为c092c9d，run38547140654完整矩阵（含Android）全绿，PR78已merge，main6b99425；main完整发布run38548692606成功（core、Docker、三ABI/APK/mobile release），实际v2026.10.14.425资产核实上传；PR原生Android已验，main对应PR-only gates按配置skip；本地/远端P0-A分支已删除。未做用户生产部署 |
| P0-B 导出、契约及文档 | 独立实施中 | `agent/p0-export` / Draft PR #79 / f4806f9（同步main6b99425） | 完成初稿与独立只读review；全量错误返回、literal过滤、limit+1与v2 cursor、敏感字段处理。真实MySQL多页/删anchor/literalfilter集成在run38547668272已执行通过（非skip）；同步main完整PR矩阵run38548773948全绿，PR79已merge到main8d5945d；main完整发布run38550538777待验收，暂不删分支 |
| P1 一致快照/restore | 组件实施及review中 | `agent/p1-bolt-snapshot`、`agent/p1-sqlite-snapshot` / 同名隔离工作树 | Bolt component Draft PR #80 /65dcdef；SQLite升级前component Draft PR #81 /51bbd3d，初稿经review补齐发布/取消/旧schema marker边界，SQLite初版run38548128055真实测试发现候选目录rename失败及late migration fixture问题，已修manifest-last no-clobber发布并同步main候选2cca996/run38549020742全绿；同步PR79新main到e5e2255再完整验证中；未merge。Bolt候选cd48df8/run38548792740完整矩阵全绿；PR79合入main后再同步b89d744重新验证，未merge。OpenList checkpoint语义Draft PR #82，startup恢复fence Draft PR #83（无restore/lock/stickygen完成声称），runtime备份owner Draft PR #84（依赖Bolt组件，component-only/external runtime JSON除外），初候选checkpoint全矩阵已过，后同步main4dfa196；fence6c5b53e/ownerfed98cf亦同步新main重新验证。独立review发现owner Start/Shutdown listener登记race及deadline后active handler仍访问closed store风险，正在同PR修真实listener/请求join，不因绿CI直接merge。offline restore CLI/common lifetime lock/DB sticky generation在独立agent/p1-offline-restore实施，review要求Windows lock兼容及旧transport凭据失效；MySQL一致备份在agent/p1-mysql-backup实施（仅component快照/no restore/no跨storeflush保证） |
| P2 实例/挂载所有权 | 第一安全批实施中 | `agent/p2-instance-owner` | bootstrap之前实例租约/factory snapshot/可信身份，重叠拒绝和active client/body未drain不释放；所有驱动Drop/join仍需P3，pool总量待验 |
| P3 驱动分批 | 清单准备中（不代表P2完成） | `agent/p3-driver-inventory` | 固定版本逐操作保守能力清单和漂移gate准备；runtime改造待P2及清单review |
| P4 异步UI | 实施中 | `agent/p4-async-files` | 五处sync及单进程owner路径预约，明确不把Dart File.create当跨进程O_EXCL |
| P5 新鲜度 | 待开始 | — | root/mobile证据和失效 |
| P6 V3别名 | 待开始 | — | 整record/KDF预算/layout |
| P7 可信适配/预热 | 待开始 | — | root/mobile协议、withdraw、App桥 |
| P8 审计/安全mutation | 待开始 | — | 单写管理优先，协调写能力分层 |
| P9 综合验收 | 待开始 | — | 自动证据矩阵、发布签收 |

## 验证声明

此台账中的“待开始/实施中”不表示已验证。PR所需checks和main完整发布全绿后才记录工程完成；云端不能替代设备体验。生产新发布/配置及网盘测试必须单独核实范围。已有用户文件不批量改名、不覆盖。
