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
| P0-B 导出、契约及文档 | 独立实施中 | `agent/p0-export` / Draft PR #79 / f4806f9（同步main6b99425） | 完成初稿与独立只读review；全量错误返回、literal过滤、limit+1与v2 cursor、敏感字段处理。真实MySQL多页/删anchor/literalfilter集成在run38547668272已执行通过（非skip）；同步main完整PR矩阵run38548773948全绿，PR79已merge到main8d5945d；main完整发布run38550538777 tests/build通过，但release-core 115809069424 artifact下载5次重试耗尽失败；终态后rerun release-core 115813999771仍失败；单作业日志与artifact库存显示无筛选下载包含Buildx非ZIP .dockerbuild，筛选server/tool修复PR #88/head10b6036完整矩阵38553140261全绿，已合入main e9d5b4f；main完整发布38555039570正在验收，未签收不删分支 |
| P1 一致快照/restore | 组件实施及review中 | `agent/p1-bolt-snapshot`、`agent/p1-sqlite-snapshot` / 同名隔离工作树 | Bolt component Draft PR #80 /65dcdef；SQLite升级前component Draft PR #81 /51bbd3d，初稿经review补齐发布/取消/旧schema marker边界，SQLite初版run38548128055真实测试发现候选目录rename失败及late migration fixture问题，已修manifest-last no-clobber发布并同步main候选2cca996/run38549020742全绿；同步PR79新main到e5e2255再完整验证中；未merge。Bolt候选cd48df8/run38548792740完整矩阵全绿；PR79合入main后再同步b89d744重新验证，未merge。OpenList checkpoint语义Draft PR #82，startup恢复fence Draft PR #83（无restore/lock/stickygen完成声称），runtime备份owner Draft PR #84（依赖Bolt组件，component-only/external runtime JSON除外），初候选checkpoint全矩阵已过，后同步main4dfa196；fence6c5b53e/ownerfed98cf亦同步新main重新验证。独立review发现owner Start/Shutdown listener登记race及deadline后active handler仍访问closed store风险，已补真实listener/请求join与h2c ownership绕过修复至PR84 head9f3bc4b，独立静态复审无remaining blocker；实际TCP HTTP1/h2c gate tests写齐，run38553169763实际h2c test发现late connection state重入registry泄漏1，修为所有closed/sealed状态拒登记并补真实TCP迟到state fixture，PR84 headf29b868重跑；PR90继承至1edf9de，不因静态review/旧绿CI直接merge。offline restore CLI/common lifetime lock/DB sticky generation在独立agent/p1-offline-restore实施，review修正Windows lock兼容及旧transport凭据失效；独立review发现reserved source/config被journal覆盖、nested sticky bucket误放行和重复restore抹旧journal风险，正在补拒绝/fixture；已整合PR84真实HTTP/h2c handler join，增加真实HTTP取消后仍持store锁fixture；Draft PR #90/0be180f（含前置PR80/83/84未merge）待完整云编译/tests，不声称已验收。MySQL一致备份Draft PR #86（仅component快照/no restore/no跨storeflush保证），真实MySQL run38552292034发现schema drift未拒绝；独立review补DDL literal保真/strict envelope/发布后错误边界，已修8cf8e8f/run38553656033完整矩阵全绿（真实MySQL非skip）；发布修复合main后同步091c3d7重新门禁，未merge |
| P2 实例/挂载所有权 | 第一安全批实施中 | `agent/p2-instance-owner` / Draft PR #89 /58c229b | bootstrap之前实例租约/factory snapshot/可信身份，重叠拒绝和active client/body未drain不释放；独立review发现HTTP全局指针nil窗口与S3/FTP/SFTP迟到启动可逃逸lease，已修all-endpoint登记/join、顺序restart旧storage/readiness残留及cmd公开bootstrap entrypoint绕租约至0b0a420；同步新main head6b69ebe/run38555570050待云验，独立复审仍发现legacy-first租约碰撞及旧hook未join，正在修；真实mobileGo失败fixtures raw transport wrapper断言/OSS proxy/取消Init mock Drop nil，待同PR修。stdlib endpoint helper -race count20子报告通过，不等完整包/embedded fixture通过；FTP/SFTP无sessionjoin则保lease明确unsupported。所有驱动Drop/join仍需P3，pool总量待验 |
| P3 驱动分批 | 清单准备中（不代表P2完成） | `agent/p3-driver-inventory` | Draft PR #85：81注册包/88名称，22包23名已静态review，59包65名unchecked；无取消证明晋级。10 cheap测试+actual/src mirror过，漂移gate已接CI。runtime改造待P2及清单review |
| P4 异步UI | 云端失败修正中 | `agent/p4-async-files` / Draft PR #87 | 五处sync及单进程owner路径预约，明确不把Dart File.create当跨进程O_EXCL；run38552523221 analyze通过但3widget刷新/overflow失败，已补取消join与真实小viewport滚动/fixture时序至0abe2e7同PR重跑，尚无Flutter tests通过声明 |
| P5 新鲜度 | 实施中 | `agent/p5-freshness` | Draft PR #91/057859e：root/mobile strict opt-in实际caller授权复查与证据分级；独立review发现root admission epoch过晚/响应阻塞后发布未复核/scheme凭据降级及mobile重复payload编译错误，正在同PR修正，未称ready；provider revision优化仍待能力验证 |
| P6 V3别名 | 实施中 | `agent/p6-v3-recognition` | Draft PR #92：root完整认证record识别保守默认1MiB；移动仅shared wrapper无别名classifier入口，明确延后接线不捏造任意URL API；独立review发现现有2worker/2probe fixture与新预算不符，正在补真实成本/Stop回归，未执行通过声明 |
| P7 可信适配/预热 | 首批实施中 | `agent/p7-interest-withdraw` | root authenticated generation withdraw/capability，跨端和App桥能力边界待验证 |
| P8 审计/安全mutation | 首批实施中 | `agent/p8-audit-management` | Draft PR #93/95a1931：敏感JWT+fresh user、原名只读有界导出、本地一致dry-run；无可信upstream caller的remote核对明确blocked/unknown，rename/copy仍拒绝 |
| P9 综合验收 | 待开始 | — | 自动证据矩阵、发布签收 |

## 验证声明

此台账中的“待开始/实施中”不表示已验证。PR所需checks和main完整发布全绿后才记录工程完成；云端不能替代设备体验。生产新发布/配置及网盘测试必须单独核实范围。已有用户文件不批量改名、不覆盖。
