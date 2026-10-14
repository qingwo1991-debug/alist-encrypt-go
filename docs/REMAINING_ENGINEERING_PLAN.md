# 历史目标工程补齐计划：非真机范围

> 状态：用户已批准执行；进度与验收证据见 `REMAINING_ENGINEERING_EXECUTION.md`。本文件描述目标，不代表所有阶段已实现。
>
> 基线：`b5d84dad09169ec44e1d6ae59698abdc14f09c90`，对应已验证发布 `v2026.10.14.414`。本计划基于当前源码、已有验收文档和只读复核，不把旧设计中的 TODO 自动当作现存缺口，也不把 CI 全绿当作真实播放器体验证明。
>
> 计划编写阶段仅交付文档；实施阶段按独立分支、Draft PR及main发布门槛逐批推进。不擅自更改生产配置或网盘用户对象。

## 1. 新一轮要达到什么

### 1.1 总目标

在保留此前播放、共享 V3、缓存、取消和联通长名成果的基础上：

1. 补齐已经发现的接口正确性和写操作覆盖缺口。
2. 让数据库备份可验证、可恢复，完整原名记录不能因“有备份文件”而被误以为已安全保存。
3. 将驱动路由与取消从目前实际接入的 MEGA，推进到明确列出的其他驱动和专用传输；未接入的必须显式展示，不能伪装为全驱动支持。
4. 移除已确认的 UI 同步磁盘操作，同时保持同名预约、下载取消和文件所有权正确。
5. 为元数据、展示别名和实际内容分别建立可解释的新鲜度策略；减少重复探测，但不以旧缓存冒充当前对象证明。
6. 增加有预算的 V3 视频别名识别，复用已有认证 record 和 KDF，避免目录扫描触发大规模下载或派生。
7. 为我们能控制的客户端增加可信播放兴趣适配和受约束预热；不从 IP、Range 或第三方播放器流量猜测切集。
8. 设计并按能力逐步实现原名审计的迁移、管理和写协调；没有上游原子条件写时，不承诺任意外部写入竞争也绝不覆盖。
9. 最终以源码覆盖清单、可重复自动验收、恢复演练、完整发布和必要的授权服务端实测收口，而不是靠“基本可用”签收。

### 1.2 本次不纳入完成条件

- Android 真机、OEM、实际 VPN/TUN 与物理网络出口验收。
- MX 等外部播放器的物理首帧、完整播放、真实耗电和蜂窝无线电活动测量。
- 无客户端配合时，自动理解任意外部播放器的播放列表、退出或切集。
- 无不可变远端版本或可靠验证器时，同时保证永久零探测和严格最新内容。
- 无远端条件创建/提交能力时，保证绕过代理的外部工具竞争也不覆盖。
- 本次直接更换 V3 文件格式或默认重加密已有文件。
- 自动推广联通的 100 字符上传限制到其他网盘，或把该限制等同 rename/move/copy 的极限。
- 一次大改重写所有移动代理代码、无审核更新 OpenList/SDK 依赖。

## 2. 当前证据与新增发现

### 2.1 已交付，不重复造轮子

- PR #67–#73：测量与故障上游、移动共享 V3、小块和认证缓存、有界 KDF、显式兴趣 API、原生路由/MEGA 取消、生命周期及验收文档。
- PR #74：MX WebDAV 明文长度/Range 修复。
- PR #75：移动可信元数据持久化复用和可选邻集预热。
- PR #76–#77：联通完整限长编码、完整原名审计、同步上传冲突拒绝、历史视频别名和空目录兼容。
- 当前本机生产已经验证 API/DAV 长名上传、重复409、Range前缀、正确凭据隔离及重启后反查；记录见 `UNICOM_DEPLOYMENT_VERIFICATION.md`。

### 2.2 本次复核确认的工程缺口

| 缺口 | 当前源码/文档依据 | 处理优先级 |
| --- | --- | --- |
| 写保护并非所有 mutation 入口同等覆盖 | `internal/handler/alist.go` 的 API move/copy 没有与 PUT 相同的限长/占位流程；rename 与 DAV MOVE/COPY 只有部分长度检查，没有原名审计事务迁移 | P0，先封住不支持的受保护操作 |
| Bolt 导出与文档承诺不一致 | `internal/handler/api.go` 的 Bolt fallback 未应用 provider/path/path_prefix/since/cursor 过滤，分页 `has_more` 计算也需要修正 | P0，独立正确性修复 |
| 接口说明过时 | `DB_EXPORT_API.md` 仍描述 UUID/非空 token 和 query token；当前 `internal/server/middleware.go` 实际验证 JWT 且不接受 query token | P0，修正文档和契约回归 |
| 移动备份不是 WAL 一致快照 | `mobile/openlist-lib/openlistlib/encrypt/local_store.go` 启动时复制 SQLite 主文件；`ExportAll` 仅导 sizes/strategies，且非同一读事务 | P1 |
| 工厂存在不等于驱动全部接入 | `NewDriverHTTPClient` 当前实际驱动调用仅 MEGA；`DriverRouteIdentity` 只有 Driver/Provider，登记工厂仍为全局 | P2/P3 |
| 遗留同步磁盘调用 | `mobile/lib/utils/download_manager.dart` 的 existsSync/listSync及`pages/download_manager_page.dart`的build/dialog statSync，共确认五处 | P4，不能机械替换成 await |
| 根媒体识别worker没有完整Stop所有权 | `internal/handler/media_name_recovery.go` 直接启动WithoutCancel后台worker；`WebDAVHandler.Stop`未取消/join该worker | P0补生命周期，P6不得沿用 |
| 同路径同大小变更的新鲜度有限 | 移动确认24h、同 validator namespace 才比较；根别名读取按 scope/TTL/可选大小，没有重新证明历史 validator | P5 |
| V3 视频别名识别尚未支持 | `internal/proxy/media_identity.go` 对 V3 明确拒绝 | P6 |
| App 没有可信兴趣适配 | 根端有 `playbackInterest`；当前移动 encrypt 包未发现同等 endpoint；App 主要转发 URL/intent，没有可靠逻辑文件事件 | P7 |
| 本地占位无法协调独立实例和外部写入 | `internal/storage/filename_records.go` 是单 Bolt 物理目标占位，失败/完成占位保留 | P8，能力分层而非假保证 |

这些发现不否定此前已验证的 PUT 和历史别名结果，但说明“所有写操作都保护好了”“导出就是完整备份”等说法不成立。应先纠正，之后再拓展功能。

## 3. 共用工程约束

1. **兼容**：保留 V1/V2/V3 读取、现有密文和默认 chunk；新功能默认保守/可关闭。旧源文件命名解析不全局替换。
2. **权限**：实际上游调用用对应调用者/已授权任务身份；管理 JWT 不是 provider credential；不同凭据、规则、origin 不共用确认。
3. **所有权**：任务有明确 owner、context、并发/队列/字节预算。取消等待者不假装正在执行的 CPU/I/O 已停止；停止要真实 join。
4. **响应**：成功头/正文发布前完成必要验证；已经发出正文后不拼接重试或错误 JSON。
5. **不可逆数据**：完整原名及写入审计属于关键数据；媒体确认/策略缓存可重建，二者备份和清理策略不同。
6. **可解释性**：区分 `implemented`、`automated_verified`、`server_verified`、`device_unverified`、`unsupported`；拒绝不是支持，编译不是体验。
7. **源码覆盖**：修改移动 upstream tree 必须同步 actual/src、更新受控 overlay 路径和 pristine 指纹，不能绕过检查。
8. **文档**：以最新完成证据为准；旧 handoff/设计保留历史身份，并链接当前状态，不能依靠旧文档重复造轮子。

## 4. 阶段总览与依赖

| 阶段 | 交付目标 | 依赖 | 建议 PR 粒度 | 优先级 |
| --- | --- | --- | --- | --- |
| P0 | 覆盖缺口、导出正确性和基线台账 | 无 | 操作守卫、导出、文档分别拆分 | 最高 |
| P1 | 一致快照与恢复演练 | P0 契约 | SQLite/Bolt，再恢复工具 | 最高 |
| P2 | 存储会话路由/取消契约与所有权 | P0 | 独立基础设施 PR | 高 |
| P3 | 按驱动批次接入并报告覆盖 | P2 | 一类或少量驱动一 PR | 高 |
| P4 | UI 文件 I/O 异步化与安全路径预约 | P0/P1数据边界 | 预约、目录操作可分开 | 高 |
| P5 | 元数据与别名新鲜度分层 | P0，可与P2–P4并行 | 契约、root/mobile适配 | 高 |
| P6 | 有界 V3 视频身份识别 | P5 | reader预算、handler别名 | 中 |
| P7 | 可信客户端兴趣适配与预热条件 | P2/P5 | 服务契约、App adapter、UI | 中 |
| P8 | 原名审计管理、安全 mutation 与协调写 | P0/P1/P5/P3对应能力 | 单写管理、协调、逐项mutation | 高风险，分批 |
| P9 | 自动综合验收、发布与证据收口 | 所有批准必选阶段 | 故障/资源矩阵及最终文档 | 最终门禁 |

推荐主线：**P0 → P1 → P2 → P3**。P4/P5 可在契约稳定后并行；随后 P6/P7。P8 不阻塞前面改进，但不得以基础阶段完成代替多实例功能完成。P9 每阶段积累证据，最终统一签收。

不估计固定日历日期：驱动 SDK 的真实 context/transport 钩子、上游条件写及迁移成本尚待阶段内确认。排期使用 PR/验收门槛，不用未经验证的“几天全部完成”。

## 5. P0：先建立准确基线，封住覆盖缺口

### 5.1 写操作能力台账与统一守卫

- 枚举 API PUT、rename、move、copy、批量/任务式操作、目录 mutation，以及 DAV PUT/MOVE/COPY/DELETE 与 raw 表示入口；逐一标注是否允许、是否限长、是否占位、是否迁移原名审计。
- 判断源或目标是否与受保护挂载/其目录子树相交；不能只检查目的 basename。覆盖跨范围、跨规则、批量、上级目录移动和目标覆盖。
- 在安全 mutation 实施前，对受保护范围的 unsupported rename/move/copy/resume 明确拒绝，不向上游发送请求。未配置挂载保持既有行为。
- 返回稳定错误分类和操作原因：`protected_operation_unsupported`、`destination_conflict`、`audit_unavailable`；协议状态和客户端展示分别定义，避免把能力拒绝误报上游故障。
- DELETE 保留删除语义，但删除成功后的原名审计先保留 tombstone/历史，不自动解除失败或已完成占位；不得据缓存404释放。
- 更新联通文档，明确当前 PUT 保护与 mutation 保护的差别，不宣称旧版全入口覆盖。

**验收**：真实 handler + recording loopback 上游；危险操作上游请求数为0，合法 PUT 不回归；覆盖 source/dest、目录子树、批量、URL编码、Destination异常、短名/长名及未配置挂载。对别名/有审计短名不能重新编码成另一个错误源对象。

### 5.2 导出接口修正

- 明确区分“同步导出”与“完整数据库备份”。修复 Bolt 过滤、分页和可证明的 cursor 顺序；排序/游标以稳定的更新版本与唯一键组成，避免仅秒级 since 导致同秒数据遗漏。
- 多页全量需要 snapshot upper watermark 或明确弱一致模式；增量需要删除/tombstone和revision语义。做不到的模式明确 `unsupported`，不能返回看似完整的空结果。
- 检查 MySQL 与 Bolt 的响应契约一致性，并对移动同步 consumer 回归；为新契约加版本字段，保留老接口兼容适配而不是悄悄改变 cursor 含义。
- `has_more` 用明确下一条/limit+1或一致快照计数证明；不能从已截断的列表猜。
- 默认导出不泄漏可重用signed URL、token和凭据；若历史字段必须兼容，提供明确敏感模式/权限和弃用迁移。
- 修正 `DB_EXPORT_API.md` 的JWT、token transport、Bolt fallback、分页和备份边界。

**验收**：多于两页的全量、provider/path/prefix过滤、同时间戳更新、分页中更新/删除、invalid cursor、重启继续、权限与敏感字段；MySQL真实集成服务与Bolt fixture使用同一组契约断言。

### 5.3 媒体别名worker生命周期

- 把根端媒体识别flight接入实例owned context、准入fence和wait group；单个request取消只撤销等待，不取消其他共享者，实例Stop必须取消实际网络I/O并join。
- Stop不能仅停止proxyHandler就关闭store；即便构造失败、未Start、重复Stop也保证顺序。重配置加入mount/rule epoch防止迟到任务落库。
- unknown-format、网络失败、权限失败、预算不足和caller取消分开冷却；不能都按固定5分钟“格式失败”惩罚。

**验收**：两个等待者取消一个仍成功；Stop在headers/body/入队阻塞期间使真实请求退出，store-close之后零落库；配置变更中flight不重新发布旧确认；owned pending归零。此项先做，不等待新增V3。

### 5.4 历史目标证据台账

- 每个历史目标对应实现路径、最新测试、PR/main提交、产物及残留范围。
- 复核旧 handoff 中 warm状态/记录字段是否已完成；只补实际缺失的链路，不复写现存调度器。
- 发布能力信息显示准确版本/commit、模块和驱动覆盖，而不是仅笼统 `1.0.0`。

## 6. P1：一致备份、关键审计保护与恢复

### 6.1 SQLite

- 使用固定 sqlite driver 实际可用的 online backup API；若采用 `VACUUM INTO`，先验证固定SQLite版本、事务一致性、取消/锁预算和文件错误处理。不把主文件/WAL独立复制拼成一致快照。
- pre-migration备份在 schema升级前、通过合法连接完成；runtime备份通过store拥有的受限worker。不能先迁移、再把快照称为升级前备份。
- 开始前定义“仅已提交DB事务快照”还是“含已完成flush的应用状态”。后者先建立flush barrier/watermark；snapshot之后的提交不混入该水位承诺。
- 移动OpenList自身`data.db`和加密代理`local_media.db`是不同组件。`ForceDBSync`仅对OpenList DB执行PRAGMA，目前忽略checkpoint返回busy/log/checkpointed结果；按实际DB引擎分支、读取真实结果并修正“已完全合并WAL”的过强说明。checkpoint不替代一致备份，MySQL不套SQLite PRAGMA。
- 避免占用唯一查询连接很久而饿死播放；采用有界分步、busy预算、截止时间和明确取消。实际API选型以固定driver验证为门禁。
- 快照必须覆盖数据库实际表，而非只导sizes/strategies。对 confirmed metadata、stats、sync checkpoint/schema列出包含项。

### 6.2 Bolt 与 MySQL

- 根Bolt使用读事务快照（如事务 `WriteTo`），包含完整原名、占位、反向索引及别名；复制后读验证主/反向索引一致。
- MySQL元数据导出走数据库自身一致事务或合规工具。没有联合写屏障时，Bolt/SQLite/MySQL只承诺各自一致，不声称跨数据库同一时刻的整站快照。
- 需要跨store一致性时另设短暂停写/提交水位及restore校验；只对已实现的协调域给保证。

### 6.3 产物与恢复

- 写临时文件 → 完整校验 → flush/fsync → 同文件系统原子发布（平台能力允许时同步目录）；只有已验证快照才参与保留轮换，失败不删除上一份好备份。
- manifest含格式/schema、源commit、时间、水位、内容hash、组件、加密/敏感等级，不含明文口令/签名URL。备份文件按敏感数据控制访问，必要时提供独立加密方案。
- 恢复只能在停止服务/独占环境进行：校验hash、schema和引擎完整性，先备份现库，不做热覆盖；失败可回退。
- 恢复不得重置确认时间延长TTL；旧auth/rule确认仍需重新授权。原名审计与占位历史不能因为恢复缓存而清空。
- 恢复旧审计快照可能缺失备份之后已在网盘成功保存的对象。恢复后默认只读或进入reconciliation，不能因本地占位消失就批准再次写入；signedURL/session等过期传输信息失效，原名审计保留。

**验收**：WAL中存在未checkpoint提交、并发写、未提交rollback、取消、磁盘满、目标已存在、进程中断、重复备份及Stop；恢复后query一致、主/反向索引一致，关键原名可查，过期别名不被当新证据。输出自动restore演练报告。

## 7. P2：驱动契约与实例所有权

### 7.1 身份和生命周期

- 驱动身份从可信storage bootstrap创建，至少区分driver/provider、storage实例、server实例、配置epoch；不把用户header或URL猜测当挂载身份。
- 收敛全局factory登记风险：注入实例拥有的factory/registry；若固定上游结构不支持多实例则明确拒绝重叠启动，不能后注册实例覆盖已有实例策略。
- 区分 session context、operation context和reader context。短Init deadline不能成为整个成功session生命周期；Drop取消session任务并join，response body实际结束才归还资源。
- 配置更新：发布新factory snapshot、已初始化session按明确reinit策略应用；显示pending configuration epoch，不暗示所有现存client已热更新。

### 7.2 路由/传输能力契约

- control/probe/media/upload分purpose预算，重试是原始整体deadline的一部分；限流、锁等待、backoff也计入。
- immutable route decision同时固定Proxy/DNS/Dial/TLS/redirect policy；pool key含实例、storage、route、generation及必要representation维度。
- 不动态修改global Resty client，不用取消等待者+遗弃goroutine伪造真实取消。
- 不把“设置30秒client Timeout”当所有操作预算；大文件流、响应头、上游读取空闲和慢下游写入分别处理。
- proxy endpoint DNS/socket和origin远端解析语义分开；跨origin credential不转发；active body不因拓扑通知被不加区分强关。
- 同时设单storage和实例总体pool/task预算。不能只声明每个storage32项便忽略很多挂载后的总量。
- 当前共享KDF及root/mobile认证record cache具有process-global作用域。明确process总预算、instance namespace及退出清理责任：某实例Stop不得关掉其他实例的共享KDF，数学key复用也不能代替对象版本/授权证明；没有可信revision时保留保守cache identity。

**验收**：同host不同storage/代理并发、两个server实例、config reload/reinit、失败Init清理、Drop中body/backoff/queue阻塞、停止重启、DNS/token更新fake bridge；实际loopback取消及资源归还，不靠源码字符串检查。

## 8. P3：驱动分批接入，不做全局Client一键替换

### 8.1 固定范围

先生成当前固定OpenList版本下实际驱动清单和transport能力表，然后依次实施：

1. **Wopan（联通）**：当前SDK注入`base.HttpClient`，List部分有ctx，Init/Drop仍需专项处理；优先为session注入独立client，并检查SDK初始化/刷新/上传的context钩子。
2. **HTTP/Resty代表**：先按实际清单覆盖global Resty的Google Drive/OneDrive/AliyunDrive、私有Resty的189，再以123系列及其他高频驱动为批次；覆盖API请求、直链解析、重试、上传与token refresh。已有部分context回归不重复造轮子，但不省略无ctx的初始化/刷新链路。
3. **专用WebDAV**：目前`ReadDir/Link`等不传ctx，cron重建client；需库级context API及生命周期，不得只给shared transport换名字。
4. **S3/SDK代表**：独立session HTTP client、context-aware SDK调用，覆盖direct upload和presign分支；本地S3兼容fixture验证，不推断所有云厂商协议一致。
5. **其余SDK、非HTTP及全局client驱动**：包括Azure Blob等SDK，以及SFTP/FTP/SMB独立协议；HTTP工厂不覆盖这些，需单独dial/connection adapter、operation deadline和Close/join。逐项标注已接入/部分/不支持及理由。缺钩子时评估固定小fork或上游贡献，不盲目升级依赖。

驱动表须按Init/List/Link/Read/Put/Refresh/Drop分别记录，不使用单一绿色勾掩盖部分覆盖。不能用代表驱动通过宣布所有驱动完成。

### 8.2 Docker的外部后端边界

本仓库根代理和Docker中独立的OpenList服务是两个部署单元。移动内置driver修改不会自动改变外部`openalist`镜像；要让Docker后端具备相同driver能力，需独立构建/版本锁定/部署该后端，作为单独经批准的交付项。根代理只能验证它到上游的请求预算，不能宣称控制远端driver内部重试。

### 8.3 每批验收

- 用真实driver方法+协议兼容loopback/emulator，不只测注入工厂。
- headers/body blackhole、429/5xx/backoff、取消、Refresh重入、连接关闭、重复Init/Drop、源与CDN路由分别验证。
- 有可信body hash素材的读取字节比较；有写fixture时检验取消后不发布成功和副作用说明。
- 生命周期owned pending/连接池/worker回到测试定义基线；SDK不可取消短CPU段如实报告。
- 每批更新actual/src overlay和能力报告。

**退出条件**：本轮批准清单全部达到操作级契约；若目标是“全部驱动”，必须逐项完成或经用户接受排除项，不能把unsupported当做已支持。

## 9. P4：异步UI文件操作，不丢失路径原子预约

- 替换下载目录列举/清理的listSync，使用可取消异步遍历、分批结果和明确UI加载状态；大目录不一次把全部结果塞进widget。
- `download_manager_page.dart`的build循环和信息dialog不再statSync；预先异步读取不可变文件DTO，build只渲染，文件消失/权限变化按单条处理。此次明确覆盖已确认五处同步磁盘调用，不重复重做已经正确异步的positional writer。
- 把“选唯一名字 + 保留路径 + 创建文件”交给单一reservation owner/串行命令队列。等待异步exists期间其他下载不能同时claim同一名字。
- 如要求跨进程不覆盖，必须用真正OS级exclusive create/平台API或独立下载协调服务；Dart普通File.create不得假称O_EXCL。外部写入不在保护域时明确限制。
- 同一owner统一处理下载、通知、回调、清理、删除与取消；活动/预约文件清理策略明确跳过或先cancel并join，不能删正在写的文件。
- 处理UI dispose、队列取消、权限拒绝、路径变化、剩余空间和重复点击；恢复只在实际worker结束后开始。
- 对大体积JSON扫描/排序若CPU阻塞，再用有界isolate；不为每个stat创建isolate，不把“Future声明”当离开UI执行证明。

**验收**：注入可gate文件系统，exists/list停住时UI事件仍可推进；同时通知/页面同名下载得到不同预约，取消无残留，清理不误删活动任务；四路交错下载维持完整10MiB+7字节比较。对实际可达路径设置禁止sync I/O回归检查，例外单独登记。

## 10. P5：新鲜度分层，避免缓存证明越界

### 10.1 证据级别

统一描述以下不同证据，不必一次重构全部实现：

| 证据 | 可用于什么 | 不可用于什么 |
| --- | --- | --- |
| 目录/导入hint | UI候选、预热建议 | 直接提升为可信nonce/认证参数 |
| 已验证展示别名 | 原始路径反查、受scope约束的类型提示 | 无限期保证当前对象未换、授权通过 |
| 不可变object version/强ETag | 经对应namespace验证的对象版本复用 | 不同CDN namespace的ETag直接比较 |
| Last-Modified | 低成本变更提示 | 当作强版本证明或密码学真实性 |
| 有效期内完整geometry | 配置策略允许下的重复读取优化 | 无条件严格最新、永久零探测 |
| V3认证record | 对应index/nonce/key的record内容认证 | 现有header/trailer全局真实性 |

### 10.2 两种明确策略（建议设计，非现有配置名）

- **bounded-cache，兼容默认**：保留有界TTL和真实响应piggyback验证，响应冲突即失效；显示无validator的stable-object assumption及有效期。
- **strict-freshness，显式启用**：优先immutable版本，其次同namespace可靠强validator/条件请求；没有可靠版本则播放前重新读取必要格式前缀/尾部与当前几何，不允许只凭TTL提交旧解密参数。即使重读也不能在无远端稳定版本时承诺整个传输跨请求原子快照；不可建立所要求保证则明确失败/降级提示。

配置名/存储schema在实施PR决定，root/mobile策略含义必须一致。授权验证与内容新鲜度独立，缓存命中不跳过当前上游授权。

### 10.3 改动

- 根别名恢复先做display→raw定位，不直接将旧alias记录作为当前nonce/长度证明；实际响应Content-Type和长度建立在当前允许的证据上。
- 为PUT/DELETE/MOVE/COPY、规则/origin/auth变化、validator冲突增加统一失效事件和generation fence，阻止迟到flight重新写回已失效记录。
- 新鲜度策略对HEAD、本地零长度响应、尾部seek和恢复后记录一致，不只照顾GET。
- signed URL rotation只改变transport，不自动成为内容变化；不能比较不同URL namespace的验证器，不以忽略query就认定object immutable。
- 可比较强validator检查尽量搭载实际stream；配置reload不继承旧规则确认；manual refresh保留。

**验收**：同path同size换nonce、换格式/内容、换validator及namespace、304/412条件结果、无validator、Vary/压缩表示、授权撤销、重启TTL、失效中flight；分别断言每种模式正确性与实际probe次数，不把TTL假设标成严格证明。

## 11. P6：V3视频别名识别，预算先于功能

### 11.1 实现路线

- 复用共享V3解析、context-aware KDF、record admission和已认证record cache；不另做一个无限制PBKDF2/下载器。
- 读取并校验必要48字节头、streaming格式必要16字节尾及完整record0。认证成功后才把最多4096字节明文交给已有严格容器分类器。
- 一个V3 record有`chunkSize+16`字节；16MiB旧chunk识别绝不是4KiB网络探测。小文件最后record仍为固定填充宽度。
- 别名持久化当前V3几何校验只覆盖fixed布局，不接受streaming额外16字节尾；增加明确layout证据/校验并迁移schema，不能仅去掉V3拒绝开关。chunk/KDF/nonce先严格校验，恶意参数不通过默认值修补。
- 前缀不足无法确认的格式保持未知；不自动读取更多record或整个文件去猜。
- 推测KDF用speculative准入，前台可提升共享flight；取消不能提前释放仍运行PBKDF2的CPU slot。
- 尽量绑定元数据与record的同对象版本/实际响应头，检测探测之间更换header、nonce、几何和validator。

### 11.2 建议默认预算

- 先仅对当前明确启用的联通范围；新V3目录识别默认不主动扫描大chunk。
- 目录后台识别：建议仅允许最多一个1MiB record，单worker、最多2个pending、总等待/字节预算明确；预算不够保持`.bin`，原因可观察。
- 显式用户确认：可另配置最多一个32MiB record及适合网络的deadline；仍受全局record/KDF预算，默认需显式允许。
- 32MiB以上core能解析的遗留chunk，识别入口直接预算拒绝，不分配到core极限。播放能力与识别预算分别描述。
- 若默认旧16MiB文件也需在目录自动恢复，应先明确接受该流量成本，再调预算；不能既承诺低流量又保证所有大chunk首次列表立即恢复。

### 11.3 格式真实性边界

当前V3 `Seal/Open` 使用空AAD，streaming trailer记录长度；现有头/尾不是被完整AEAD绑定的metadata。此功能只能声称“首record认证成功 + 格式几何核验 + 视频签名”，不能声称整文件或header/PlainSize密码学认证。

若以后要认证整个container metadata，另立新格式版本设计、跨端兼容和迁移计划，不改变已有V3字节语义，本阶段不自动重加密。

**验收**：已知长度/streaming V3，1/16/32MiB，短文件/空文件、损坏tag、错密码、header/tail不一致、同record-count内PlainSize变化边界、206/忽略Range/截断/压缩/重定向、预算拒绝、取消和热命中。记录实际读取字节、派生次数、内存lease，不仅看扩展名。

## 12. P7：可信播放适配与低成本预热

### 12.1 服务端契约

- 保留根端兴趣API的鉴权/session/generation及引用所有权。先复核当前保守同origin/DAO目标限制，再增加受授权控制的signed-CDN对象解析；不接受任意目标URL或客户端provider/scope。
- 移动内置代理需要明确同等能力的adapter/endpoint，或独立原生调用契约；不能假定根端接口已经存在于移动进程。
- 增加明确withdraw/clear兴趣契约，鉴权与单调generation保持一致；当前根API只有提交有效目标/TTL收敛，不能假称chooser取消已有撤销接口。退出只释放该session后台引用，不取消共享者的media。
- 以能力/version握手兼容旧服务：不支持兴趣时普通播放仍可进行，不能为上报失败阻断播放。

### 12.2 App/WebView适配

- 在我们控制的“打开该文件/启动播放器”入口，取得服务端确认的canonical逻辑对象及可信session，再提交generation；解析不出对象的URL保持非适配模式。
- WebView桥仅允许受信本地页面/已确认origin，并校验页面事件和对象；不让任意导航/JS提交管理身份或任意探测目标。
- 明确一个launch intent只证明“用户请求打开此文件”，不是外部播放器实际开始/切集/退出证据。App回前台也不等于播放器停止；不凭这个取消还在用的流。
- 新launch撤销同session旧后台兴趣，不取消其他session和实际HTTP media context。退出/失联用TTL和明确事件，不能捏造completion。
- 如要真正的每次切集/帧事件，后续需要受控内置播放器或第三方明确callback/插件；任意MX自动接入不属于本轮完成承诺。

### 12.3 预热条件和可观察性

- 邻集启发式仍是advisory，不当作MX播放列表。默认关闭，显式兴趣优先。
- 接入计费网络、省电、电量/充电、网络offline等能力时，未知状态按保守禁用；通过Pigeon源生成桥，不手改generated文件。
- 只预热必要metadata，保留前台槽位、字节/任务上限、成功/失败冷却；显示跳过原因及成功消费hit，而非仅“已预热”计数。
- 计费/电量影响仍标未真机测；本阶段证明策略输入和任务行为，不宣称真实省电。

**验收**：服务契约跨root/mobile，Flutter fake bridge/mock server，旧版本fallback、导航origin变化、dispose、rapid generations、共享session、signedURL更新、错误鉴权、metered/power未知/变化、队列取消和Stop；真实后台任务被取消/join，不把拒绝warm等同播放失败。

## 13. P8：完整原名审计、协调写与安全mutation

### 13.1 先补单写者管理（必选）

- 完整原名审计建立只读查询/导出、版本和敏感权限；不公开token、不通过默认统计暴露原名。
- 新状态机保留旧pending/failed/complete兼容，增加必要unknown/reconciliation/tombstone而不抹掉历史。没有证据的失败不自动释放。
- 恢复后及异常退出后有dry-run reconciliation：按当前caller权限检查远端和本地记录，结果可能为unknown；不能因一次404或最终一致列表看不到便删除占位。
- 管理动作有op ID、审计和确认，先备份，禁止“重试”等同重用可能已部分写入的nonce/对象。
- 普通重复PUT仍409；幂等重试必须使用独立显式op token且验证请求/对象内容身份，不根据同名和同大小自动允许覆盖。

### 13.2 部署与保证分层

| 模式 | 可承诺的保护 | 条件/限制 |
| --- | --- | --- |
| 单写者默认 | 同一权威占位库内不重复申请目标，实际结果验证 | 其他实例/外部writer不在保证域 |
| 受控协调写 | 所有已接入代理经同一协调store序列化 | SQL唯一约束/CAS、owner/op ID、持久状态；不能把lease当远端fencing |
| 远端原子不覆盖 | 竞争写入也由provider条件创建/提交拒绝 | 必须验证该driver/API实际支持，不仅宣称DAV标准 |
| 无条件写的HA | 默认不支持严格HA同目标重用 | 不能撤销旧远端请求时，不给新owner重用同一个物理目标 |

- MySQL可以作为可选协调store，但仅锁到写完成前的 cooperating proxies。旧owner请求在lease失效后仍可能完成，数据库fence无法使远端撤销。
- 有远端条件写/commit时才能可靠交接；否则保留单active writer、未知目标隔离，或设计唯一不可复用physical object并核实provider语义。不能用“拿到新lease”作为安全重试许可。
- owner崩溃、网络隔离和发布结果丢失都转unknown/reconcile；成功响应前完成远端和本地提交证明。
- 默认部署继续单实例；HA启用需能力检查及用户明确接受保证域。

### 13.3 逐操作实施

1. **单文件rename/move，同规则且不覆盖**：源通过已绑定raw路径定位，目标限长/占位，远端执行验证，事务迁移完整原名索引/别名/失效事件；跨本地DB与远端不是原子事务，采用持久intent+reconcile，不能提前删除源记录。
2. **copy**：目标独立审计，占位及内容/元数据验证；源保留。server-side copy到同名的远端是否原子必须按能力决定。
3. **跨规则或跨后端**：不是改文件名即可；可能需要读解密再写加密。当前先拒绝，另设迁移job/校验/取消/空间成本设计再启用。
4. **目录和批量操作**：需完整子树审计、边界清单及部分成功恢复，没实现前继续拒绝，不能用盲目的前缀替换。
5. **断点续传（可选独立扩展）**：默认仍拒绝；需要上传session/op token、总大小、范围状态、checkpoint、明密坐标、nonce/key的记录不可变性和重试去重。不得重封同nonce/index不同明文的V3 record；临时对象→最终对象提交依赖远端能力。单独设计评审后才进入实现。

**验收**：双进程同目标、同摘要候选、DB中断、owner崩溃、lease失效旧请求迟到、远端成功本地提交失败、列表可见性延迟、外部writer插入、rename/copy部分失败、规则变化、恢复后的重复目标。fixture证明策略行为；真实provider测试仅授权随机目录，不改已有用户对象。缺少remote CAS时报告明确边界，不把fixture能力当联通已支持。

## 14. P9：综合自动验收和交付

### 14.1 门禁矩阵

- **协议与字节**：V1/V2/V3，root/mobile，完整GET/HEAD/PROPFIND和开口/闭口/后缀Range；cold/warm/restart、direct/redirect、honor/ignore Range。
- **故障与取消**：headers/body stall、截断、429/401/403/404/5xx、失效signedURL、授权撤销、caller取消、Stop、配置更新。
- **数据**：分页同步不漏/不重、tombstone、WAL/Bolt一致快照、恢复、原名及占位主/反向索引。
- **竞争**：不同caller/storage/server、快速generation、多写者、迟到flight、权限或规则变更。
- **资源**：分别计queued/running/joined任务、pool、record lease、CPU KDF、SQLite connection、FD/goroutine。释放后不能有owned任务残留；资源测量基于固定测试环境，不用共享runner绝对RSS/p95硬阈值。
- **成本**：probe次数、实际上游读取字节、KDF次数、cache命中、备份耗时/锁等待。小范围读取仍按V3整record认证物理成本评估。

### 14.2 验收报告

每阶段保存：PR/head/main、Actions链接、产物版本/hash、测试fixture/环境、成功/失败/取消/unsupported分组、错误字节数、成本及残留项。

通过要求：错误明文字节为0；不发布未经验证的成功；没有无界等待/重试；关键数据restore验证通过；owned资源实际收敛；批准范围的驱动操作覆盖有证据。

性能比较在同条件下做；CI基准用于观察allocation和请求/字节放大，不能据此宣称生产首帧更快或给“100分”。

### 14.3 交付流程

1. 每个阶段/批次独立`agent/*`分支，先廉价格式、diff和focused gates。
2. 本地重依赖构建一次短预算未完成即cloud-first，不加长timeout反复跑。
3. 推分支并开Draft PR；使用当前`.github/workflows/release.yml`完整矩阵，不用workflow_dispatch做日常验证。
4. 只追相关失败日志，更新同一PR；精确候选head全部required checks通过再合并。
5. 核对main完整发布、Docker及适用的三ABI AAR/APK，清理临时分支。
6. 对生产的部署/配置/真实网盘测试单独确认范围；先一致备份，固定镜像tag/digest/commit，验证原挂载。
7. rollback先考虑schema兼容和关键审计；新库只读/恢复策略事先测试，不能只拉旧镜像便声称可回退。
8. 服务端实测需要授权与账号，缺失时该项标`server_unverified`，不自动声称完成，也不反复试生产凭据。

## 15. 执行顺序与审阅点

### 默认建议

- **第一批**：P0操作守卫/导出/文档 → P1一致备份及restore。先防数据与状态误判。
- **第二批**：P2会话所有权 → P3优先Wopan、HTTP代表、WebDAV、S3，逐批验证；并行P4/P5。
- **第三批**：P6有预算V3别名 → P7可信launch适配和预热策略。
- **第四批**：P8单写者审计管理为必选；协调store及安全单文件mutation按批准能力推进，HA/续传另立验收。
- **收口**：P9合并证据，分别写“已实现”“自动已验收”“服务端已验收”“真机未纳入”。

### 开始实施前需要确认

1. 接受P0在联通受保护范围内暂时拒绝未完成安全迁移的rename/move/copy，以及跨范围/目录操作；正常PUT/读取继续保留。
2. 多实例是本轮必须交付，还是先以单写者管理为默认；建议先单写者，不对无remote CAS的上游承诺严格HA。
3. 客户端适配优先现有App的可信launch入口；是否另需要内置播放器应单独决定，不悄悄扩大产品范围。
4. 新鲜度建议兼容模式默认、严格模式opt-in；V3目录探测建议先保守字节预算，旧16MiB大chunk自动扫描需明确流量许可。
5. 断点续传、跨规则迁移、批量目录安全mutation、新容器版本认证属于可选后续专项，不能未经评审塞进一个大PR。
6. 如希望Docker外部OpenList也获得驱动迁移，需要批准该独立后端产物及部署范围；更新加密代理镜像本身不够。

## 16. 最终签收边界

本计划批准的必选阶段和驱动清单逐项满足代码/自动验收/main发布门槛，才称“本轮非真机工程目标完成”。可选项未批准或上游能力不足须列明确范围，不用unsupported凑完成率。

即便全部非真机门禁通过，最终报告仍保留：真实手机/MX/VPN/OEM/耗电未验证；无可靠远端版本的严格快照、无provider CAS的外部并发防覆盖、未知历史原标题恢复不具无条件保证。

## 17. 核对依据

- `AGENTS.md`、`mobile/AGENTS.md`
- `docs/PLAYBACK_FINAL_ACCEPTANCE.md`、`docs/PLAYBACK_ACCEPTANCE_ROADMAP.md`
- `docs/NATIVE_ROUTING_ACCEPTANCE.md`、`docs/MX_WEBDAV_PLAYBACK_FIX.md`
- `docs/MOBILE_CONFIRMED_METADATA_REUSE.md`、`docs/PLAYBACK_INTEREST_API.md`
- `docs/UNICOM_DEPLOYMENT_VERIFICATION.md`、`docs/UNICOM_FILENAME_BOUNDARY_FINDINGS.md`
- `internal/server/middleware.go`、`internal/handler/api.go`、`internal/handler/alist.go`、`internal/handler/webdav.go`
- `internal/storage/store.go`、`internal/storage/filename_records.go`、`internal/proxy/media_identity.go`
- `mobile/openlist-lib/internal/net/driver_client.go`、`mobile/openlist-lib/openlistlib/encrypt/newdriver_route_transport.go`
- `mobile/openlist-lib/openlistlib/encrypt/local_store.go`、`confirmed_metadata.go`
- `mobile/openlist-lib/drivers/base/client.go`、`drivers/wopan/driver.go`、`drivers/webdav/driver.go`
- `mobile/lib/utils/download_manager.dart`、`mobile/lib/pages/web/web.dart`、`mobile/lib/utils/intent_utils.dart`
- `shared/encryptcore/content_v3.go`、`v3_stream.go`、`v3_stream_plain.go`
- `mobile/openlist-lib/scripts/SOURCE_OVERLAY.md`、`.github/workflows/release.yml`
