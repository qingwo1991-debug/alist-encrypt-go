# 受保护文件名操作能力：P0补齐版

本说明针对显式正数 `alistServer.filenameWriteLimits` 配置，不等于全网盘统一命名策略。实施基线 `33d4032`，PR #78；最终发布证据以执行台账为准，本文存在不代表已部署。

## 入口与能力

| 入口 | 保护范围行为 | 未配置/明确无关行为 | 原名审计迁移 |
|---|---|---|---|
| API PUT / DAV PUT | 既有同步整文件占位与限长策略；重复/失败/已完成占位拒绝 | 既有行为 | 创建新记录，不覆盖历史 |
| API rename | 展示路径与最终物理路径相交则501 | 专用入口保持既有行为 | 未支持，不能假称安全 |
| API move/copy | 每个真实源/目标检查，batch整体早拒绝 | 专用入口不相交保持既有行为 | 未支持 |
| DAV MOVE/COPY | Destination同host且合法DAV路径，展示及最终物理路径二次检查，相交501 | 合法不相交保持既有行为 | 未支持 |
| DAV MKCOL/PROPPATCH/LOCK/UNLOCK及未知方法 | 请求路径子树相交501 | 不相交既有透传 | 未支持 |
| catch-all `/api/fs/*` 未确认操作或method | 保护启用时501，不解析未知body | **保护启用时即使声明无关目标也拒绝**；无配置保持既有行为 | 未支持 |
| 已确认catch-all只读route/method | get/list/search/dirs/archive meta/list的GET/HEAD/POST，link的POST | 透传 | 不涉及 |
| API remove / DAV DELETE | 保留既有删除语义 | 既有行为 | 占位不自动释放；完整删除/tombstone联动在P8完善 |
| GET/HEAD/PROPFIND | 保留实际授权和作用域隔离的读取 | 既有行为 | 不涉及 |

未知fs操作包括form、batch/regex rename、recursive move、mkdir、offline/direct-upload及driver自定义other。未知schema可能包含多个目标或异步副作用，不能从一个path字段猜测全部对象。拒绝这类操作是有意的保守限制，不把它计算为“已支持该操作”。

## 路径和状态

- API JSON是literal存储路径；DAV使用HTTP/net/url已解码的Path。文件名的合法 `%`、`+` 不重复解码。
- 校验绝对路径/UTF-8/控制字符/反斜杠并规范化点段。子树检查双向：移动保护目录的祖先也会拒绝。
- `orig_`和缓存映射不能绕过实际物理路径守卫；转换后的API basename拒绝空名、`.`、`..`和分隔符。
- 501 `protected_operation_unsupported` 是能力拒绝，不是401/403鉴权失败。
- 配置启用时路径不确定/畸形返回400 `invalid_mutation_path`。Destination不可带userinfo/query/fragment或外部host。
- 并发管理更新不等于冻结所有写入配置；P2/P5/P8还将扩大epoch和提交协调。当前支持的同步PUT保证仍限同一本地Bolt及受控单写者。

## 生命周期

媒体别名识别由WebDAV实例拥有：Stop关闭准入、取消真实I/O、等待worker退出，之后停止关联proxy。单request取消只撤等待，不误取消其他flight共享者。

配置成功管理更新增加非持久runtime revision；新任务核对新鲜规则，不以旧cache规则绑定新revision，发布在配置read guard下验证generation。Stop/config过期不生成格式失败证据。已检查未知格式冷却5分钟，临时失败15秒，明确401/403不写格式负缓存。

## 验证范围

新增direct handler、真实路由表、录制上游、`orig_`最终路径、headers/body/queued取消、配置ABA与预准入混代、停止后零发布及冷却分型测试。具体CI以PR/head记录为准；物理设备、任意外部writer竞争及所有未知API副作用不由这些fixtures证明。
