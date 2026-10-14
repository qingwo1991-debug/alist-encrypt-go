# 对外元数据同步导出 API（P0-B）

## 1. 用途与安全边界

`/enc-api/exportFileMeta` 是**同步 hint 导出，不是数据库备份**，也不证明对象当前内容、调用者上游授权或可信 storage 身份。默认 `consistency=live`，响应声明 `consistency=weak_live`、`incremental=best_effort`、`snapshot_supported=false`、`strict_incremental_supported=false`。

- MySQL 读取已持久化的 `is_active=1` 元数据，不含未 flush 的 write-behind buffer。
- MySQL 未启用时使用 Bolt `file_info` bucket：每次请求完整读事务读取、转换、过滤、排序、游标、offset、limit+1 后裁剪。不包含仅存在于内存的 path cache 或独立 `file_size` bucket。
- Bolt 的 `UpdatedAt` 只是上游 `Modified`，缺失时退到 `UpstreamFetchedAt`，两者均缺失使用 Unix epoch。**不是本地变更时间/revision**。MySQL 当前 `updated_at` 秒级，也没有可靠删除/tombstone feed。
- 每页单独读取 live 状态；两页之间写入可能产生跳过或重复，删除不会作为事件导出。游标不依赖 anchor 仍存在，但不冻结记录。重启保持同一后端和筛选范围时可继续，不承诺跨数据变动无遗漏。
- `since` 是 best-effort 下界，不能当作严格同步 checkpoint、snapshot upper watermark 或完整增量证明。晚写旧时间、同秒再次更新、删除均可能无法捕获。定期重新全量对账只能缓解，不能替代备份。
- `consistency` 除 `live`、`mode` 除 `live` 均拒绝；`snapshot`、`strict`、`include_deleted`、`include_sensitive` 除 `false`/`0` 均返回 HTTP 400。严格增量（含删除）和一致快照明确 unsupported。

默认（所有版本）清空 `RawURL`、`Sign`、`RawURLAuthScope`，不提供敏感导出模式。保留 KeyHash、ProviderHost、OriginalPath、EncryptedPath、Name、明/密文 size、content version、header/nonce/chunk/KDF geometry 等 hint 字段。路径、名称和 nonce 仍有敏感性，应限制管理 JWT 和导出文件访问；不得据 hint 跳过实际对象格式验证与上游授权。

`ProviderHost` 是缓存 `RawURL` 的实际 `url.Host`（含显式端口）；URL 无 host 时为空，与 MySQL writer 一致。不是 ProviderKey 的路径拼接，也不推断挂载、driver、可信 storage 或凭据身份。

## 2. 鉴权与响应

先 `POST /enc-api/login`，JSON `{"username":"admin","password":"..."}`，成功取得 `data.jwtToken`。这是服务端校验签名和有效期的 **JWT**，不是 UUID，更不是非空即通过。

受保护接口只接受 header：

```sh
curl 'https://HOST/enc-api/exportFileMeta?version=2&limit=1000' \
  -H 'Authorization: Bearer REPLACE_WITH_JWT'
```

也兼容 `Authorizetoken: <JWT>`、`Authorization: <JWT>`。**query token 不被接受**，不要放入 URL、日志或 referrer。管理 JWT 不是网盘凭据。缺失/无效 JWT 返回 HTTP 401、`{"code":401,"msg":"user unlogin"}`。成功 HTTP 200、`{"code":0,"data":...}`；导出参数错误 HTTP 400/code 400；后端读取/JSON 损坏 HTTP 500/code 500，不能吞为成功空数组。

## 3. 文件元数据参数

GET/POST 均使用 query 参数（不读取 POST body）。

| 参数 | 默认 | 契约 |
| --- | --- | --- |
| `version` | `1` | 仅 1 或 2；不静默改变旧 cursor 含义 |
| `limit` | `1000` | 正整数，最大裁到 5000；实际 fetch limit+1 |
| `offset` | `0` | 非负整数；过滤/排序后偏移；显式 offset（包括 0）与 cursor 同用 400 |
| `provider` | 空 | case-sensitive 精确 host 匹配；空表示不过滤 |
| `path` | 空 | case-sensitive literal 精确路径匹配 |
| `path_prefix` | 空 | case-sensitive literal 字节前缀；`%`、`_`、`=`、反斜线无 wildcard 语义；不是目录边界匹配 |
| `since` | 不设置 | 非负 Unix 秒，inclusive 下界 |
| `updated_after` | 不设置 | RFC3339/RFC3339Nano inclusive 下界，不能与 since 同用 |
| `cursor` | 空 | 按所选版本解释；重复 recognized 参数、格式不正确返回 400 |
| `consistency` / `mode` | `live` | 只支持弱一致 live |

`has_more` 来自同次读取真实下一条（limit+1），只说明当前页读取时还有数据。空 items 始终为数组。

### 3.1 version=1（legacy）

统一以 **UTC 整秒 UpdatedAt + KeyHash** 升序，返回时间同样整秒；避免 Bolt fraction 排序与移动 consumer `next_since` 秒精度不一致。`updated_after` 也归整秒。

第一页无 cursor；下一页传上一页 `next_since` 与 **原样 raw KeyHash** `next_cursor`。since inclusive，tuple cursor exclusive。同秒多键按 hash 顺序推进，不要求上一页 anchor 仍在。raw cursor 必须为 32 位 lowercase hex 且有 since/updated_after；单独 cursor 不再被静默忽略，返回 400。旧版移动 consumer 使用 since+rawhash，丢弃 RawURL/Sign，与默认脱敏兼容。

```text
/enc-api/exportFileMeta?limit=2
/enc-api/exportFileMeta?limit=2&since=<next_since>&cursor=<next_cursor>
```

全量 offset 仍可用，但 live 写入时易漂移。此 legacy 适配不是严格变更 feed。

### 3.2 version=2（explicit opaque cursor）

排序以 backend 原始 timestamp 精度 + KeyHash 升序（现有 MySQL schema 仍秒级）。响应 `next_cursor` 是 base64url 的版本化 opaque tuple，绑定 timestamp、key、backend、筛选范围（provider/path/prefix/初始时间下界）。严格验证版本、canonical 编码、UTC timestamp、key 和 scope。不签名、不加密，也不是权限 token；客户应当视为不可解释的 continuation token，不自行改写。

下一页 **保留第一请求的筛选和初始 since/updated_after**，仅新增/替换 cursor。不要将 `next_since` 替换为新的下界（会造成 scope mismatch）。可改变 limit，不能改变后端/筛选；需要新的筛选时从无 cursor 重新开始。

```text
/enc-api/exportFileMeta?version=2&limit=2&path_prefix=/movies/
/enc-api/exportFileMeta?version=2&limit=2&path_prefix=/movies/&cursor=<next_cursor>
```

opaque cursor 在删除 anchor 后仍使用 tuple 继续，而不是搜索 anchor。无变动数据集可跨多页无重漏；live 变动仍受上述弱一致边界限制。

### 3.3 响应字段

`items` 为 FileMetaRecord（保留历史 PascalCase 字段）。`version`、`backend`（`mysql`/`boltdb`）、`consistency`、`incremental`、`snapshot_supported`、`strict_incremental_supported` 明确能力；保留 `limit`、`offset`、`has_more`、`next_since`、`next_since_rfc3339`、`next_cursor`。非空页的 continuation 来源是**裁剪后最后一条**，不能来自 lookahead。

## 4. Strategy / RangeCompat

`/enc-api/exportStrategy`、`/enc-api/exportRangeCompat` 保留历史形状。Bolt fallback **未实现**，返回兼容空 items，但显式 `supported=false`、`status=unsupported`、`backend=boltdb`；消费者不得解释为完整空库或清除本地状态。MySQL 这两个历史接口尚未迁移到 file-meta v2 契约，其 anchor-based cursor、精度和 has_more 限制不在本次修复保证范围。

## 5. 验收和剩余工作

新增 Bolt fixture/真实 handler 契约测试覆盖超过两页、literal/case/path/provider 过滤、limit+1 裁剪、同秒 legacy 排序、offset、删除 cursor anchor、invalid/scope/backend cursor、geometry 和敏感字段、Bolt JSON/读错误。MySQL 真实集成 fixture（`MYSQL_TEST_DSN`）覆盖数据库实际 SQL，不以 mock 替代。测试源码存在不等于本机已通过：本阶段按要求仅 gofmt 和 git diff --check，完整编译/运行交父 Draft PR/cloud CI；真实 DB 集成须设置 DSN，缺失会 skip。

待后续实现：跨页一致快照、可靠 revision/删除 feed、关键原名审计及全部 bucket 的备份/恢复（P1/P8）、移动 consumer v2 capability 适配、strategy/range 稳定分页。禁止将此同步导出文件称为整库备份；部署或恢复前使用数据库原生一致快照/合规备份工具。
