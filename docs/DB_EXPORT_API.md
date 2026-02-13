# 对外数据库元数据 API 对接说明

本文档用于第三方平台对接 `alist-encrypt-go` 的元数据导出能力，主接口是 `exportFileMeta`。

## 1. 接口总览

服务默认地址示例：`http://<host>:5344`

| 接口 | 方法 | 说明 | 是否鉴权 |
|---|---|---|---|
| `/enc-api/login` | `POST` | 登录，获取 token | 否 |
| `/enc-api/exportFileMeta` | `GET`/`POST` | 导出 MySQL 中的文件元数据（分页/增量） | 是 |
| `/enc-api/getStats` | `GET`/`POST` | 查看运行状态（可用于核对探测/缓存是否生效） | 是 |

说明：
- `/enc-api/*` 接口采用统一响应格式：`{ code, msg, data }`
- `code=0` 表示成功
- 鉴权头兼容以下任一方式：
  - `Authorizetoken: <token>`（推荐）
  - `Authorization: <token>`
  - 查询参数 `?token=<token>`

## 2. 鉴权流程

### 2.1 登录

`POST /enc-api/login`

请求示例：

```bash
curl -X POST "http://127.0.0.1:5344/enc-api/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your_password"
  }'
```

成功响应示例：

```json
{
  "code": 0,
  "data": {
    "userInfo": {
      "username": "admin",
      "headImgUrl": "/public/logo.svg"
    },
    "jwtToken": "7f6d8d55-b08d-4f36-a6f8-5a2cb8e5f4f1"
  }
}
```

失败响应示例：

```json
{
  "code": 500,
  "msg": "passwword error"
}
```

说明：
- 返回字段名是 `jwtToken`，但它是 UUID 风格 token（兼容历史前端命名）。
- 后续请求把该 token 放到 `Authorizetoken` 头即可。
- 当前版本服务端鉴权逻辑为“token 非空即通过”，联调时建议仍按登录流程传入 `jwtToken`，便于后续升级到严格校验时平滑兼容。

### 2.2 未登录错误

当未携带 token 调用受保护接口时，返回：

```json
{
  "code": 401,
  "msg": "user unlogin"
}
```

## 3. 导出元数据（核心接口）

### 3.1 接口定义

`GET /enc-api/exportFileMeta`

参数（query）：

| 参数 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `limit` | int | 1000 | 单页条数，最大 5000 |
| `offset` | int | 0 | 偏移量 |
| `provider` | string | 空 | 按 `provider_host` 精确过滤 |
| `path` | string | 空 | 按 `original_path` 精确过滤 |
| `path_prefix` | string | 空 | 按路径前缀过滤 |
| `since` | int64 | 空 | 增量时间下界（Unix 秒） |
| `updated_after` | RFC3339 | 空 | 增量时间下界（RFC3339），当 `since` 缺失时生效 |
| `cursor` | string | 空 | 游标（上一页最后一条 `KeyHash`） |

注意：
- `cursor` 仅在设置了 `since`/`updated_after` 时才参与分页条件。
- 返回仅包含逻辑有效数据（`is_active=1`）。

### 3.2 全量分页示例

请求：

```bash
curl "http://127.0.0.1:5344/enc-api/exportFileMeta?limit=2&offset=0" \
  -H "Authorizetoken: 7f6d8d55-b08d-4f36-a6f8-5a2cb8e5f4f1"
```

响应示例：

```json
{
  "code": 0,
  "data": {
    "items": [
      {
        "KeyHash": "e0f43d8d0b4f3a4a8f4b0de1b5d7c4a2",
        "ProviderHost": "openalist:5244",
        "OriginalPath": "/movies/demo1.mp4",
        "Size": 2147483648,
        "ETag": "\"abc123\"",
        "ContentType": "video/mp4",
        "UpdatedAt": "2026-02-13T10:12:31+08:00",
        "LastAccessed": "2026-02-13T10:12:31+08:00",
        "StatusCode": 206,
        "Active": true
      },
      {
        "KeyHash": "f3ab2c66d95f4d19b2f8c93791cbf9e8",
        "ProviderHost": "openalist:5244",
        "OriginalPath": "/movies/demo2.mkv",
        "Size": 5368709120,
        "ETag": "\"def456\"",
        "ContentType": "video/x-matroska",
        "UpdatedAt": "2026-02-13T10:13:05+08:00",
        "LastAccessed": "2026-02-13T10:13:05+08:00",
        "StatusCode": 200,
        "Active": true
      }
    ],
    "limit": 2,
    "offset": 0,
    "has_more": true,
    "next_since": 1770948785,
    "next_since_rfc3339": "2026-02-13T02:13:05Z",
    "next_cursor": "f3ab2c66d95f4d19b2f8c93791cbf9e8"
  }
}
```

### 3.3 增量拉取示例（推荐）

请求：

```bash
curl "http://127.0.0.1:5344/enc-api/exportFileMeta?since=1770948000&cursor=f3ab2c66d95f4d19b2f8c93791cbf9e8&limit=1000" \
  -H "Authorizetoken: 7f6d8d55-b08d-4f36-a6f8-5a2cb8e5f4f1"
```

说明：
- 使用 `since + cursor` 能稳定翻页，避免同秒多条数据时漏/重。
- 每页处理完后，保存响应中的 `next_since` 和 `next_cursor`，用于下一次请求。

### 3.4 MySQL 未启用时

如果当前实例未启用 MySQL，会返回：

```json
{
  "code": 500,
  "msg": "mysql not enabled"
}
```

## 4. 运行状态查询（可选）

`GET /enc-api/getStats`

请求示例：

```bash
curl "http://127.0.0.1:5344/enc-api/getStats" \
  -H "Authorizetoken: 7f6d8d55-b08d-4f36-a6f8-5a2cb8e5f4f1"
```

响应关键字段示例：

```json
{
  "code": 0,
  "data": {
    "version": "1.0.0",
    "uptime": "2h31m5s",
    "meta": {
      "cleanup_disabled": true
    },
    "stream": {
      "play_first_fallback": true,
      "final_passthrough_count": 12,
      "size_conflict_count": 1,
      "strategy_fallback_count": 8
    }
  }
}
```

## 5. 推荐对接策略

建议外部平台按以下策略实现同步：

1. 首次全量：`limit/offset` 分页拉取，入库。
2. 增量轮询：保存 `next_since + next_cursor`，按固定间隔拉取新增/更新。
3. 幂等写入：以 `KeyHash` 作为唯一键更新，避免重复。
4. 异常重试：遇到 `code!=0` 或网络失败，重试并保留上次成功游标。
5. 对时区敏感场景：优先使用 `next_since`（Unix 秒）作为增量基准。

## 6. 字段说明（items）

| 字段 | 类型 | 说明 |
|---|---|---|
| `KeyHash` | string | 记录唯一键（由 provider + path 计算） |
| `ProviderHost` | string | 提供方主机标识 |
| `OriginalPath` | string | 原始路径 |
| `Size` | int64 | 文件大小（字节） |
| `ETag` | string | 上游 ETag |
| `ContentType` | string | MIME 类型 |
| `StatusCode` | int | 采样时 HTTP 状态 |
| `UpdatedAt` | string(time) | 记录更新时间 |
| `LastAccessed` | string(time) | 最近访问时间 |
| `Active` | bool | 是否有效（导出接口默认仅返回 true） |
