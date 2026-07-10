<div align="center">
  <h1>Alist-Encrypt-Go</h1>
  <p>面向 Alist / OpenList 的透明加密代理，支持 HTTP、WebDAV 与可拖动的视频流式解密。</p>
  <p>
    <a href="https://github.com/qingwo1991-debug/alist-encrypt-go/releases"><img src="https://img.shields.io/github/v/release/qingwo1991-debug/alist-encrypt-go?style=flat-square" alt="Release"></a>
    <a href=".github/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/qingwo1991-debug/alist-encrypt-go/release.yml?style=flat-square" alt="Build"></a>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square&logo=go" alt="Go"></a>
  </p>
</div>

Alist-Encrypt-Go 部署在客户端与 Alist/OpenList 之间。它拦截文件列表、下载、上传和 WebDAV 请求，在传输过程中实时加解密内容与文件名，不要求网盘保存明文副本，也不负责转码。

```text
浏览器 / 播放器 / rclone / WebDAV 客户端
                    │
          alist-encrypt-go :5344
                    │
             Alist/OpenList :5244
                    │
                 网盘 / CDN
```

## 主要能力

| 范围 | 当前实现 |
|---|---|
| HTTP | 拦截 `/api/fs/*`、`/d/*`、`/p/*`，转换路径、文件名、大小和下载地址 |
| WebDAV | `/dav/*` 的 GET、HEAD、PUT、PROPFIND、DELETE、MOVE、COPY 等方法 |
| 加密格式 | V2 新格式，以及对既有 V1 文件的兼容读取 |
| 算法 | AES-128-CTR、ChaCha20、RC4-MD5；文件名使用 MixBase64 + CRC6 |
| 视频播放 | 单 Range 映射、Range 能力学习、Chunked/Full 回退、过期直链刷新、客户端取消识别 |
| 性能 | 连接复用、流缓冲、V2 派生密钥缓存、解密块缓存、并发保护 |
| 后台预热 | 预取大小、签名 URL、Range 能力与 V2 头元数据；支持冷却和存储源限流 |
| 持久化 | BoltDB 必需；MySQL 可选，用于共享部分元数据与学习状态 |
| 管理与工具 | Vue 管理后台、独立 `encrypt-tool`、Android/OpenList 集成构建 |

## 快速部署

### 连接已有 Alist/OpenList

```yaml
services:
  alist-encrypt:
    image: ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
    container_name: alist-encrypt-go
    restart: unless-stopped
    ports:
      - "5344:5344"
    volumes:
      - ./conf:/app/conf
      - ./data:/app/data
    environment:
      TZ: Asia/Shanghai
      ALIST_HOST: openlist
      ALIST_PORT: "5244"
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:5344/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    networks:
      - media

networks:
  media:
    external: true
```

把 `openlist` 改成上游容器名或可达主机名，并确保两个服务位于同一 Docker 网络。也可以直接运行：

```bash
docker run -d \
  --name alist-encrypt-go \
  --restart unless-stopped \
  -p 5344:5344 \
  -e ALIST_HOST=192.168.1.15 \
  -e ALIST_PORT=5244 \
  -e TZ=Asia/Shanghai \
  -v "$PWD/conf:/app/conf" \
  -v "$PWD/data:/app/data" \
  ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
```

必须持久化 `conf` 和 `data`。前者包含加密密码、扫描凭据和 JWT secret，后者包含管理员与运行状态；两者都应限制读取权限并纳入备份。

启动后：

- 管理后台：`http://<主机>:5344/index`，会跳转到 `/public/index.html`
- 代理后的 Alist/OpenList：`http://<主机>:5344/`
- WebDAV：`http://<主机>:5344/dav`
- 健康检查：`http://<主机>:5344/health`

初始用户名为 `admin`，随机密码只在首次创建用户时写入启动日志。首次登录后应立即修改管理员密码，并修改或删除默认 `/encrypt/*` 示例规则中的 `123456`。

### 启用 MySQL

MySQL 是可选元数据后端，不替代 BoltDB。显式配置 MySQL 后，连接或建表失败会直接阻止服务启动，避免静默回退造成两套状态分裂。因此必须等待数据库健康后再启动代理：

```yaml
services:
  mysql:
    image: mysql:8.4
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: alist_encrypt
      MYSQL_USER: alist_encrypt
      MYSQL_PASSWORD: ${MYSQL_PASSWORD:?set MYSQL_PASSWORD}
      MYSQL_ROOT_PASSWORD: ${MYSQL_ROOT_PASSWORD:?set MYSQL_ROOT_PASSWORD}
    volumes:
      - ./mysql-data:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -u alist_encrypt -p\"$${MYSQL_PASSWORD}\" --silent"]
      interval: 10s
      timeout: 5s
      retries: 20
      start_period: 30s

  alist-encrypt:
    image: ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
    restart: unless-stopped
    depends_on:
      mysql:
        condition: service_healthy
    environment:
      DB_TYPE: mysql
      DB_DSN: "alist_encrypt:${MYSQL_PASSWORD}@tcp(mysql:3306)/alist_encrypt?charset=utf8mb4&parseTime=True&loc=Local"
```

把密码放入未提交的 `.env` 或 secret 管理系统。即使启用 MySQL，也不能删除 `data/alist-encrypt.db`。

## 加密格式与安全边界

新上传和 `encrypt-tool` 默认生成 V2。V2 有 32 字节头，包含格式标识、随机 nonce 和明文大小；密文 Range 会自动补偿头长度。V1 没有文件头，仅用于兼容旧文件。

| 格式 | KDF / nonce | 用途 |
|---|---|---|
| V2 | PBKDF2-SHA256 600,000 次，每文件随机 nonce | 新数据推荐 |
| V1 | PBKDF2 1,000 次，nonce/IV 与大小相关 | 只读兼容；同密码同大小文件可能重用密钥流 |

算法建议：有 AES 硬件加速时优先 AES-128-CTR V2；无 AES 加速的平台可选 ChaCha20 V2。RC4-MD5 仅建议用于兼容既有数据。ChaCha20 的随机访问上限约为 256 GiB。

V1/V2 都是未认证流加密，不提供 AEAD/MAC，不能检测恶意篡改。文件名 CRC6 和播放 sniff 也不是密码学完整性校验。对高安全性归档，应在外层增加签名或认证加密。

`/redirect/:key` 是临时 bearer capability：拿到地址的人可以读取对应解密内容。不要把代理、日志或分享链接暴露给不可信用户。

## HTTP 与 WebDAV

HTTP 侧会处理以下关键链路：

- `/api/fs/list`：解密文件名、建立明文到密文的映射、记录列表大小并触发后台探测。
- `/api/fs/get`、`/api/fs/link`：转换路径，修正 V2 明文大小，并把上游直链替换为本地解密入口。
- `/api/fs/put`：流式加密上传。
- remove、rename、move、copy：转换密文名称并失效关联缓存。
- `/d/*`、`/p/*`、`/redirect/:key`：执行实际流式解密。

WebDAV 客户端连接 `/dav`，鉴权继续使用上游 Alist/OpenList 的 WebDAV 账号。当前管理页中的多 WebDAV 上游列表属于兼容保留配置，运行时 `/dav` 固定使用主 `alistServer`，不要把它当作多实例路由。

当前仅支持单个 HTTP Range；多段 Range 返回 416。WebDAV PUT 必须能确定完整明文大小，否则会返回 400。

## 视频播放与拖动

播放策略按文件和存储源学习：

```text
原生 Range
    └─ 上游不兼容或连续失败 → Chunked（全量响应并丢弃前缀）
                                  └─ 深度 seek 超过阈值 → Full 回退
```

- 无 Range GET、`bytes=0-` 和靠近开头的小偏移会按首播请求处理。
- 上游 401/403/404 不会再被计为播放成功；签名 URL 失效时会强制刷新后重试。
- 播放器 seek 导致的客户端取消属于正常结束，不会再尝试向已输出的响应追加 502。
- 默认连续 2 次 Range 失败后降级，连续 3 次成功后恢复，30 分钟后允许重探。
- Chunked 默认最多丢弃 8 MiB，深度跳转仍取决于上游真正的 Range 能力。
- 默认最多 32 条并发解密流，过载返回 429。

因此，当前路径已经针对首帧、快进和快退做了优化，但“最佳”仍取决于网盘/CDN 的 Range 支持、签名 URL 获取速度、文件大小是否可靠以及播放器的请求形状。Full/Chunked 是兼容回退，不等于高效随机 seek。

解密块缓存只服务带 Range 的 GET，单次完整命中上限为 16 MiB，并要求范围内的块全部存在。开放区间 `bytes=N-`、签名 URL 改变或首次深度 seek 通常仍会 miss；不要把它理解为完整视频缓存。

## 后台预热：做了什么，没做什么

预热的实际目标是减少正式播放前的元数据往返。它会尝试：

- 解析并缓存文件大小；
- 获取并缓存签名 `raw_url`；
- 探测存储源的 Range 兼容性；
- 读取 V2 头，缓存 nonce、明文/密文大小；
- 将可用元数据写入 BoltDB 或 MySQL。

它不会下载视频正文、预取首尾媒体块、解析 MP4 `moov`，也不会提前执行 V2 的 600,000 次 PBKDF2。V2 key cache 在第一次真正解密时才产生。因此预热对“省掉 fs/get、头探测和 Range 试错”有积极作用，但不能替代 CDN 缓存，也不能保证首次解密零 CPU 延迟。

任务来源包括文件列表、PROPFIND、目录同步、可选启动探测和首播 warmup。调度器具有：

- 全局并发与单 provider 并发限制；
- 按文件冷却，而不是按整个域名冷却；
- queued/in-flight 去重，过期或失效任务只允许一个刷新；
- 视频扩展和最小大小过滤；未知大小仍可探测，首播任务绕过这两项过滤；
- 失败、上游 4xx 或显式失效后释放冷却，允许后续重试。

配置了扫描账号后，目录同步会启动扫描并约每 15 分钟运行一次；相同扫描不会重叠。后台快照默认 30 分钟有效。`consumer_hit` 只表示一次真实播放使用了仍处于 ready 的预热状态，是相关性指标，不等同于已经测量出首帧耗时下降。

在管理后台统计页观察这些字段：队列长度、成功/失败、`raw_url` 获取数、Range 探测数、warm 状态、失效原因和 consumer hit。若发现 discovered 很高但 queued/success 接近零，优先检查扫描凭据、视频过滤、最小大小、冷却和上游 401。

## 配置与环境变量

首次启动会生成 `conf/config.json`。管理后台保存配置后，文件会以 `0600` 原子写入。加密规则缓存、探测 worker、HTTP transport 和数据库连接并非全部热更新；修改规则、预热并发、代理分流或数据库后建议重启服务。

`ALIST_HOST`、`ALIST_PORT` 只参与首次/缺省配置；已有 `conf/config.json` 时，以文件中的主上游地址为准。其余下表变量在加载配置后覆盖对应字段：

| 变量 | 默认值 | 说明 |
|---|---:|---|
| `ALIST_HOST` | 容器 `alist`；本机 `localhost` | 首次默认上游主机 |
| `ALIST_PORT` | `5244` | 首次默认上游端口 |
| `DB_TYPE` / `DB_DSN` | 空 | 两者同时设置以启用 MySQL |
| `DB_DISABLE_CLEANUP` | `false` | 禁用 MySQL 后台清理 |
| `PROBE_ENABLE` | `true` | 后台探测开关 |
| `PROBE_CONCURRENCY` | `4` | 全局 worker 数 |
| `PROBE_PROVIDER_CONCURRENCY` | `1` | 单存储源并发 |
| `PROBE_MIN_DELAY_MS` / `PROBE_MAX_DELAY_MS` | `3000` / `15000` | 已成功 warm 后的重探随机延迟；首次任务立即执行 |
| `PROBE_COOLDOWN_MINUTES` | `1440` | 单文件冷却 |
| `PROBE_QUEUE_SIZE` | `1000` | 队列容量 |
| `PROBE_MIN_SIZE_BYTES` | `104857600` | 已知大小文件的最小探测阈值 |
| `SIZE_UNKNOWN_STRICT` | `true` | 大小未知时拒绝冒险输出 |
| `CHUNKED_SEEK_MAX_DISCARD_BYTES` | `8388608` | Chunked 最大前缀丢弃量 |
| `DECRYPTED_BLOCK_CACHE_ENABLE` | `true` | 解密块缓存开关 |
| `DECRYPTED_BLOCK_CACHE_MB` | `128` | 块缓存总量 |
| `DECRYPTED_BLOCK_SIZE_KB` | `256` | 块大小 |
| `RANGE_FAIL_TO_DOWNGRADE` | `2` | Range 降级阈值 |
| `RANGE_SUCCESS_TO_RECOVER` | `3` | Range 恢复阈值 |
| `RANGE_REPROBE_MINUTES` | `30` | 不兼容状态重探间隔 |
| `RANGE_PROBE_TIMEOUT_SECONDS` | `8` | Range 探测超时 |
| `V2_KEY_CACHE_TTL_MINUTES` | `1440` | V2 派生 key 滑动 TTL |
| `MAX_ACTIVE_STREAMS` | `32` | 最大并发解密流 |
| `STREAM_OVERLOAD_STATUS` | `429` | 过载 HTTP 状态，可设 503 |

`PLAY_FIRST_FALLBACK` 当前是保留字段，实际 Range → Chunked → Full 编排不由它控制。`HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` 只在代理模式设为 `env` 时生效。不要使用旧文档中的 `ALIST_ENCRYPT_*` 变量，它们没有接线。

## 数据持久化与备份

| 位置 | 内容 |
|---|---|
| `conf/config.json` | 主配置、加密密码、扫描凭据、JWT secret |
| `data/alist-encrypt.db` | BoltDB；管理员、规则相关状态、文件/大小缓存等，始终需要 |
| `data/range_compat.json` | 未启用 MySQL 时的 Range 学习状态 |
| MySQL | 文件元数据、Range、provider 策略、目录快照和扫描状态 |

启用 MySQL 后依然要同时备份 `conf`、`data` 和 MySQL。服务会安全拒绝删除仍在使用的 BoltDB。

## 常见问题

### 普通浏览器 401，无痕模式正常

这通常是浏览器保存了过期或来自旧 `jwt_secret` 的 token。新版前端会在 JWT 本地过期或 API 返回真实 401/403 时清理登录态并回到登录页。升级前可手工清除该站点的 Local Storage/Cookie，或使用开发者工具删除旧 token。

`navigator.getBattery is not a function` 若来自 `chrome-extension://.../contentscript.js`，是浏览器扩展注入脚本的问题，与本项目无关；禁用对应扩展即可验证。

### MySQL `connection refused`

显式 MySQL 模式现在会 fail fast。检查数据库健康、网络、DSN 和权限，并使用 Compose `condition: service_healthy`。不要依赖启动时静默回退 BoltDB。

### 首帧慢或 seek 慢

依次检查：上游直链获取耗时、`Range` 响应是否真为 206、文件大小是否正确、当前策略是否已降级、预热成功数、签名 URL 是否频繁变化、是否达到 32 流上限。`/enc-api/getStats` 需要管理 JWT，可从后台统计页查看。

### 健康接口显示正常但上游不可用

`/health` 是浅层存活检查；`/ready` 当前也固定返回 ready，不验证 Alist/OpenList 或 MySQL。生产监控应额外探测一个受控的上游目录或文件。

## CLI

```bash
go build -o encrypt-tool ./cmd/encrypt-tool

# V2 单文件加密；自动追加密文后缀
./encrypt-tool enc --password-file /run/secrets/media-key -i video.mp4

# 自动识别 V1/V2 并解密
./encrypt-tool dec --password-file /run/secrets/media-key -i video.mp4.bin

# 目录并发处理并加密文件名
./encrypt-tool enc -p 'change-me' -i ./videos -o ./encrypted -n -w 4
```

完整参数见 [docs/encrypt-tool.md](docs/encrypt-tool.md)。自动化场景优先使用 `--password-file`，避免密码进入 shell 历史和进程参数。

## 源码构建与验证

```bash
git clone https://github.com/qingwo1991-debug/alist-encrypt-go.git
cd alist-encrypt-go

cd enc-webui
npm ci
npm run build
cd ..

rm -rf web/public
mkdir -p web/public
cp -a enc-webui/dist/. web/public/
go build -o alist-encrypt-go ./cmd/server
```

常用验证：

```bash
go test ./...
go test -tags noembedwebui ./...
go vet ./...

cd enc-webui
npx vitest run
npm run build
```

`noembedwebui` 构建不包含管理后台，`/index` 会返回 404。

## GitHub Actions 与发布物

`.github/workflows/release.yml` 会运行 Go 测试，并由 GitHub Actions 构建：

- Docker：`linux/amd64`、`linux/arm64`；Dockerfile 使用 Node 20 构建最新前端。
- Server/CLI：Linux amd64/arm64/armv7、Windows amd64/arm64、macOS amd64/arm64。
- Android：arm64-v8a、armeabi-v7a、x86_64；细节见 [mobile/BUILD_GUIDE.md](mobile/BUILD_GUIDE.md)。

PR 只进行构建验证，不推送镜像。合并或直接推送到 `main` 后，Actions 才会推送 GHCR 的 `main`/`latest`；`v*` tag 还会生成版本镜像和 Release。独立 Server 二进制的 workflow 也会先重建前端再嵌入，避免发布旧管理页。

## 当前限制

- 不是媒体转码器，不解析或重排 MP4 `moov`。
- 仅支持单 Range；深度 seek 的体验最终受上游 Range 能力制约。
- 管理页的多 WebDAV 上游配置、在线加密和文件转存仍不是完整运行链路。
- 本地批量任务保存在内存，服务重启后任务记录会丢失。
- 部分配置需重启才能完全生效。

## 致谢

- [alist-encrypt](https://github.com/traceless/alist-encrypt)：原始 Node.js 项目
- [Alist](https://github.com/alist-org/alist) 与 [OpenList](https://github.com/OpenListTeam/OpenList)
