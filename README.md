<div align="center">
  <h1>Alist-Encrypt-Go</h1>
  <p>Alist 透明加密代理 — Go 重写，单二进制部署</p>
  <p>
    <a href="https://github.com/qingwo1991-debug/alist-encrypt-go/releases"><img src="https://img.shields.io/github/v/release/qingwo1991-debug/alist-encrypt-go?style=flat-square" alt="Release"></a>
    <a href=".github/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/qingwo1991-debug/alist-encrypt-go/release.yml?style=flat-square" alt="Build"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go" alt="Go"></a>
    <a href="https://flutter.dev/"><img src="https://img.shields.io/badge/Flutter-3.24-02569B?style=flat-square&logo=flutter" alt="Flutter"></a>
  </p>
</div>

---

Alist-Encrypt-Go 是一个位于客户端与 [Alist](https://github.com/alist-org/alist) 之间的**透明加密代理**，实时对文件内容和文件名进行加解密，同时完整保留视频拖拽、WebDAV、Range 请求等能力。

除独立后端外，本项目还基于 [OpenList](https://github.com/OpenListTeam/OpenList) 构建了**Android APK**，将加密代理直接集成到手机文件管理器 App 中。

## 快速开始

```bash
# 一键启动 Alist + 加密代理
docker compose up -d

# 访问管理界面
open http://your-ip:5344/index
```

创建 `docker-compose.yml`：

```yaml
services:
  alist-encrypt:
    image: ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
    container_name: alist-encrypt
    restart: unless-stopped
    ports:
      - "5344:5344"
    volumes:
      - ./conf:/app/conf
      - ./data:/app/data
    environment:
      - TZ=Asia/Shanghai
      - ALIST_HOST=alist
      - ALIST_PORT=5244
    depends_on:
      - alist

  alist:
    image: xhofe/alist:latest
    container_name: alist
    restart: unless-stopped
    ports:
      - "5244:5244"
    volumes:
      - ./alist-data:/opt/alist/data
    environment:
      - TZ=Asia/Shanghai
```

Docker Run：

```bash
docker run -d \
  --name alist-encrypt \
  -p 5344:5344 \
  -e ALIST_HOST=your-alist-host \
  -e ALIST_PORT=5244 \
  -v ./conf:/app/conf \
  -v ./data:/app/data \
  ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
```

> 务必挂载 `conf` 和 `data` 目录，否则重启后配置和用户数据将丢失。

## 功能特性

| 类别 | 特性 |
|------|------|
| **加密** | AES-128-CTR、ChaCha20、RC4-MD5 文件内容加密；MixBase64 + CRC6 文件名加密 |
| **流媒体** | 加密文件 Range Seek — 视频拖拽进度不受影响 |
| **WebDAV** | 完整 WebDAV 加密代理 |
| **性能** | 连接池复用、PBKDF2/MixBase64 缓存、512KB 流缓冲、后台探测调度 |
| **HTTP/2** | 原生 h2c 和 HTTPS 支持，管理界面热切换 |
| **代理分流** | 按域名分流（`direct` / `env` / `fixed` / `rules`），内置网盘域名字典 |
| **智能学习** | 自动探测各存储的 Range 兼容性并缓存，支持并发控制和冷却时间 |
| **数据库** | 默认 BoltDB 文件存储；可选 MySQL 持久化 Range 缓存与文件元数据 |
| **部署** | 单二进制、多架构 Docker（linux/amd64, linux/arm64）、Android APK |
| **管理界面** | Vue 3 管理面板：Alist 配置、WebDAV 设置、本地加解密、在线加密规则、文件迁移 |

## 加密算法

| 算法 | Intel（有 AES-NI） | ARM / 无 AES-NI |
|------|-------------------|-----------------|
| **AES-128-CTR**（v1 / v2） | ✅ 推荐 | ⚠️ 较慢 |
| **ChaCha20**（v1 / v2） | ✅ 良好 | ✅ 推荐 |
| **RC4-MD5**（v1 / v2） | ✅ 最快 | ✅ 最快 |

内容加密分为两代：**v1**（PBKDF2 + 文件大小参与密钥派生）和 **v2**（增强 KDF，引入额外熵源）。文件名加密使用 MixBase64 配合 CRC6 完整性校验。

## 构建模式

本项目通过 GitHub Actions 产出**两种构建产物**：

### 1. 独立后端（默认）

内嵌 Web 管理界面，单二进制或 Docker 镜像。适用于：

- NAS / VPS 的 Docker 部署
- 直接运行的 Windows exe / Linux 二进制
- 支持 linux/amd64、linux/arm64、darwin/amd64、darwin/arm64、windows/amd64

```bash
# 带内嵌管理页（默认）
go build -o alist-encrypt-go ./cmd/server

# 不带内嵌管理页（供外部管理端使用）
go build -tags noembedwebui -o alist-encrypt-go ./cmd/server
```

### 2. 移动端 Android APK

基于 [OpenList-Mobile](https://github.com/OpenListTeam/OpenList-Mobile) 的 Flutter Android 客户端，将加密代理编译为 Go 绑定（AAR）打包进 App。需要：

- Flutter 3.24+
- Go 1.24+
- Android SDK 35、NDK 25.2.9519653
- gomobile

```bash
# 1. 构建 Go Android 绑定 (AAR)
cd mobile/openlist-lib/scripts
./init_openlist.sh
./init_web.sh
./init_gomobile.sh
./gobind.sh

# 2. 构建 Flutter APK
cd mobile
flutter pub get
flutter build apk --release --split-per-abi

# 输出: OpenList-Encrypt-<version>_{arm64-v8a,armeabi-v7a,x86_64}.apk
```

详细构建说明请参考 [mobile/BUILD_GUIDE.md](mobile/BUILD_GUIDE.md)。

## 源码构建（独立后端）

```bash
git clone https://github.com/qingwo1991-debug/alist-encrypt-go.git
cd alist-encrypt-go

# 构建前端
cd enc-webui
pnpm install && pnpm build
cd ..

# 复制到嵌入目录
cp -r enc-webui/dist/* web/public/

# 构建 Go 二进制
go build -o alist-encrypt-go ./cmd/server
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ALIST_HOST` | Alist 服务器地址 | `localhost` |
| `ALIST_PORT` | Alist 服务器端口 | `5244` |
| `TZ` | 时区 | `UTC` |
| `DB_TYPE` | 数据库类型（仅 `mysql`；需与 `DB_DSN` 同时设置才启用） | 空，默认 BoltDB |
| `DB_DSN` | MySQL 连接串 | 空，默认 BoltDB |
| `DB_DISABLE_CLEANUP` | 禁用数据库定期清理 | `false` |
| `RANGE_FAIL_TO_DOWNGRADE` | Range 连续失败降级阈值 | `2` |
| `RANGE_SUCCESS_TO_RECOVER` | Range 连续成功恢复阈值 | `3` |
| `RANGE_REPROBE_MINUTES` | 不兼容后重探间隔（分钟） | `30` |
| `RANGE_PROBE_TIMEOUT_SECONDS` | 后台 Range 探测超时（秒） | `8` |
| `PROBE_ENABLE` | 启用后台 Range 兼容性探测 | `true` |
| `PROBE_CONCURRENCY` | 探测全局并发数 | `4` |
| `PROBE_PROVIDER_CONCURRENCY` | 每存储源并发数 | `1` |
| `PROBE_MIN_DELAY_MS` | 探测最小延迟（毫秒） | `3000` |
| `PROBE_MAX_DELAY_MS` | 探测最大延迟（毫秒） | `15000` |
| `PROBE_COOLDOWN_MINUTES` | 探测冷却时间（分钟） | `1440` |
| `PROBE_QUEUE_SIZE` | 探测队列容量 | `1000` |
| `PROBE_MIN_SIZE_BYTES` | 触发探测的最小文件大小（字节） | `104857600` |
| `PLAY_FIRST_FALLBACK` | Range 失败时回退全量播放 | `false` |
| `SIZE_UNKNOWN_STRICT` | 未知大小时严格处理 | `true` |
| `CHUNKED_SEEK_MAX_DISCARD_BYTES` | 分块 Seek 最大丢弃字节数 | `8388608` |

### 数据库

可选 MySQL 用于持久化缓存（Range 兼容性、策略状态、文件元数据）。`DB_TYPE` 和 `DB_DSN` 必须同时设置才启用，否则默认使用 BoltDB 文件存储（`data/alist-encrypt.db`）。重复访问相同文件时，项目会避免多次写入同一条记录以减轻数据库压力。

## 默认凭据

- 初始管理员用户：`admin`
- 密码：首次启动随机生成，打印在启动日志中
- **首次登录后请立即修改用户名和密码**

> 默认配置包含一条示例加密规则 `/encrypt/*`，密码为 `123456`。这是*文件加密密码*，不是管理员登录密码。生产环境请及时修改或删除。

## 管理界面

访问 `http://your-ip:5344/index`：

- **首页** — 系统概览
- **Alist 配置** — 服务器地址、加密密码、H2C 开关
- **WebDAV 配置** — 加密 WebDAV 代理设置
- **本地加解密** — 对本地文件夹加解密
- **在线配置** — 加密规则、代理模式、Range 学习设置
- **文件迁移** — 文件夹转换与文件迁移

> 仅独立后端构建提供内嵌管理页。Android APK 和 `noembedwebui` 构建的 `/index` 返回 404，配置由原生 App 提供。

## 致谢

- [alist-encrypt](https://github.com/traceless/alist-encrypt) — 原 Node.js 项目，感谢 [@traceless](https://github.com/traceless) 的开创性工作
- [Alist](https://github.com/alist-org/alist) — 多存储文件列表工具
- [OpenList](https://github.com/OpenListTeam/OpenList) — 支持移动端的 Alist 社区分支
- AI 辅助开发：Google、Anthropic（Claude）、Antigravity

## 许可证

[MIT](LICENSE)
