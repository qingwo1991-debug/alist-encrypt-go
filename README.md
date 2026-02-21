# Alist-Encrypt-Go

基于 Go 语言重构的 Alist 透明加密代理，提供文件内容加密和文件名加密功能。

> **本项目是 [alist-encrypt](https://github.com/traceless/alist-encrypt) 的 Go 语言重构版本**

## 重构优化

相比原 Node.js 版本，Go 重构版本带来以下优化：

| 优化项 | 说明 |
|--------|------|
| **内存占用** | 从 Node.js 的 ~150MB 降低到 ~15MB |
| **启动速度** | 单二进制文件，毫秒级启动 |
| **并发性能** | Go 协程原生支持高并发，文件名解密并行处理 |
| **HTTP/2 支持** | 原生 h2c 和 HTTPS HTTP/2 支持 |
| **512KB 流缓冲** | 大缓冲池优化高码率视频流传输 |
| **连接池复用** | HTTP 客户端连接池，减少连接开销 |
| **PBKDF2/MixBase64 缓存** | 密钥派生和文件名加密结果缓存，提升解密性能 |
| **ChaCha20 加密** | 新增 ChaCha20 算法，无 AES-NI 的 CPU 性能提升 3-5 倍 |
| **用户名可修改** | 支持自定义管理员用户名（原版固定为 admin） |
| **单文件部署** | 无需 Node.js 运行时，单二进制即可运行 |

## 功能特性

- **透明加密**: AES-128-CTR、ChaCha20、RC4-MD5 文件内容加密
- **文件名加密**: MixBase64 + CRC6 校验的文件名加密
- **Range 请求**: 支持视频拖拽进度（加密文件也支持 Seek）
- **WebDAV 支持**: 加密的 WebDAV 访问
- **H2C 热切换**: 管理界面切换 HTTP/2 无需手动重启
- **Docker 就绪**: 多架构镜像（amd64/arm64），轻松容器化部署

## 快速开始

### Docker Compose（推荐）

创建 `docker-compose.yml`:

```yaml
version: '3.8'

services:
  alist-encrypt:
    image: ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
    container_name: alist-encrypt
    restart: unless-stopped
    ports:
      - "5344:5344"
    volumes:
      - ./conf:/app/conf    # 配置目录（重要：存储加密密码等配置）
      - ./data:/app/data    # 数据目录（存储用户凭据）
    environment:
      - TZ=Asia/Shanghai
      - ALIST_HOST=alist    # Alist 容器名或主机地址
      - ALIST_PORT=5244     # Alist 端口
    networks:
      - alist-network
    depends_on:
      - alist

  # Alist 服务
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
    networks:
      - alist-network

networks:
  alist-network:
    driver: bridge
```

启动服务：

```bash
docker compose up -d
```

访问管理界面: `http://your-ip:5344/index`

### Docker Run

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

> **重要**: 务必挂载 `conf` 和 `data` 目录，否则重启后配置和用户数据会丢失！

### 从源码构建

```bash
# 克隆仓库
git clone https://github.com/qingwo1991-debug/alist-encrypt-go.git
cd alist-encrypt-go

| `DB_TYPE` | 数据库类型（仅支持 mysql） | 空 |
| `DB_DSN` | 数据库连接串 | 空 |
# 构建前端
cd enc-webui
npm install
npm run build
cd ..

# 复制前端到嵌入目录
cp -r enc-webui/dist/* web/public/
  -e DB_TYPE=mysql \
  -e DB_DSN="<db_user>:<db_password>@tcp(<db_host>:3306)/<db_name>?charset=utf8mb4&parseTime=True&loc=Local" \

# 构建 Go 二进制
go build -o alist-encrypt-go ./cmd/server


### 数据库配置（可选）

启用 MySQL 持久化（Host 策略与文件元数据）时，建议使用环境变量配置：

```text
DB_TYPE=mysql
DB_DSN=<db_user>:<db_password>@tcp(<db_host>:3306)/<db_name>?charset=utf8mb4&parseTime=True&loc=Local
```

如未设置数据库连接，将自动降级为纯内存模式。
# 运行
./alist-encrypt-go
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ALIST_HOST` | Alist 服务器地址 | `localhost` |
| `ALIST_PORT` | Alist 服务器端口 | `5244` |
| `TZ` | 时区 | `UTC` |
| `RANGE_FAIL_TO_DOWNGRADE` | Range 连续失败后降级阈值 | `2` |
| `RANGE_SUCCESS_TO_RECOVER` | Range 连续成功后恢复阈值 | `3` |
| `RANGE_REPROBE_MINUTES` | Range 不兼容后的重探间隔（分钟） | `30` |
| `RANGE_PROBE_TIMEOUT_SECONDS` | 后台 Range 探测超时（秒） | `8` |

## 代理分流（网盘多选）

- 支持 `direct/env/fixed/rules` 四种代理模式（默认 `direct`）。
- `rules` 模式下可按“网盘 -> 域名”分流，未命中规则默认直连。
- 管理页会显示网盘中文名（如“谷歌云盘/谷歌相册/微软网盘”），支持多选并自动展开域名规则。
- 默认使用内置字典种子 + 手工维护（适配 OpenList/本项目分离部署）。
- 字典文件保存于 `conf/proxy_domain_dict.json`。

## 智能学习配置（默认开启）

以下配置属于“收益大于成本”的项，默认已开启；并且服务端会做范围收敛，超出范围会自动夹紧到合法区间。
`rangeCompatTtlMinutes` 已废弃，不再生效，请使用 `rangeReprobeMinutes`。

| 配置项 | 默认值 | 合法范围 | 说明 |
|------|------|------|------|
| `enableRangeCompatCache` | `true` | `true/false` | 启用 Range 能力学习（建议保持开启） |
| `enableBackgroundProbe` | `true` | `true/false` | 启用后台低频补探（冷启动与失效重探） |
| `rangeFailToDowngrade` | `2` | `1-10` | 连续失败多少次后标记不兼容并降级 |
| `rangeSuccessToRecover` | `3` | `1-20` | 连续成功多少次后恢复 Range 首选 |
| `rangeReprobeMinutes` | `30` | `1-1440` | 不兼容后下一次后台重探间隔 |
| `rangeProbeTimeoutSeconds` | `8` | `2-60` | 单次后台 Range 探测超时 |
| `probeConcurrency` | `4` | `1-20` | 后台探测总并发 |
| `probeProviderConcurrency` | `1` | `1-5` | 单 provider 探测并发上限 |
| `probeMinDelayMs` | `3000` | `0-60000` | 后台探测最小随机延迟 |
| `probeMaxDelayMs` | `15000` | `0-120000` | 后台探测最大随机延迟 |
| `probeCooldownMinutes` | `1440` | `1-10080` | 同一路径探测冷却时间 |
| `probeQueueSize` | `1000` | `100-10000` | 后台探测队列容量 |

## 加密算法选择

| CPU 类型 | AES-NI | 推荐算法 |
|----------|--------|----------|
| Intel Core i3/i5/i7/i9 | ✅ 有 | `aesctr` |
| AMD Ryzen | ✅ 有 | `aesctr` |
| Intel Celeron/Pentium (J4125, N5105) | ❌ 无 | `chacha20` |
| ARM (树莓派、NAS 等) | ❌ 无 | `chacha20` |

## 默认凭据

- 用户名: `admin`
- 密码: `123456`

**首次登录后请立即修改用户名和密码！**

## 管理界面

访问 `http://your-ip:5344/index` 进入管理界面：

- **首页**: 修改用户名、密码，切换主题和语言
- **配置 Alist**: 设置 Alist 服务器地址、加密密码、H2C 开关
- **WebDAV 配置**: 配置 WebDAV 加密代理
- **本地加解密**: 对本地文件夹进行加解密操作

## 鸣谢

### 原项目

- [alist-encrypt](https://github.com/traceless/alist-encrypt) - 原项目作者 [@traceless](https://github.com/traceless)，感谢开创性工作！
- [Alist](https://github.com/alist-org/alist) - 优秀的网盘挂载工具

### AI 辅助开发

本项目的 Go 语言重构由 AI 辅助完成：

- **[Google](https://www.google.com/)** - 感谢 Google 在 AI 领域的研究贡献
- **[Anthropic](https://www.anthropic.com/)** - Claude AI 开发商

### 特别鸣谢

**Antigravity** - 强大的 AI 编程助手，使得这次从 Node.js 到 Go 的完整重构成为可能。从代码架构设计、加密算法移植、WebDAV 协议实现到前端优化，全程 AI 辅助完成。

## 许可证

MIT License
