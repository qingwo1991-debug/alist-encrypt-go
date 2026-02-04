# Alist-Encrypt-Go

基于 Go 语言重构的 Alist 透明加密代理，提供文件内容加密和文件名加密功能。

> **本项目是 [alist-encrypt](https://github.com/traceless/alist-encrypt) 的 Go 语言重构版本**
>
> 感谢原作者 [@traceless](https://github.com/traceless) 的开创性工作！

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
| **LRU 缓存** | 内存安全的重定向缓存，自动淘汰 |
| **ChaCha20 加密** | 新增 ChaCha20 算法，无 AES-NI 的 CPU 性能提升 3-5 倍 |
| **类型安全** | 静态类型检查，编译期发现错误 |
| **单文件部署** | 无需 Node.js 运行时，单二进制即可运行 |

## 功能特性

- **透明加密**: AES-128-CTR、ChaCha20、RC4-MD5 文件内容加密
- **文件名加密**: MixBase64 + CRC6 校验的文件名加密
- **Range 请求**: 支持视频拖拽进度（加密文件也支持）
- **WebDAV 支持**: 加密的 WebDAV 访问
- **Docker 就绪**: 环境变量配置，轻松容器化部署

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
      - ./data:/app/data          # 数据目录（BoltDB 存储）
      - ./conf:/app/conf          # 配置目录
    environment:
      - TZ=Asia/Shanghai
      - ALIST_HOST=alist          # Alist 容器名或主机地址
      - ALIST_PORT=5244           # Alist 端口
    networks:
      - alist-network

  # 如果需要同时部署 Alist
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
  -v ./data:/app/data \
  -v ./conf:/app/conf \
  ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
```

### 从源码构建

```bash
git clone https://github.com/qingwo1991-debug/alist-encrypt-go.git
cd alist-encrypt-go
go build -o alist-encrypt-go ./cmd/server
./alist-encrypt-go
```

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ALIST_HOST` | Alist 服务器地址 | `localhost` |
| `ALIST_PORT` | Alist 服务器端口 | `5244` |
| `TZ` | 时区 | `UTC` |

## 加密类型选择

| CPU 类型 | AES-NI | 推荐算法 |
|----------|--------|----------|
| Intel Core i3/i5/i7/i9 | ✅ 有 | `aesctr` |
| AMD Ryzen | ✅ 有 | `aesctr` |
| Intel Celeron/Pentium (J4125, N5105) | ❌ 无 | `chacha20` |
| ARM (树莓派等) | ❌ 无 | `chacha20` |

## 默认凭据

- 用户名: `admin`
- 密码: `admin`

**首次登录后请立即修改密码！**

## 鸣谢

- [alist-encrypt](https://github.com/traceless/alist-encrypt) - 原项目作者 [@traceless](https://github.com/traceless)
- [Alist](https://github.com/alist-org/alist) - 优秀的网盘挂载工具

## 许可证

MIT License
