# Alist-Encrypt-Go

A Go rewrite of alist-encrypt, providing transparent encryption proxy for Alist with HTTP/2 support.

## Features

- **Transparent Encryption**: AES-128-CTR, ChaCha20, and RC4-MD5 encryption for file content
- **ChaCha20 Support**: Optimized for CPUs without AES-NI (e.g., Intel J4125, ARM) - 3-5x faster than software AES
- **Filename Encryption**: Optional encrypted filenames with MixBase64 + CRC6
- **HTTP/2 Support**: Full HTTP/2 with h2c (cleartext) and HTTPS support
- **WebDAV Support**: Encrypted WebDAV access
- **Range Request Support**: Video seeking works with encrypted files
- **Connection Pooling**: Optimized HTTP client with connection reuse
- **512KB Stream Buffer**: Large buffer pool for high-bitrate video streaming
- **LRU Cache**: Memory-safe redirect cache with automatic eviction
- **BoltDB Storage**: Embedded database for configuration persistence
- **Unix Socket Support**: For reverse proxy setups
- **Docker Ready**: Environment variable support for easy container deployment

## Quick Start

### Using Docker (Recommended)

```yaml
# docker-compose.yml
version: '3.8'
services:
  alist-encrypt:
    image: ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
    container_name: alist-encrypt
    restart: unless-stopped
    ports:
      - "5344:5344"
    volumes:
      - ./data:/app/data
    environment:
      - TZ=Asia/Shanghai
      - ALIST_HOST=alist        # Your Alist container/host name
      - ALIST_PORT=5244
    networks:
      - your-network
```

```bash
docker compose up -d
```

Access WebUI at: `http://your-ip:5344/index`

### From Source

```bash
# Download dependencies
go mod tidy

# Build
go build -o alist-encrypt-go ./cmd/server

# Run
./alist-encrypt-go
```

## Configuration

Create a `config.json` file (compatible with OpenAlist format):

```json
{
  "scheme": {
    "address": "0.0.0.0",
    "http_port": 5344,
    "https_port": -1,
    "force_https": false,
    "cert_file": "",
    "key_file": "",
    "unix_file": "",
    "unix_file_perm": "",
    "enable_h2c": false
  },
  "alist": {
    "host": "localhost",
    "port": 5244,
    "https": false
  },
  "cache": {
    "enable": true,
    "expiration": 10,
    "cleanup_interval": 5
  },
  "proxy": {
    "max_idle_conns": 100,
    "max_idle_conns_per_host": 100,
    "max_conns_per_host": 100,
    "idle_conn_timeout": 90,
    "enable_http2": true,
    "insecure_skip_verify": false
  },
  "log": {
    "level": "info",
    "format": "console",
    "output": "stdout"
  },
  "data_dir": "./data",
  "jwt_secret": "your-secret-key",
  "jwt_expire": 24
}
```

### Configuration Options

#### scheme - Server Settings
| Option | Description | Default |
|--------|-------------|---------|
| `address` | Listen address | `0.0.0.0` |
| `http_port` | HTTP port | `5344` |
| `https_port` | HTTPS port (-1 to disable) | `-1` |
| `force_https` | Redirect HTTP to HTTPS | `false` |
| `cert_file` | TLS certificate file | `""` |
| `key_file` | TLS key file | `""` |
| `unix_file` | Unix socket path | `""` |
| `enable_h2c` | Enable HTTP/2 cleartext | `false` |

#### alist - Alist Backend
| Option | Description | Default |
|--------|-------------|---------|
| `host` | Alist server host | `localhost` |
| `port` | Alist server port | `5244` |
| `https` | Use HTTPS for Alist | `false` |

#### proxy - HTTP Client
| Option | Description | Default |
|--------|-------------|---------|
| `max_idle_conns` | Max idle connections | `100` |
| `max_idle_conns_per_host` | Max idle connections per host | `100` |
| `enable_http2` | Enable HTTP/2 for client | `true` |
| `insecure_skip_verify` | Skip TLS verification | `false` |

### Environment Variables (Docker)

For Docker deployment, you can use environment variables instead of config.json:

| Variable | Description | Default |
|----------|-------------|---------|
| `ALIST_HOST` | Alist server hostname | Auto-detect (`alist` in Docker, `localhost` otherwise) |
| `ALIST_PORT` | Alist server port | `5244` |

```bash
docker run -d \
  -p 5344:5344 \
  -e ALIST_HOST=your-alist-host \
  -e ALIST_PORT=5244 \
  -v ./data:/app/data \
  ghcr.io/qingwo1991-debug/alist-encrypt-go:latest
```

### Configuration File

All options can also be set via environment variables with `ALIST_ENCRYPT_` prefix:

```bash
ALIST_ENCRYPT_SCHEME_HTTP_PORT=5344
ALIST_ENCRYPT_ALIST_HOST=localhost
ALIST_ENCRYPT_SCHEME_ENABLE_H2C=true
```

## API Endpoints

### Encryption Management

- `POST /enc-api/login` - User authentication
- `GET/POST /enc-api/getUserInfo` - Get current user info
- `GET/POST /enc-api/updatePasswd` - Update user password
- `GET/POST /enc-api/getAlistConfig` - Get Alist server configuration
- `GET/POST /enc-api/saveAlistConfig` - Save Alist server configuration
- `GET/POST /enc-api/getWebdavConfig` - Get WebDAV configurations
- `GET/POST /enc-api/saveWebdavConfig` - Add WebDAV configuration
- `GET/POST /enc-api/updateWebdavConfig` - Update WebDAV configuration
- `GET/POST /enc-api/delWebdavConfig` - Delete WebDAV configuration
- `GET/POST /enc-api/encodeFoldName` - Encode folder name with password
- `GET/POST /enc-api/decodeFoldName` - Decode folder name

### Proxy Endpoints

- `/d/*`, `/p/*` - File download with decryption
- `/dav/*` - WebDAV with encryption/decryption
- `/redirect/:key` - Redirect decryption handler
- `/api/fs/*` - Alist API interception
- `/*` - Catch-all proxy to Alist

## Password Configuration

```json
{
  "path": "/encrypted",
  "password": "your-password",
  "encType": "aesctr",
  "encPath": ["/encrypted/.*"],
  "encName": true,
  "encSuffix": ".enc",
  "enable": true
}
```

| Field | Description |
|-------|-------------|
| `path` | Base path identifier |
| `password` | Encryption password |
| `encType` | `aesctr` or `rc4md5` |
| `encPath` | Regex patterns for matching |
| `encName` | Enable filename encryption |
| `encSuffix` | Custom file extension |
| `enable` | Enable this config |

## Encryption Types

### ChaCha20 (Recommended for J4125/ARM)

- **Best for CPUs without AES-NI** (Intel Celeron/Pentium, ARM)
- 3-5x faster than software AES on these CPUs
- PBKDF2 key derivation (1000 iterations, SHA256)
- O(1) random access - instant video seeking
- Modern, secure stream cipher

```json
{
  "encType": "chacha20"
}
```

### AES-128-CTR (Recommended for modern CPUs with AES-NI)

- Best for CPUs with hardware AES acceleration (most desktop/server CPUs)
- PBKDF2 key derivation (1000 iterations, SHA256)
- File size-based IV generation
- O(1) random access - instant video seeking

```json
{
  "encType": "aesctr"
}
```

### RC4-MD5 (Legacy)

- MD5-based key derivation
- Stream cipher with position support
- **Not recommended**: O(N) seeking performance for large files
- Kept for backward compatibility

```json
{
  "encType": "rc4md5"
}
```

### CPU Recommendation

| CPU Type | AES-NI | Recommended |
|----------|--------|-------------|
| Intel Core i3/i5/i7/i9 | ✅ Yes | `aesctr` |
| AMD Ryzen | ✅ Yes | `aesctr` |
| Intel Celeron/Pentium (J4125, N5105, etc.) | ❌ No | `chacha20` |
| ARM (Raspberry Pi, etc.) | ❌ No | `chacha20` |
| Qualcomm Snapdragon (with ARMv8 crypto) | ✅ Yes | `aesctr` |

### Filename Encryption

- MixBase64 encoding with KSA-shuffled alphabet
- CRC6 checksum for integrity
- Folder password support

## Architecture

```
cmd/server/main.go          - Entry point
internal/
  config/config.go          - Configuration with env var support
  server/
    server.go               - HTTP/HTTPS/Unix server
    middleware.go           - Logging, CORS, Auth
  handler/
    api.go                  - /enc-api/* routes
    proxy.go                - Proxy with LRU cache
    alist.go                - Alist API interception
    webdav.go               - WebDAV handling
  proxy/
    client.go               - HTTP client pool
    stream.go               - 512KB buffer streaming
  encryption/
    flow.go                 - Encryption dispatcher
    aesctr.go               - AES-128-CTR
    chacha20.go             - ChaCha20 (optimized for non-AES-NI CPUs)
    rc4md5.go               - RC4-MD5 (legacy)
    filename.go             - Filename encryption
  storage/
    store.go                - BoltDB storage
    cache.go                - In-memory TTL cache
  dao/
    user.go                 - User management
    file.go                 - File info + password DAO
  auth/
    jwt.go                  - JWT authentication
```

## Default Credentials

- Username: `admin`
- Password: `admin`

**Change immediately after first login!**

## License

MIT
