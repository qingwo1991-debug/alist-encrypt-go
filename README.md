<div align="center">
  <h1>Alist-Encrypt-Go</h1>
  <p>Transparent encryption proxy for Alist — Go 重写，单二进制部署</p>
  <p>
    <a href="https://github.com/qingwo1991-debug/alist-encrypt-go/releases"><img src="https://img.shields.io/github/v/release/qingwo1991-debug/alist-encrypt-go?style=flat-square" alt="Release"></a>
    <a href=".github/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/qingwo1991-debug/alist-encrypt-go/release.yml?style=flat-square" alt="Build"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?style=flat-square&logo=go" alt="Go"></a>
    <a href="https://flutter.dev/"><img src="https://img.shields.io/badge/Flutter-3.24-02569B?style=flat-square&logo=flutter" alt="Flutter"></a>
  </p>
</div>

---

Alist-Encrypt-Go is a **transparent encryption proxy** for [Alist](https://github.com/alist-org/alist). It sits between clients and Alist, encrypting file content and filenames on the fly while preserving full compatibility with video seeking, WebDAV, and range requests.

In addition to the standalone backend, this project also produces an **Android APK** based on [OpenList](https://github.com/OpenListTeam/OpenList) that bundles the encryption proxy directly into a mobile file manager app.

## Quick Start

```bash
# Start Alist + encryption proxy
docker compose up -d

# Access management UI
open http://your-ip:5344/index
```

Create `docker-compose.yml`:

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

Docker run:

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

> Mount `conf` and `data` volumes — otherwise configuration and user data are lost on restart.

## Features

| Category | Features |
|----------|----------|
| **Encryption** | AES-128-CTR, ChaCha20, RC4-MD5 file content encryption; MixBase64 + CRC6 filename encryption |
| **Streaming** | Encrypted range seek support — video seeking works even with encrypted files |
| **WebDAV** | Full WebDAV proxy over encrypted storage |
| **Performance** | Connection pooling, PBKDF2/MixBase64 caching, 512 KB stream buffer, background probe scheduler |
| **HTTP/2** | Native h2c and HTTPS HTTP/2 support with hot-switch via management UI |
| **Proxy Routing** | Domain-based proxy routing (`direct` / `env` / `fixed` / `rules`) with built-in provider domain dictionary |
| **Smart Learning** | Automatic Range compatibility detection and caching per storage provider; configurable probe scheduler with concurrency control and cooldown |
| **Database** | In-memory by default; optional MySQL for persistent Range compatibility cache and file metadata |
| **Deployment** | Single binary, multi-arch Docker images (linux/amd64, linux/arm64), Android APK |
| **Management** | Vue 3 management UI: Alist config, WebDAV settings, local encrypt/decrypt, file transfer, online encrypt config |

## Encryption Algorithms

| Algorithm | Intel AES-NI | ARM / No AES-NI |
|-----------|--------------|-----------------|
| **AES-128-CTR** (v1 / v2) | ✅ Recommended | ⚠️ Slower |
| **ChaCha20** (v1 / v2) | ✅ Good | ✅ Recommended |
| **RC4-MD5** (v1 / v2) | ✅ Fastest | ✅ Fastest |

Content encryption has two versions: **v1** (PBKDF2 + file size in key derivation) and **v2** (enhanced KDF with additional entropy). Filename encryption uses MixBase64 with CRC6 integrity check.

## Build Modes

This project produces **two artifact types** via GitHub Actions:

### 1. Standalone Backend (default)

Embedded Web management UI; single binary or Docker image. Ideal for:

- Docker deployment on NAS / VPS
- Windows exe / Linux binary direct execution
- Linux amd64, arm64, darwin amd64/arm64, windows amd64

```bash
# With embedded web UI (default)
go build -o alist-encrypt-go ./cmd/server

# Without embedded web UI (for external management)
go build -tags noembedwebui -o alist-encrypt-go ./cmd/server
```

### 2. Mobile Android APK

A Flutter-based Android client based on [OpenList-Mobile](https://github.com/OpenListTeam/OpenList-Mobile) that bundles the encryption proxy as a Go binding (AAR). Requires:

- Flutter 3.24+
- Go 1.24+
- Android SDK 35, NDK 25.2.9519653
- gomobile

```bash
# 1. Build Go Android binding (AAR)
cd mobile/openlist-lib/scripts
./init_openlist.sh
./init_web.sh
./init_gomobile.sh
./gobind.sh

# 2. Build Flutter APK
cd mobile
flutter pub get
flutter build apk --release --split-per-abi

# Output: OpenList-Encrypt-<version>_{arm64-v8a,armeabi-v7a,x86_64}.apk
```

See [mobile/BUILD_GUIDE.md](mobile/BUILD_GUIDE.md) for detailed build instructions.

## Build from Source (Standalone)

```bash
git clone https://github.com/qingwo1991-debug/alist-encrypt-go.git
cd alist-encrypt-go

# Build frontend
cd enc-webui
pnpm install && pnpm build
cd ..

# Copy to embed directory
cp -r enc-webui/dist/* web/public/

# Build Go binary
go build -o alist-encrypt-go ./cmd/server
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ALIST_HOST` | Alist server address | `localhost` |
| `ALIST_PORT` | Alist server port | `5244` |
| `TZ` | Timezone | `UTC` |
| `DB_TYPE` | Database type (`mysql` only; requires `DB_DSN`) | _(empty, in-memory)_ |
| `DB_DSN` | MySQL connection string | _(empty, in-memory)_ |
| `RANGE_FAIL_TO_DOWNGRADE` | Range failure threshold before downgrade | `2` |
| `RANGE_SUCCESS_TO_RECOVER` | Range success threshold to restore | `3` |
| `RANGE_REPROBE_MINUTES` | Re-probe interval after incompatibility (min) | `30` |
| `RANGE_PROBE_TIMEOUT_SECONDS` | Background probe timeout (s) | `8` |

### Database

Optional MySQL for persistent caching (Range compatibility, strategy state, file metadata). Both `DB_TYPE` and `DB_DSN` must be set to enable; otherwise in-memory mode is used. Repeated file accesses avoid duplicate writes to reduce DB load.

## Default Credentials

- Initial admin user: `admin`
- Password: randomly generated on first start, printed in startup logs
- **Change password immediately after first login.**

> A default encryption rule `/encrypt/*` is pre-configured with password `123456` for demonstration. This is the *file encryption password*, not the admin login password. Modify or remove it in production.

## Management UI

Access `http://your-ip:5344/index` to manage:

- **Dashboard** — system overview
- **Alist Config** — server address, encryption password, H2C switch
- **WebDAV** — encrypted WebDAV proxy configuration
- **Local Encrypt/Decrypt** — encrypt or decrypt local folders
- **Online Config** — encryption rules, proxy mode, Range learning settings
- **File Transfer** — folder conversion and file migration

> The embedded Web UI is only available in the default standalone build. Android APK and `noembedwebui` builds leave `/index` returning 404 and rely on the native app for configuration.

## Acknowledgements

- [alist-encrypt](https://github.com/traceless/alist-encrypt) — original Node.js project by [@traceless](https://github.com/traceless)
- [Alist](https://github.com/alist-org/alist) — multi-storage file list tool
- [OpenList](https://github.com/OpenListTeam/OpenList) — Alist community fork with mobile support
- AI-assisted development: Google, Anthropic (Claude), Antigravity

## License

[MIT](LICENSE)
