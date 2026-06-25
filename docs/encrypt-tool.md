# encrypt-tool

独立文件加解密命令行工具，与 alist-encrypt-go 代理服务完全互通。

加密产物为 V2 格式（32 字节文件头 + 流密码加密体），可直接上传到 Alist 供代理在线解密和视频流式播放（支持 Range 随机读取）。同时支持自动识别并解密 V1 旧格式文件。

## 查看帮助与版本

```bash
encrypt-tool --help      # 显示完整用法
encrypt-tool --version   # 显示版本号
```

## 编译

```bash
# 本机编译
go build -o encrypt-tool ./cmd/encrypt-tool/

# 交叉编译
GOOS=linux   GOARCH=amd64 go build -o encrypt-tool-linux-amd64   ./cmd/encrypt-tool/
GOOS=linux   GOARCH=arm64 go build -o encrypt-tool-linux-arm64   ./cmd/encrypt-tool/
GOOS=windows GOARCH=amd64 go build -o encrypt-tool-windows-amd64.exe ./cmd/encrypt-tool/
GOOS=darwin  GOARCH=amd64 go build -o encrypt-tool-darwin-amd64  ./cmd/encrypt-tool/
GOOS=darwin  GOARCH=arm64 go build -o encrypt-tool-darwin-arm64  ./cmd/encrypt-tool/
```

## 命令

```
encrypt-tool <command> [flags]
```

| 命令 | 说明 |
|------|------|
| `enc` | 加密文件或文件夹 |
| `dec` | 解密文件或文件夹（全自动识别，只需密码） |

## 参数

### 通用参数

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--password` | `-p` | 二选一 | 直接传入加密/解密密码；会出现在进程参数中 |
| `--password-file` | — | 二选一 | 从文件读取密码，适合自动化脚本，与 `--password` 互斥 |
| `--input` | `-i` | （必填） | 输入文件或目录路径 |
| `--output` | `-o` | 源文件同目录 | 输出路径：文件、目录或不指定 |
| `--stdout` | — | false | 仅加密单文件：把 V2 密文写到标准输出，不创建完整密文文件 |
| `--workers` | `-w` | NumCPU | 批量模式并发工作线程数 |
| `--log` | — | 无 | 错误日志输出路径，带时间戳记录检测过程、警告和错误 |
| `--verbose` | `-v` | false | 显示详细进度 |

### 仅加密 (enc)

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--type` | `-t` | `aesctr` | 加密算法：`aesctr` / `chacha20` / `rc4md5` |
| `--enc-name` | `-n` | false | 同时加密文件名（对齐代理的 ConvertRealNameWithSuffix） |
| `--suffix` | `-s` | `.bin` | 加密文件后缀，设为 `""` 表示不加后缀 |

### 仅解密 (dec)

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--type` | `-t` | `auto` | 算法：`auto`（自动检测）/ `aesctr` / `chacha20` / `rc4md5` |

## 加密算法

| 算法 | 说明 | 适用场景 |
|------|------|----------|
| `aesctr` | AES-128-CTR，V2 使用随机 nonce + PBKDF2 600K 迭代 | 默认推荐，通用 |
| `chacha20` | ChaCha20，同上 V2 安全参数 | 无 AES 硬件加速时性能更优 |
| `rc4md5` | RC4-MD5，V1 遗留算法 | 仅兼容旧文件，**不建议用于新加密** |

> RC4-MD5 使用纯 Go 逐字节实现，速度比 AES-CTR/ChaCha20 慢 10-50 倍。处理超过 1 GiB 的文件时工具会自动警告。

## 自动检测（解密时）

解密时无需指定加密类型、格式版本、后缀和文件名，工具会自动识别：

**格式版本检测**

读取文件前 6 字节，匹配 V2 魔数（`AECTR2` / `CHC202` / `RC4MD2`）。匹配成功为 V2 格式（32 字节头），否则为 V1 格式（无头部）。

**算法检测（4 层级联）**

1. **V2 魔数**（100% 可靠）— V2 头部前 6 字节直接标识算法
2. **文件名 CRC6**（~98.4% 可靠）— 对文件名做 CRC6 校验，通过则确认算法。CRC6 使用算法相关的 PBKDF2 盐值，使不同算法之间误判率仅 1/64
3. **内容文件签名** — 读取前 256 字节，分别用三种算法尝试解密，检查解密结果是否匹配已知文件头（MP4 ftyp、ZIP PK、PDF %PDF、PNG、JPEG 等 18 种常见格式）
4. **默认 aesctr** — 以上均无法确定时回退到 aesctr，同时输出警告提示用户可手动指定 `-t`

**后缀处理**

`.bin` / `.enc` / `.dat` 自动剥离。其他自定义后缀通过 CRC6 检测后剥离。

**文件名解密**

自动尝试解码加密文件名。V2 格式：`EncodeName(完整文件名) + 后缀`；V1 格式：`EncodeName(文件名主体) + 原始扩展名`。两种格式自动识别，无需手动指定。

## 输出路径规则

`-o` 参数的行为取决于路径是否存在以及是单文件还是批量模式：

| 场景 | `-o` 不指定 | `-o` 指向已存在文件 | `-o` 指向已存在目录 | `-o` 指向不存在路径 |
|------|------------|-------------------|-------------------|-------------------|
| 单文件 | 源文件同目录，自动生成文件名 | 直接覆盖该文件 | 放入目录，自动生成文件名 | 当作文件路径直接输出 |
| 批量 | — | — | 放入目录，保持相对结构 | 创建为目录，保持相对结构 |

## 加密后验证

每次加密完成后，工具自动读回加密文件前 4KB 进行解密，与原始文件对比。如果密码或算法有问题，会在加密后立即报告，避免上传错误文件。

## 进度报告

文件超过 100 MB 时自动启用进度显示（即使不加 `-v`），每 3 秒输出一次：

```
  video.mp4: 1.2 GiB / 4.5 GiB (27%) | 380 MiB/s | ETA: 9s
```

加 `-v` 时所有文件都显示进度，包括检测方法和逐文件完成状态。

## 错误日志

使用 `--log <path>` 将诊断信息写入日志文件，带时间戳，便于排查问题：

```bash
encrypt-tool dec -p mypass -i ./encrypted -o ./decrypted --log errors.log -v
```

日志内容包含：

- 会话启动信息（版本、命令、输入路径）
- 每个文件的检测结果（算法 + 检测方法）
- 警告（检测失败、RC4-MD5 慢速、磁盘空间不足、worker 数超过 CPU 核心数）
- 批量模式中每个文件的错误（文件路径 + 错误详情）
- 批量结束摘要（文件数、字节数、错误数）
- Fatal 错误（退出前自动写入并关闭日志）

## 磁盘空间预检查

开始处理前自动检查输出目录可用空间。空间不足时输出警告（不阻断，由用户决定是否继续）。Windows 使用 `GetDiskFreeSpaceEx`，Linux/macOS 使用 `statfs`。

## 并发与内存

- 每个工作线程约 576 KB 内存（512 KB I/O 缓冲 + ~64 KB 密码状态），与文件大小无关
- 内存占用 = 工作线程数 × 576 KB，始终为 O(1)
- `-w` 默认值为 `runtime.NumCPU()`，单核机器自动设为 1
- 设置 `-w` 超过 CPU 核心数时输出提示（加密为 CPU 密集型，多余线程无收益）

## 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 失败（密码错误、文件不存在、加解密错误等） |

适合在脚本中通过 `&&` / `||` 链式调用。

## 使用示例

```bash
# 自动化场景推荐：密码文件仅允许 root 读取
install -m 0600 /dev/null /etc/encrypted-mover/key
read -rsp 'Encryption password: ' ENCRYPT_PASSWORD; echo
printf '%s' "$ENCRYPT_PASSWORD" > /etc/encrypted-mover/key
unset ENCRYPT_PASSWORD
encrypt-tool enc --password-file /etc/encrypted-mover/key -i video.mp4

# 流式输出，密文长度严格等于明文长度 + 32 字节
encrypt-tool enc --password-file /etc/encrypted-mover/key -i video.mp4 --stdout

# 仅生成与代理兼容的加密文件名
encrypt-tool name --password-file /etc/encrypted-mover/key -i video.mp4 -t aesctr -s .bin

# 加密单个文件（默认 aesctr，输出追加 .bin 后缀）
encrypt-tool enc -p mypass -i video.mp4

# 加密到指定输出路径
encrypt-tool enc -p mypass -i video.mp4 -o ./encrypted/output.bin

# 批量加密文件夹（含文件名加密，4 线程并发）
encrypt-tool enc -p mypass -i ./videos -o ./encrypted -n -w 4

# 使用 chacha20 算法加密
encrypt-tool enc -p mypass -i archive.zip -t chacha20

# 不追加后缀
encrypt-tool enc -p mypass -i archive.zip -s ""

# 解密单个文件（全自动，只需密码）
encrypt-tool dec -p mypass -i video.mp4.bin

# 解密到指定目录（自动还原原始文件名）
encrypt-tool dec -p mypass -i video.mp4.bin -o ./decrypted

# 批量解密文件夹，带日志和进度
encrypt-tool dec -p mypass -i ./encrypted -o ./decrypted --log errors.log -v -w 4

# 手动指定算法（跳过自动检测）
encrypt-tool dec -p mypass -i video.mp4.bin -t chacha20
```

`--password-file` 会移除文件末尾由编辑器追加的一组 `LF` 或 `CRLF`，
但保留密码中的其他空格和换行。不要同时传入 `--password` 与
`--password-file`。建议密码文件权限设置为 `0600`，且不要放入 Git 仓库。

## 与代理服务的兼容性

| 特性 | encrypt-tool | 代理服务 |
|------|-------------|---------|
| V2 加密格式 | ✅ NewLatestContentEncryptor | ✅ 相同 |
| 文件名加密 | ✅ EncodeName(完整文件名) + 后缀 | ✅ ConvertRealNameWithSuffix |
| V1 兼容解密 | ✅ AutoDecryptReader | ✅ 相同 |
| Range 随机读取 | — | ✅ SetPosition 支持 |
| 后解密验证 | ✅ 加密后自动读回 4KB 校验 | — |

加密后的文件可直接上传到 Alist 存储目录，代理会自动识别 V2 头部并按需在线解密，支持视频拖拽跳转。

## 文件格式

### V2 格式（本工具产出）

```
偏移  长度  内容
0     6     魔数：AECTR2 / CHC202 / RC4MD2
6     1     版本号：2
7     1     保留：0
8     16    随机 Nonce 字段
24    8     原始文件大小（BigEndian uint64）
32    —     流密码加密体（与原文件等长）
```

V2 使用 PBKDF2-SHA256 600,000 次迭代派生密钥，每次加密使用独立随机 Nonce，无 nonce 重用风险。

### V1 格式（仅兼容解密）

无文件头，直接为流密码加密体，与原文件等长。密钥派生使用 PBKDF2 1,000 次迭代 + MD5(fileSize) 作为 IV。同密码同大小的文件会共享 IV，存在 nonce 重用风险，仅用于向后兼容。
