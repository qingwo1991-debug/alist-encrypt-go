# alist-encrypt-go 完整链路分析（代码验证版）

> 所有结论均来自直接阅读源代码，标注具体文件和行号

---

## 一、核心发现：fileSize 参与密钥派生

**代码位置**: `internal/encryption/aesctr.go:28-64`

```go
// 第29行: NewAESCTR 接收 fileSize 作为必需参数
func NewAESCTR(password string, fileSize int64) (*AESCTR, error) {

// 第37-40行: 密码预处理 (PBKDF2)
if len(password) != 32 {
    key := pbkdf2.Key([]byte(password), []byte("AES-CTR"), 1000, 16, sha256.New)
    passwdOutward = hex.EncodeToString(key)
}

// ⚠️ 第41行: fileSize 直接拼接到密钥派生材料中
passwdSalt := passwdOutward + strconv.FormatInt(fileSize, 10)

// 第44行: AES 密钥 = MD5(passwdSalt)，包含 fileSize
keyHash := md5.Sum([]byte(passwdSalt))
a.key = keyHash[:]

// 第47行: IV 也是从 fileSize 派生
ivHash := md5.Sum([]byte(strconv.FormatInt(fileSize, 10)))
```

**结论**:
- `fileSize` 直接参与 AES 密钥和 IV 的计算
- 如果 `fileSize` 错误，密钥和 IV 都会错误，解密输出完全是乱码
- 这不是"解密位置错误"的问题，而是**密钥本身就是错的**

---

## 二、解密三要素及其来源

| 要素 | 代码来源 | 行号 | 获取方式 |
|-----|---------|------|---------|
| password | `passwdInfo.Password` | proxy.go:214 | 配置文件 passwdList |
| encType | `passwdInfo.EncType` | proxy.go:214 | 配置文件 passwdList |
| fileSize | `fileInfo.Size` | proxy.go:205 | **多源获取** (见下) |

### fileSize 获取链路

**代码位置**: `internal/handler/proxy.go:205`
```go
fileInfo, usedStrategy := h.getFileSizeWithStrategy(displayPath, realPath, urlPrefix, r)
```

**代码位置**: `internal/handler/proxy_strategy.go:83-112`
```go
func (h *ProxyHandler) fallbackChainHTTP(...) (*dao.FileInfo, StrategyType) {
    // Level 1: 文件信息缓存 (第87行)
    if fileInfo, ok := h.fileDAO.Get(displayPath); ok {
        return fileInfo, StrategyFileInfoCache
    }

    // Level 2: 文件大小缓存 (第93行)
    if size, ok := h.fileDAO.GetFileSize(realPath); ok {
        return &dao.FileInfo{Path: displayPath, Size: size}, StrategyFileSizeCache
    }

    // Level 3: HEAD 请求 (第100行)
    size, err := h.executeHEADRequestHTTP(headURL, realPath, r)
    if err == nil && size > 0 {
        h.fileDAO.SetFileSize(realPath, size, 24*time.Hour)
        return &dao.FileInfo{Path: displayPath, Size: size}, StrategyHEADRequest
    }
}
```

---

## 三、Range 请求处理流程

**代码位置**: `internal/proxy/stream.go:88-188`

### 关键点1: 剥离客户端 Range 头部
```go
// 第98-103行: 构建请求时明确排除 Range 头部
// Build request WITHOUT Range header - we always fetch full encrypted file
req, err := httputil.NewRequest("GET", targetURL).
    WithContext(r.Context()).
    CopyHeadersExcept(r, "Range").  // ← 关键: 不透传 Range
    Build()
```

### 关键点2: 解密后应用 Range
```go
// 第144-149行: 在解密器上设置位置
if isRangeRequest {
    if err := flowEnc.SetPosition(requestedRange.Start); err != nil {
        return errors.NewDecryptionErrorWithCause("failed to set position", err)
    }
}

// 第170-171行: 用 LimitReader 限制输出长度
readerToStream = io.LimitReader(flowEnc.DecryptReader(resp.Body), requestedRange.ContentLength())
```

### 关键点3: SetPosition 的实现
**代码位置**: `internal/encryption/aesctr.go:66-94`
```go
func (a *AESCTR) SetPosition(position int64) error {
    // 第73-74行: 恢复原始 IV
    a.iv = make([]byte, len(a.sourceIv))
    copy(a.iv, a.sourceIv)

    // 第77行: 计算要跳过的 16 字节块数
    blockCount := position / 16

    // 第80行: 增加 IV 计数器
    a.incrementIV(blockCount)

    // 第83行: 创建新的 CTR 流
    a.stream = cipher.NewCTR(a.block, a.iv)

    // 第86-90行: 丢弃部分块字节
    offset := position % 16
    if offset > 0 {
        discard := make([]byte, offset)
        a.stream.XORKeyStream(discard, discard)
    }
}
```

---

## 四、重定向处理链路

**代码位置**: `internal/handler/proxy.go:249-307`

### 检测到 302 时的处理
```go
// 第250行: 检测 302/301 状态码
if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
    location := resp.Header.Get("Location")

    // 第255-257行: 解析重定向路径，保存原始请求路径
    redirectPath := parsedLoc.Path
    originalPath := r.URL.Path  // ← 这是展示路径
```

### 三级查找策略
```go
// 第262-266行: 策略1 - 用原始请求路径查缓存
if fileInfo, found := h.fileDAO.Get(originalPath); found && fileInfo.Size > 0 {
    fileSize = fileInfo.Size
}

// 第268-274行: 策略2 - 用重定向路径查缓存
if fileSize == 0 {
    if fileInfo, found := h.fileDAO.Get(redirectPath); found && fileInfo.Size > 0 {
        fileSize = fileInfo.Size
    }
}

// 第276-298行: 策略3 - 用 FileSizeResolver 实时获取
if fileSize == 0 {
    result := h.sizeResolver.ResolveSingle(r.Context(), file, authHeaders)
    if result.Error == nil && result.Size > 0 {
        fileSize = result.Size
    }
}

// 第300行: 注册重定向，存储三要素
key := h.RegisterRedirect(location, fileSize, passwdInfo.Password, passwdInfo.EncType)
```

### redirectInfo 存储结构
**代码位置**: `internal/handler/proxy.go:41-47`
```go
type redirectInfo struct {
    URL       string    // 重定向目标 URL
    FileSize  int64     // 文件大小 (用于密钥派生)
    Password  string    // 密码
    EncType   string    // 加密类型
    ExpiresAt time.Time // 1小时过期
}
```

---

## 五、fileSize == 0 时的行为

**代码位置**: `internal/proxy/stream.go:91-96`

```go
// Handle empty files without decryption overhead
if fileSize == 0 {
    w.Header().Set("Content-Length", "0")
    w.Header().Set("Accept-Ranges", "bytes")
    w.WriteHeader(http.StatusOK)
    return nil  // ← 直接返回空响应，不执行后续逻辑
}
```

### ⚠️ 关键点：fileSize==0 没有回退机制

如果 `ProxyDownloadDecrypt` 被调用时 `fileSize==0`：
1. **直接返回空响应** - 不会发起上游请求
2. **resolveFileSize 不会被调用** - 因为函数已经 return
3. **用户看到空文件** - 而不是解密失败

这意味着 **fileSize 必须在调用 ProxyDownloadDecrypt 之前正确获取**。

### resolveFileSize 的实际作用

`resolveFileSize` (第115行) 只在 fileSize > 0 时作为**校验/补充**使用：
```go
// 只有 fileSize > 0 才会执行到这里
resp, err := s.client.Do(req)  // 第108行
// ...
fileSize = resolveFileSize(fileSize, resp)  // 第115行 - 优先使用缓存值
```

如果传入的 fileSize 是错误的非零值（比如从错误缓存获取）：
- 会使用错误的 fileSize 派生密钥
- 解密输出完全是乱码
- **没有任何机制检测或恢复**

---

## 六、Content-Length 设置

**代码位置**: `internal/proxy/stream.go:172-175`

```go
} else {
    // Full content response
    w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))  // ← 用 fileSize
    w.WriteHeader(http.StatusOK)

    readerToStream = flowEnc.DecryptReader(resp.Body)
}
```

**问题场景**: 如果用了上游的 Content-Length（加密大小）而不是正确的 fileSize：
- AES-CTR 模式下，加密大小 = 解密大小（无头部开销）
- 但如果 fileSize 派生错误，解密器可能在某处出错或提前终止
- 客户端收到的字节数与 Content-Length 不符 → broken pipe

---

## 七、降级策略代码验证

### resolveFileSize 回退链
**代码位置**: `internal/proxy/stream.go:310-337`

```go
func resolveFileSize(cachedSize int64, resp *http.Response) int64 {
    // Priority 1: 使用缓存的大小
    if cachedSize > 0 {
        return cachedSize
    }

    // Priority 2: 从 Content-Range 解析 (206 响应)
    if resp.StatusCode == http.StatusPartialContent {
        if cr := resp.Header.Get("Content-Range"); cr != "" {
            // Format: bytes start-end/total
            if idx := strings.LastIndex(cr, "/"); idx >= 0 {
                if total, err := strconv.ParseInt(cr[idx+1:], 10, 64); err == nil && total > 0 {
                    return total
                }
            }
        }
    }

    // Priority 3: 使用 Content-Length
    if cl := resp.Header.Get("Content-Length"); cl != "" {
        if size, err := strconv.ParseInt(cl, 10, 64); err == nil && size > 0 {
            return size
        }
    }

    return 0  // ← 全部失败返回 0
}
```

---

## 八、完整数据流图（代码验证）

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ GET /d/encrypted-folder/电影.mp4                                             │
└───────────────────────────────────────────┬─────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ HandleDownload (proxy.go:172)                                                │
│ ├── displayPath = strings.TrimPrefix(r.URL.Path, "/d")      # 行173         │
│ └── passwdInfo, found := h.passwdDAO.FindByPath(displayPath) # 行178        │
└───────────────────────────────────────────┬─────────────────────────────────┘
                                            │ found == true
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 路径转换 (如果 passwdInfo.EncName == true)                                   │
│ ├── realPath = h.convertDisplayToRealPath(displayPath, passwdInfo) # 行194  │
│ │   ├── 优先: h.fileDAO.GetEncPath(displayPath)           # 行155           │
│ │   └── 回退: converter.ToRealName(fileName)              # 行167           │
└───────────────────────────────────────────┬─────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 获取文件大小 (proxy.go:205)                                                  │
│ fileInfo, usedStrategy := h.getFileSizeWithStrategy(displayPath, realPath...) │
│ ├── Level 1: fileDAO.Get(displayPath)     # proxy_strategy.go:87            │
│ ├── Level 2: fileDAO.GetFileSize(realPath) # proxy_strategy.go:93           │
│ └── Level 3: executeHEADRequestHTTP()      # proxy_strategy.go:100          │
└───────────────────────────────────────────┬─────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 流式解密 (proxy.go:214)                                                      │
│ h.streamProxy.ProxyDownloadDecrypt(w, r, targetURL, passwdInfo, fileInfo.Size) │
└───────────────────────────────────────────┬─────────────────────────────────┘
                                            │
                                            ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ ProxyDownloadDecrypt (stream.go:89)                                          │
│ ├── 构建请求: CopyHeadersExcept(r, "Range")                # 行102          │
│ ├── 创建解密器: NewFlowEnc(password, encType, fileSize)    # 行118          │
│ │   └── 内部: passwdSalt = passwdOutward + fileSize        # aesctr.go:41   │
│ │   └── 内部: key = MD5(passwdSalt)                        # aesctr.go:44   │
│ ├── Range处理: flowEnc.SetPosition(rangeStart)             # 行146          │
│ ├── 设置头部: Content-Length = fileSize                    # 行174          │
│ └── 流式输出: io.CopyBuffer(w, decryptReader, 512KB)       # 行183          │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 九、确定成功与确定失败

### 确定成功的条件（代码验证）

| 检查点 | 代码位置 | 成功条件 |
|-------|---------|---------|
| 密码配置匹配 | proxy.go:178 | `passwdDAO.FindByPath()` 返回 `found=true` |
| fileSize 获取 | proxy.go:205 | `fileInfo.Size > 0` |
| 解密器创建 | stream.go:118 | `NewFlowEnc()` 返回 `err == nil` |
| 流式传输 | stream.go:183 | `io.CopyBuffer()` 无错误 |

### 确定失败的场景

| 场景 | 代码位置 | 后果 |
|-----|---------|------|
| passwdInfo 未找到 | proxy.go:179-188 | 直接透传，不解密 |
| fileSize == 0 且无法回退 | stream.go:115 返回 0 | 密钥派生错误，解密乱码 |
| 上游完全不可达 | stream.go:109 | 返回错误，502 |
| io.Copy 写入失败 | stream.go:183 | broken pipe 日志 |

---

## 十、验证清单

```bash
# 1. 验证 fileSize 获取日志
# 预期: "File size: NNNN, strategy: XXX"
curl -v "http://localhost:5233/d/encrypted/video.mp4" 2>&1 | grep -i size

# 2. 验证 Range 处理
# 预期: 206 Partial Content, Content-Range 正确
curl -v "http://localhost:5233/d/encrypted/video.mp4" -H "Range: bytes=0-1000"

# 3. 验证重定向处理日志
# 预期: "Found size via original path" 或 "Resolved size via head"
# 查看服务日志

# 4. 验证 Content-Length
# 预期: Content-Length 与实际输出字节数一致
curl -v "http://localhost:5233/d/encrypted/video.mp4" -o /dev/null 2>&1 | grep Content-Length
```

---

## 附录：关键代码文件索引

| 文件 | 关键行号 | 功能 |
|-----|---------|------|
| `internal/encryption/aesctr.go` | 41, 44, 47 | 密钥和 IV 派生（fileSize 参与） |
| `internal/proxy/stream.go` | 89-188 | 流式解密主逻辑 |
| `internal/proxy/stream.go` | 310-337 | fileSize 回退获取 |
| `internal/handler/proxy.go` | 171-218 | HTTP 下载处理 |
| `internal/handler/proxy.go` | 249-307 | 重定向拦截处理 |
| `internal/handler/proxy_strategy.go` | 83-112 | fileSize 获取策略链 |
| `internal/handler/webdav.go` | 97-136 | WebDAV GET 处理 |
