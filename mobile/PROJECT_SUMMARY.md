# OpenList-Encrypt 项目总结

## 项目状态

✅ 已完成基础架构搭建
✅ 已完成加密模块实现

## 已创建的文件

### 1. Go 后端加密模块 (`openlist-lib/openlistlib/encrypt/`)

| 文件 | 功能 | 状态 |
|------|------|------|
| `crypto.go` | AES-CTR、RC4、Mix 加密算法实现 | ✅ 完成 |
| `mix_enc.go` | Mix 混淆加密算法（兼容 alist-encrypt） | ✅ 完成 |
| `mix_base64.go` | 自定义 Base64 编码器（用于文件名加密） | ✅ 完成 |
| `crc.go` | CRC6/CRC8 校验算法 | ✅ 完成 |
| `proxy.go` | HTTP 代理服务器，处理加解密 | ✅ 完成 |
| `config.go` | 配置管理器，保存/加载配置 | ✅ 完成 |
| `webui.go` | Web 管理界面 | ✅ 完成 |

### 2. Go 后端入口 (`openlist-lib/openlistlib/`)

| 文件 | 功能 | 状态 |
|------|------|------|
| `encrypt_server.go` | 加密代理管理器，gomobile 导出函数 | ✅ 完成 |

### 3. Flutter UI (`lib/`)

| 文件 | 功能 | 状态 |
|------|------|------|
| `main.dart` | 应用入口，添加加密页面导航 | ✅ 修改 |
| `pages/encrypt/encrypt_config_page.dart` | 加密配置页面 UI | ✅ 完成 |

### 4. Android 原生桥接

| 文件 | 功能 | 状态 |
|------|------|------|
| `bridge/EncryptProxyBridge.kt` | Kotlin 桥接实现 | ✅ 完成 |
| `pigeons/pigeon.dart` | Pigeon 接口定义 | ✅ 完成 |

### 5. 文档

| 文件 | 功能 | 状态 |
|------|------|------|
| `README.md` | 项目说明文档 | ✅ 完成 |
| `BUILD_GUIDE.md` | 构建指南 | ✅ 完成 |
| `pubspec.yaml` | 项目配置（已更新名称和版本） | ✅ 修改 |

### 6. GitHub Actions

| 文件 | 功能 | 状态 |
|------|------|------|
| `.github/workflows/build.yaml` | APK 构建工作流 | ✅ 完成 |
| `openlist-lib/scripts/init_openlist.sh` | OpenList 初始化脚本 | ✅ 完成 |

## 已实现的加密功能

### 1. 加密算法（与 alist-encrypt 兼容）

- **AES-CTR**: 高性能流式加密，支持随机访问
- **RC4-MD5**: 流式加密，兼容性好
- **Mix**: 混淆加密，速度快

### 2. 文件名加密

- 使用 MixBase64 自定义编码
- CRC6 校验位验证
- 完全兼容 alist-encrypt 的文件名加密格式

### 3. 透明代理功能

- 拦截 Alist API 调用
- 自动加解密文件内容
- 支持 Range 请求（视频拖动播放）
- WebDAV 协议支持

## 架构说明

```
┌─────────────────────────────────────────────────────────────┐
│                        Flutter App                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Web View  │  │  OpenList   │  │  Encrypt Config     │  │
│  │   Page      │  │  Page       │  │  Page               │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                           │                    │             │
│                    ┌──────┴────────────────────┴──────┐      │
│                    │         Native Bridge            │      │
│                    │  (Pigeon/MethodChannel)          │      │
│                    └──────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                      Android Native                          │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                     Kotlin Bridge                        ││
│  │  - OpenListBridge (现有)                                 ││
│  │  - EncryptProxyBridge (新增)                             ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────┐
│                    Go Library (gomobile)                     │
│  ┌──────────────────┐  ┌─────────────────────────────────┐  │
│  │   OpenList       │  │        Encrypt Module           │  │
│  │   Server         │  │  ┌────────────┐ ┌────────────┐ │  │
│  │                  │  │  │   Crypto   │ │   Proxy    │ │  │
│  │   Port: 5244     │  │  │ AES/RC4/Mix│ │  Server    │ │  │
│  │                  │  │  └────────────┘ └────────────┘ │  │
│  │                  │  │        Port: 5344              │  │
│  └──────────────────┘  └─────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 数据流

### 1. 上传加密流程

```
客户端上传 → 代理服务器 → 加密模块 → 加密数据 → Alist → 云盘
```

### 2. 下载解密流程

```
客户端请求 → 代理服务器 → Alist → 加密数据 → 解密模块 → 明文 → 客户端
```

### 3. 视频播放流程

```
播放器请求(Range) → 代理服务器 → 计算偏移 → 请求 Alist → 解密对应段 → 返回明文
```

### 4. 文件名转换流程

```
加密名 (存储) → MixBase64解码 → CRC6验证 → 显示名 (用户可见)
显示名 (用户输入) → MixBase64编码 → CRC6校验位 → 加密名 (存储)
```

## 关键技术点

### 1. 流式加密

- 使用 AES-CTR、RC4 或 Mix 流式加密
- 支持随机访问（通过 SetPosition）
- 无需完整下载即可播放

### 2. 范围请求处理

```go
// 处理 Range 头
range := request.Header.Get("Range")
start := parseRangeStart(range)

// 设置加密器位置
encryptor.SetPosition(start)

// 解密后返回
decryptReader := NewDecryptReader(response.Body, encryptor)
```

### 3. 文件名加密（兼容 alist-encrypt）

```go
// 编码文件名
func EncodeName(password, encType, plainName string) string {
    passwdOutward := GetPasswdOutward(password, encType)
    mix64 := NewMixBase64(passwdOutward, "")
    encodeName := mix64.Encode([]byte(plainName))
    crc6Bit := crc6.Checksum([]byte(encodeName + passwdOutward))
    return encodeName + string(GetSourceChar(crc6Bit))
}
```

## 待完成事项

### 高优先级

1. **编译测试**
   - [ ] 本地测试 gomobile 编译
   - [ ] GitHub Actions 测试

2. **功能测试**
   - [ ] 加解密功能测试
   - [ ] 文件名加密测试
   - [ ] 与 alist-encrypt 兼容性测试

### 中优先级

3. **性能优化**
   - [ ] 添加连接池
   - [ ] 实现缓存机制
   - [ ] 优化大文件处理

4. **UI 完善**
   - [ ] 添加加密状态指示器
   - [ ] 实现配置导入/导出
   - [ ] 添加加密日志查看

### 低优先级

5. **测试**
   - [ ] 单元测试
   - [ ] 集成测试
   - [ ] 性能测试

## 使用方法

1. 启动 OpenList 服务（端口 5244）
2. 在加密配置页面设置：
   - Alist 服务地址
   - 加密路径规则
   - 加密密码
3. 启动加密代理服务（端口 5344）
4. 通过代理地址访问 Alist

## 构建说明

### 本地构建

```bash
# 初始化 OpenList 依赖
cd openlist-lib
./scripts/init_openlist.sh

# 构建 Go 库
gomobile bind -v -target=android -androidapi=21 -o ../android/app/libs/openlistlib.aar ./openlistlib

# 生成 Pigeon 代码
dart run pigeon --input pigeons/pigeon.dart --dart_out lib/generated_api.dart --java_out android/app/src/main/java/com/openlist/pigeon/GeneratedApi.java --java_package "com.openlist.pigeon"

# 构建 APK
flutter build apk
```

### GitHub Actions

推送到 main/master/dev 分支会自动触发构建。