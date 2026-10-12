# 移动端 V3 读取：阶段 2 实施设计

## 范围与审查状态

本设计基于只读源码审查，已读取根 `AGENTS.md` 与 `mobile/AGENTS.md`。设计审查未运行 build/test，未修改实现代码。本文是后续实施依据，不代表 V3 已实现或编译通过。不包含真实 URL、凭据或密码。

目标是**完整移动端 V3 读取**：容器 header/trailer、chunk AEAD、plaintext GET/HEAD/Range、缓存与 SQLite/sync 字段、拒 Range 的 bounded fallback；不是仅识别 magic 或移除 415。阶段 2 不引入 V3 upload/resume，不重写 V1/V2 cryptography，不改变 filename compatibility。

行号对应审查时工作树，后续修改可能使其漂移。

## 实证架构与 API

### 移动端与共享实现是独立边界

- `mobile/openlist-lib/openlistlib/encrypt/content_v2.go:137–144`：独立 `ContentMeta`，目前没有 `ChunkSize/KDFIterations`。
- 同文件 `:230`：`ParseContentHeader`；`:324`：`NewCipherV2`；`:345`：`NewLatestContentEncryptor`，当前上传仍为 V2；`:389`：`AutoDecryptReader`；`:543`：`normalizePlainFileSize`。
- `shared/encryptcore/go.mod:1–10`：独立 module `github.com/alist-encrypt-go/shared/encryptcore`，Go `1.25.0`，`x/crypto v0.51.0`、`x/sync v0.20.0`、`x/sys v0.45.0`。
- shared 的 package 名是 `encryption`，移动代码建议显式 import alias `core`。
- `internal/proxy/v3_download.go:10–14` 引用 root `internal/config`、`internal/errors`、`internal/httputil`。移动 module 不满足这些包的 Go internal 导入边界；该文件仅作 HTTP 策略参考，不能直接导入，也不应复制其中 crypto。

### 可复用的共享 API

| 文件定位 | API | 用途 |
| --- | --- | --- |
| `shared/encryptcore/content_v3.go:58` | `IsV3Prefix` | 安全识别短 prefix |
| 同文件 `:240` | `ParseV3Header` | 解析完整 V3 header |
| 同文件 `:272` | `ParseFrontMatter` | V3 优先，否则 V2/V1 |
| 同文件 `:295` | `V3ChunkWindow` | plaintext 区间到完整 ciphertext records |
| 同文件 `:71` | `NewV3ChunkCipher` | 构造共享 AES-256-GCM chunk cipher |
| `shared/encryptcore/v3_stream.go:41` | `DeriveV3Key` | nonce salt、iterations=0 时 600000，已有 key cache/singleflight |
| 同文件 `:224` | `ReadTrailerV3(io.ReaderAt, size)` | 从尾部读取真实 plaintext length |
| 同文件 `:302` | `OpenV3Container` | 随机访问容器 |
| 同文件 `:330` | `V3Container.ReadAt` | 按 record 认证读取 plaintext |
| `shared/encryptcore/v3_stream_plain.go:31` | `NewV3StreamReader(r, cipher, chunkSize, firstIndex, skip, limit)` | 读取完整 record 流、认证后输出限定 plaintext |

`V3StreamReader` 不理解 header/trailer（`v3_stream_plain.go:13–16`）；调用方必须先确定真实明文长度、定位 record，并限制输出。

容器有两类：

1. 固定头格式：48-byte header 中 `PlainSize > 0`，后跟固定宽度 records，无 stream trailer。
2. Streaming 格式：header 的 `PlainSize = 0`，records 后有 16-byte trailer（`v3_stream.go:23–28`），magic `V3E4` 加 reserved 与真实 plaintext length。

空容器也需明确识别。不能用 `ciphertextSize - headerLen` 推 V3 plaintext size，因为每个 record 含 tag、最后一块有 padding，stream 还有 trailer。

### alias 决策

**推荐保留移动 `ContentMeta`，仅新增 V3 字段和显式转换函数；不必 alias shared metadata。**

移动 `crypto.go:28` 的 `EncTypeAESCTR` 值是 `aes-ctr`，shared `flow.go:20` 是 `aesctr`。shared `content_v2.go:117` 的 V2 magic 查表没有 normalization；直接 string cast 后调用 shared V2 parser 会将 `AECTR2` 漏识别为 V1。RC4 两边的值均为 `rc4md5`，差别只是常量名。

如最终选择 alias，必须同时解决所有 `EncType` 字段赋值、normalization、调用点和 AES 显式映射，不得只替换 type 定义。另有语义差异：移动 V2 build/parse 拒绝 empty（`content_v2.go:215/:248`），shared 允许 empty（shared `content_v2.go:97/:129`），不能借 V3 改动顺手替换 V2 行为。

## 当前实现缺口

- `proxy_v2_helpers.go:118` 只请求 32-byte prefix；`:183–188` 仅生成 V3 magic 占位 metadata。
- `proxy.go:564–577` 的 `RedirectInfo`、`:726–738` 的 `FileInfo` 没有 chunk/KDF 字段。
- `play_v2.go:771–773/:805–807` 缓存 V3 目前也只是占位。
- 415 拒绝函数位于 `play_v2.go:1007`，调用点包括 `:1152/:1221/:1357/:1763/:1811`。应在完整 V3 读取服务接通后删除，不得提前降级为 V1。
- `play_v2.go:489–506` 的 `ServePlayback` 将 `/dav2`、`/dav`、`/d`、`/p` 分派到 legacy handlers。
- `proxy_download.go:543–557` 与 `proxy.go:5441–5457` 在非 V2 时创建 V1 `NewFlowEncryptor`，存在密文 passthrough 分支。完整 V3 支持必须覆盖这些入口，在上游 Range 与响应提交前统一 V3 调度。

## 实施阶段（8 步）

### 1. Module、init 与 gobind 同步

**实施**

- 移动实际 `go.mod:3/:5` 从 Go 1.24 / toolchain 1.24.13 提升至至少 Go 1.25；toolchain pin 不低于最低版本并与受控 CI 工具链一致。
- require `github.com/alist-encrypt-go/shared/encryptcore v0.0.0`，actual module 的 local replace 为 `../../shared/encryptcore`。
- MVS 至少选取 shared 要求的 `x/crypto v0.51.0`、`x/sync v0.20.0`、`x/sys v0.45.0`；同步真实 `go.sum`。其余 `x/net/text/tools` 仅在传递依赖确有要求时提升，不照搬 root 全部依赖。
- `mobile/openlist-lib/src/go.mod` 若要求能独立解析，replace 的相对路径应为 `../../../shared/encryptcore`，不能原样复制实际 module 的 replace 路径。
- `scripts/init_openlist.sh:91–93` 每次覆盖 actual `go.mod/go.sum`。clone/copy 后必须重应用受控 module overlay，保证 Go floor、shared require/replace、dependency pin 和 checksum 不丢失。推荐维护脚本 overlay，而不是把 generated `src` 当主要 ownership。
- 同脚本 `:190/:192` 的 `x/mobile@latest` 改为受控 pin。`init_gomobile.sh:11/:25/:32` 与 `gobind_ios.sh:60/:69/:70` 已从 module 精确安装 gomobile/gobind，继续保持一个版本来源，不无理由 bump x/mobile。
- `gobind.sh:104` 继续仅 bind mobile-facing `openlistlib`；不把 shared V3 类型暴露为 Java/Flutter 新接口，不提交生成 AAR/JAR。
- `.github/workflows/release.yml:25` 已选择 Go 1.26.5，满足 Go 1.25 floor。

**必须覆盖的验证**：readonly module graph、local replace 路径、clone/init 后 overlay 保留、checksum 完整、Android 各 ABI 云端编译与 gomobile 绑定。设计阶段不运行这些命令。

### 2. V3 metadata 桥接与安全几何

**实施**

- 移动 `ContentMeta` 增加 `ChunkSize uint32`、`KDFIterations uint32`、`IsV3()`。
- 新增 V3 bridge，显式 core↔mobile metadata 转换，复用上述共享 API；保留移动 V1/V2 `FlowEncryptor` 与密码、文件名兼容逻辑。
- 加入纯容器 metadata validator：nonce 长度 16、header 48、raw tag 16、合法 chunk、非负 plaintext size、record count 与实际 ciphertext size 一致、stream trailer 几何一致；用除法计算避免溢出，限制 chunk index 在 uint32 nonce 空间。
- 不能只信 shared 解析后的值：`ParseV3Header:257–258` 会将非法 chunk 默认化。需要检查 raw header。
- `ReadTrailerV3:224` 只完成 trailer 读取与 magic 检查；调用方还需校验 reserved、长度非负和几何。

**必须 tests**：fixed/stream/空 48 与 64-byte 容器、错误 version/tag/chunk/nonce、负数或溢出尺寸、record count 不匹配、KDF 边界；V2 AES magic 及三算法 V1/V2 golden 保持不变。

### 3. 完整 header/trailer 探测

**实施**

- 保持一个总 context/deadline，完整读取 48-byte header；可先取 32-byte prefix，识别 V3 后精确补足 16 bytes。
- 所有 tiny 206 必须核对 `Content-Range` 起终点、known total、identity encoding 与 exact length；读取最多 `n+1` bytes 以检出超长，短 body 不可确认 legacy。
- 200 只能作为从 offset 0 开始的完整表示处理，不能把 200 body 的开头当 requested trailer bytes。
- header plaintext=0 时，探测最后 16 bytes；复用 `ReadTrailerV3`，通过小的 offset-aware `io.ReaderAt` adapter，或另行评审 shared 纯 metadata helper。
- 只在 header/trailer/几何完整确认后落缓存。识别为 V3 但 probe 失败时 fail closed，禁止重新解释为 V1。
- redirect、header completion、trailer probe 全部保持 origin credentials 与 CDN credentials 隔离，且遵循 cancellation。

**必须 tests**：32-byte 截断 V3 不降 V1、错/短/超长 range、encoded response、unknown total、trailer magic/reserved/geometry 失败、follow-up auth 拒绝与跨 host credential 不泄漏。

### 4. 共用 V3 读取服务覆盖所有 routes

**实施**

- 为 redirect、`/api/play/stream`、`/dav`、`/dav2`、`/d`、`/p` 提供共用移动 V3 读取服务。
- 在普通 plaintext range 校验、上游 range 生成、V1/V2 cipher 创建之前完成 V3 metadata resolution 和分派；不能仅在已经发送 V2 range 后补 V3 解密。
- `parseSingleRange(play_v2.go:512)` 以真实 plaintext size 解释 bounded/open/suffix range。
- 请求 ciphertext range 使用 `core.V3ChunkWindow`，包含完整 record；严格验证上游覆盖正确 chunk window，再调用 shared stream reader 认证、trim padding 并只输出要求的 plaintext。
- HEAD 生成 plaintext `Content-Length/Content-Range/Accept-Ranges`，不输出 body，不执行 chunk KDF/record allocation；metadata probe 必要的 HTTP 工作仍需预算。
- 已确认 empty V3 是空文件，不是 `play_v2.go:1825` 的 unknown-size BadGateway。空文件 Range 仍按 plaintext HTTP 语义处理。
- `decode=0` 保留原始密文表示，`redirectRawFileSize(play_v2.go:682)` 增加 V3 支持，不修改 raw headers/length。
- 不对 V3 使用 V2 `UpstreamOffset` 或 ciphertext-header 明文推导；recognized V3 禁止 V1 cipher 与 PlayFirstFallback 密文透传。
- 服务接通后删除全部 V3 415 策略，替换 unsupported-only 测试。

**必须 tests**：上述所有 routes 的 GET/full/bounded/open/suffix/cross-chunk/HEAD/empty/decode=0；实际 body exact bytes、plaintext CL/CR、416 total、无 415、无密文 passthrough。

### 5. RangeRefused、no-Range HEAD 与 exactbytes fallback

**实施**

- 上游 ignore Range=200、416 或错误 206，仅在 downstream response 未 started 时返回对应 range failure，使 `play_v2.go:1984–2032` 已有 bounded chunked/full fallback 接管。
- V3 full/chunked fallback 的 body 是整个容器：先 discard 48-byte header，再以 `firstChunk=0`、`skip=plaintextStart`、`limit=requestLength` 使用 shared reader。绝不能按 `plainStart+header` 跳原密文。
- 必须精确校验最终 written == expected plaintext bytes；fallback 不得多输出 padding/trailer。
- Metadata probe 也要支持拒 Range：fixed header 可从 200 获取 48 bytes 和 total；stream header 无真实明文长度时，拒 Range 上游无法通过 HEAD 推导尾长。
- 对 no-Range streaming container，使用**有磁盘/总下载字节/时间预算的完整容器暂存**，取得 `io.ReaderAt` 后确认 trailer/几何，再回答 HEAD 或读取。超额返回明确 502/503，不无界 `ReadAll`，不伪造 plaintext size；错误路径和 cancellation 清理 temporary file。
- 尊重 `rangeSkipMaxBytes`，同时计入 V3 record 流量放大。若优化为几何跳过完整 ciphertext records，需明确安全与流量预算，目标 record 必须认证。

**必须 tests**：200 ignoreRange、416 与 malformed206，分别 fallback exact bytes；no-Range stream HEAD；bounded fallback cap、deadline/cancel/temp cleanup；错误 interval 不在错误 index 解密；不重复响应或在 response started 后 retry 拼接。

### 6. 字段全链路、SQLite/sync 与缓存 identity

**实施**

贯通 `ChunkSize/KDFIterations` 至：

- `ContentMeta`、`RedirectInfo(proxy.go:564)`、`FileInfo(proxy.go:726)`。
- `local_store.go` 的 `prewarmMeta:42`、`storeRecord:54`、`LocalSizeRecord:81`、schema create `:255`、migration `:378`。
- SQL select/scan `:463/:782/:819`、flush/upsert `:688/:699`、import/upsert `:875/:886`。
- `AddSizeV2Meta:526`（可 generalized 加兼容 wrapper）、`local_integration.go` record `:119` / lookup `:151`。
- `meta_sync.go` DTO `:71`、import conversion `:165–193`。
- 全部 clone/store/refresh/reset 路径：`play_v2.go:836/:900–920`、`proxy_cache.go:337/:413`；不能只写一次 struct definition。

缓存可信判定必须要求完整 V3 metadata，而不是只有 version=3。

`decrypted_block_cache.go:312–333` 当前 key 主要使用 `info` 字段，应使用 authoritative meta 的 version/nonce/chunk/KDF/plain/cipher，以及 password 和 object identity。避免 probe 首次请求拿旧 info 构造错误 cache key。

SQLite 不能仅用同 ciphertext size 判定 object 未替换；换 raw URL 或同大小替换要复查 header nonce。AEAD/truncation structural failure 失效 local 与 memory metadata；客户端取消不应失效。sync/import metadata 保留加密字段，丢弃服务端 signed URL/sign 的现有安全策略不变。

empty V3 size=0 必须可贯通，而 `AddSizeV2Meta:527`、lookup `local_integration.go:159`、sync `meta_sync.go:172` 当前拒绝零值。仅为完整 confirmed empty V3 放开，不能让未知 size 伪装成空文件。普通 size observation、partial sync 不可将完整 chunk/KDF/nonce 字段零化。

**必须 tests**：旧 DB migration、restart 完整 V3 metadata、import/export 字段、partial sync/size observation 保留字段、同大小替换与 new raw URL invalidation、不同 password/meta 的 decrypted cache 隔离、empty metadata roundtrip。

### 7. 认证失败、资源预算与 provider learning

**实施**

- 设置移动 per-record 与 process aggregate memory cap；在 KDF/body read 前取得预算，所有 success/error/cancel 路径释放。格式可接受的大 chunk 不等于移动播放应分配该大小。
- overload 返回 terminal 503，清理未提交的成功 headers，no-store/Retry-After；不因重试 strategy/URL 放大 overload。
- KDF iterations 设安全上界；0 保持 shared 600000 语义。拒绝过大工作量是本地 metadata/resource 失败，不是 provider Range 能力失败。
- shared reader 每个完整 record 认证后才暴露 plaintext；可预读首 record，使错误密码/首块 tamper 在提交 200 前报告失败。
- 后续 record 认证失败，立即终止流，禁止拼接 retry、密文 fallback；缓存只接收已认证 bytes。
- `StreamOutcome(strategy_selector.go:539)` 当前只有 Err/FailureReason/Retryable/ResponseStarted/StatusCode。必要时加 `NoLearning`，并 gate `play_v2.go:1954–1963` 的 learning；metadata/AEAD/resource 失败不污染 provider capability。
- exact expected bytes 校验必需；short stream 即失败。client disconnect 与 upstream truncation/AEAD 失败分类不同。

**必须 tests**：错误密码/tamper/reorder/truncation、不输出失败 record plaintext、KDF cap、并发预算/取消释放、无 provider learning、authenticated-only cache、首块失败未提交成功响应、后块失败不再 retry。

### 8. V1/V2 回归与交付验证

**实施**

- 新增移动 V3 metadata/probe/read tests，把 `playback_unsupported_v3_test.go` 改成真实支持 GET/HEAD/Range/失败场景。
- 跨 module fixture 由 shared `NewV3Writer(v3_stream.go:77)` 与 `NewV3Header(content_v3.go:214)` 生成；不在移动测试实现 crypto 副本。
- 保留 V1/V2 upload resume golden；`NewLatestContentEncryptor(content_v2.go:345)` 仍输出 V2。
- 不改变 `proxy.go:4600/:4611`、`proxy_alist_api.go:1350/:1363` 的上传算法与 resume 语义，`putUploadMeta(proxy_v2_helpers.go:61)` 的 V2-only 限制保留。
- 设计批准后按根 AGENTS：最便宜 syntax/focused gates，`agent/*` 分支和 Draft PR，云端 `test-mobile-go` 与 Android 各 ABI gomobile binding。不要在本地反复长时编译移动依赖图。

**必须 tests**：V1/V2 三算法及 filename compatibility、V2 header magic、V2 resumed upload/headers、全部 V3 routes matrix、同步/init 可复现与 cloud compilation。不得以仅 magic 测试替代实际 plaintext exactbytes 测试。

## Owned-file 边界

### 阶段 2 必须拥有或显式协调的移动文件

目录基准：`mobile/openlist-lib/openlistlib/encrypt/`。

- `content_v2.go`：仅 metadata 扩展与必要 dispatch，不改 V1/V2 crypto。
- 新 `content_v3.go`、`proxy_v3_helpers.go`、`play_v3.go` 及对应 tests。
- `proxy_v2_helpers.go`、`play_v2.go`。
- `proxy.go`：struct fields 与读取 route/dispatch 范围；不借此重写上传。
- `proxy_download.go`、`proxy_cache.go`、`decrypted_block_cache.go`。
- `local_store.go`、`local_integration.go`、`meta_sync.go`。
- `strategy_selector.go`：仅本地错误/no-learning 所需 outcome 扩展。
- `mobile/openlist-lib/go.mod/go.sum`、`scripts/init_openlist.sh`、受控 module overlay 与必要 src 同步配置；gomobile 脚本仅为同一 pin/工具链的必要同步。

### 默认不修改

- `shared/encryptcore`：默认只读复用。如确需导出 tiny trailer/validation metadata helper，应单独分配 ownership、共享 tests，不改 wire/KDF/V1 行为。
- root `internal/proxy/v3_download.go`：只读参考，不 import、不复制 crypto。
- V1/V2 cipher 与 filename 实现、upstream drivers、Flutter/Java generated bindings、AAR/JAR。
- generated `src` 不作为手工大规模改动边界；通过可复现 overlay 管理需要持久保留的配置。

## 主要架构风险与完成标准

1. **类型 alias 风险**：AES type value 不同，直接 cast 会破坏 V2 magic。
2. **路由不完整风险**：redirect 支持不等于 DAV/download 支持；legacy 分支可能将 V3 当 V1 或透传。
3. **长度风险**：V3 tags/padding/trailer 使密文长度不能线性转换为明文长度；HEAD 必须使用确认 metadata。
4. **Range refusal 风险**：trailer probe 本身可能失败；stream no-Range HEAD 必须有 bounded spool 或明确受控失败。
5. **资源风险**：不可信 chunk/KDF 参数可引发 OOM/CPU 放大；单流和总量都需预算。
6. **缓存风险**：same-size replacement、signed URL renewal、字段零化会令 nonce/chunk/KDF 与 object 错配；authenticated cache 与 identity/invalidation 需统一。
7. **供应链/同步风险**：init 覆盖 module、x/mobile@latest、src 不同 replace depth 会使实际构建与评审树分离。
8. **兼容风险**：阶段 2 必须保持 V1/V2 cryptography、filename 与 V2 upload/resume，不用 V3 工作替换整个移动 crypto stack。

完成标准：所有移动读取入口都能以 shared cryptography 读取真实 V3 plaintext；fixed/stream/empty、GET/HEAD/all single Range forms、拒 Range bounded fallback 均有 exactbytes 测试；chunk/KDF 字段跨内存/SQLite/sync 完整，缓存与认证失败安全；模块/init/gobind 可复现；V1/V2 回归通过，并有云端移动编译信号。
