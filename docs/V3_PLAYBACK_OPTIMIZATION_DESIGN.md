# Root V3 播放优化：Stage 3/4 可实施设计（只读审计）

> 本轮唯一产物是此新文档；不修改已有代码/配置/UI/workflow，不执行 build/test，不创建分支或 PR。路径与行号是本轮读取的源码快照，不是测试通过声明。范围为 root + `shared/encryptcore`；mobile 不在实现授权内。先修 Full fallback skip-budget 绕过，再做优化。以下 proposed API/参数均尚未实现。

## 1. 结论与优先顺序

1. **Stage 3 P0：统一 V3 Range 被拒后的 Full/Chunked skip budget。** 当前 Full 分支绕过已有 Chunked 限额，既可能拖慢首帧，也会逐块做无用认证；应在 KDF、body read、成功响应提交之前 fail closed，并禁止换 URL/策略继续下载同一超预算窗口。
2. **Stage 3：独立的新文件 V3 chunk 配置，不改格式默认常量，不拿运行配置解释旧文件。** 推荐新文件 playback preset 为 1 MiB；保留缺省/兼容 16 MiB，先 opt-in，bench 后才讨论改变产品缺省。CLI 与本地文件任务最小贯通；代理上传继续 V2，不能顺手“升级 Latest”。
3. **Stage 3：V3 整 authenticated chunk cache + 开放 Range cached-prefix 续接。** 现有输出 block cache 保留 V1/V2；V3 只在 AEAD 成功后发布整块，支持同块任意小范围重用，不以开放 Range 整段命中为条件。
4. **Stage 3：KDF service 的跨 key 有界 admission + cancel-wait + service-owned leader。** 已有 KDF cache/singleflight 不能删除，也不能把问题误报为“没有缓存”。先解决不同 key 并发和等待取消；PBKDF2 已运行时不可抢占的边界必须显式保留。
5. **Stage 4：独立 playback interest generation、active registry 与协作抢占。** 只撤销 speculative work 的 interest，不取消正常当前 HTTP stream。无可信播放会话标识的第三方播放器，保守保持现状；不能凭 IP、Range offset 或猜测 next episode 判定用户切片。

## 2. 当前事实、missing 与证据

### 2.1 KDF 并非空白实现

- `shared/encryptcore/v3_stream.go:38-58`：`DeriveV3Key` 把 iterations=0 归一化为 600000；先 cache，再 `singleflight.Group.Do`，leader 内二次查 cache，再 PBKDF2，返回 key copy。
- `shared/encryptcore/flow.go:183-233`：identity 为完整 SHA-256(password) + SHA-256(nonce) + iterations；load/store 拷贝，TTL 滑动续期，超容量清理过期后淘汰最早 expiry。`flow.go:66-77` 定义 256 项上限。已经隔离不同密码/nonce/iterations；TTL 借用 V2 key TTL，而非 generation。
- **missing**：同步 `Do` 无 ctx，caller 被取消仍等到 key 完成；singleflight 仅合并相同 key，不限不同容器的 PBKDF2；没有 global active/queue cap、foreground reserve、queued promotion 或 canceled waiter accounting。直接改成 DoChan 只能让 caller 返回，不能限制执行 goroutine/CPU，也不能完成 shared ownership。
- `internal/proxy/v3_download.go:46-79` 有 record memory admission，随后同步 KDF；这不是 CPU admission。`:155-163` HEAD 才返回，因此当前非空 V3 HEAD 也在 `:74` 做 KDF。优化可将无需解密的 HEAD 提前至 metadata/range 验证后，不能把 HEAD 当成已认证明文。

### 2.2 Route metadata 已经复用，但不等于认证授权

- `internal/handler/playback_orchestrator.go:85-134` 收集 Authorization/Cookie scope，先按 display path 取 FileDAO metadata；完整才注入 request context，否则 probe。
- `internal/handler/playback_content_meta.go:8-43` 已检查 V3 nonce/header/chunk/KDF 存在，缺 geometry 的旧持久化 entry 强制重探测；V3 空文件另判。不得退回“缺 chunk 就用当前新文件 chunk 配置”。
- `internal/dao/file.go:25-29`、`internal/storage/mysqlstore/types.go:53-57` 已有 chunk/KDF 字段；DAO/MySQL replacement 与 V3 专门测试已存在。不需要为新文件 chunk 新建 metadata 表列。
- 当前 complete 条件是字段存在与边界，不是 header/trailer 的密码认证，也没有在此处证明所有非空 geometry 相互一致。V3 header/trailer 参数不是单凭缓存就能当成真实的对象 revision。密码错误应在 chunk AEAD 失败，不应因复用结构 metadata 判为密码正确。
- **必须区分**：structural metadata 可在同一稳定对象/revision下复用，通常无需以密码为 key；raw URL 与 plaintext cache 则必须按授权 scope 隔离。缓存返回不得绕过原 route 的访问权限检查。密码变化必须使 plaintext/key identity 变化，而不必删除所有结构 metadata。

### 2.3 decrypted cache 的真实覆盖范围

- `internal/proxy/stream_download.go:236-271`：single GET Range 才尝试 cache，ParseRange 后对完整 `ContentLength()` 调 `getRange`；因此 `bytes=0-` 在大文件上等价“命中整个文件”。
- `internal/proxy/decrypted_block_cache.go:9,41-94,161-168`：getRange 全有才命中，最大服务 16 MiB；copy 出完整 payload，并非 contiguous-prefix API。不能将“已有 Range cache”写成“开放 Range 已支持 prefix”。
- `stream_download.go:274-301` key 含 stableID、targetURL hash 前 8 字节、password hash 前 8 字节、encType、fileSize、version、headerLen、cipherSize、nonce；**漏 ChunkSize/KDFIterations/auth scope/明确 object revision**。URL query 变动又会失效，稳定ID未消除 signed URL rotation。8-byte hash 不是必须成立的隔离证明；新 V3 identity 应用完整 domain-separated digest。
- `internal/proxy/v3_download.go:245-248`：缓存挂在输出 reader 上，只收请求输出 slice。`decrypted_block_cache.go:229-252`：不从 block boundary 开始会跳过前一块片段。
- `shared/encryptcore/v3_stream_plain.go:74-100`：先读 `chunkSize+16` 全 record，AEAD 成功，之后才 skip/limit；安全行为正确，但相邻 tiny range 每 request 仍可能再次读取和认证同一 16 MiB record。
- `shared/encryptcore/v3_stream.go:252-297` 的 `V3Container` 有每 view 一个 immutable chunk cache，且同 view 串行 miss；proxy 走 `NewV3StreamReader`，不是共享此 Container，故不能宣称 proxy 已具备跨 HTTP authenticated-chunk cache。
- `internal/proxy/v3_memory_budget.go:5-32`：256 MiB 同时 record buffer budget，注释明确 cache/pool 另算。新 cache/pinned memory 不能藏进这个计数而不解释所有权。

### 2.4 Refused Range 与 Full skip 绕过（首要修复）

- `stream_download.go:417-431`：Full 将 activeRange 保存为 fullRequestedRange，再把 activeRange 清空，进入 V3 分支。
- `v3_download.go:81-104` 已验证 Range response 的 ciphertext window。200/no Content-Range、416、错起点返回可重试 range failure，未提交成功响应；此能力必须保留。
- `v3_download.go:175-182` Full 分支直接丢 header、`skip=fullRequestedRange.Start`，**没有预算检查**。
- `v3_download.go:183-195` 仅 Chunked 检查 activeRange.Start 与 `chunkedSeekMaxDiscardBytes`；而这个位置已经过 `:74` KDF。`:250-252` 才提交成功 header，修复有可靠的 precommit 窗口。
- `v3_stream_plain.go:85-99` 对被 skip 的每一块仍 AEAD.Open，故远 seek + refused Range 的 Full 下载不是廉价 Seek。此问题不能靠缩小“新文件 chunk”修复旧 16 MiB 容器。

### 2.5 新文件入口并不统一

- `NewV3Writer`/`NewV3ContentEncryptor` 已接收 chunkSize（`v3_stream.go:75-98`，`v3_content.go:28-34`），<=0 或 >format max 目前静默回 16 MiB；产品配置层必须显式校验，不能靠此静默 fallback。
- `cmd/encrypt-tool/main.go:216-223,883-890` 两条创建路径都硬编码 `NewV3ContentEncryptor(0)`；`:1068-1084` CLI V3 默认、`--v2` 可退回；`:1146` help 的 default:V2 文本与实现不一致。
- `internal/handler/encrypt_file.go:129-164` 本地任务默认 V3、支持 v2；`:424-438` 同样硬编码 chunk=0。`enc-webui/src/views/encrypt-local/index.vue:22-35,71-91` 表单只展示旧算法，不提供 V3 格式/chunk 选项。
- `internal/config/config.go:24-33,41-104` 没有新文件 chunk 配置。`shared/encryptcore/content_v2.go:188-204` 名叫 NewLatest 但返回 V2；`internal/proxy/stream_upload.go:39-81` 的 upload/resume 路径正依赖 V2 geometry。**禁止**改 NewLatest 使上传被隐式变成 V3；V3 resume/padding/trailer 是另一个项目。

### 2.6 Scheduler 的 actual active/context 边界

- `playback_orchestrator.go:923-965` next sibling 只允许本地已知非目录、有正 size、有 encrypted mapping，安全不 fabricate；但 source 与 first frame 同为 `first_frame_warmup`。
- `probe_scheduler.go:117-122` probeItem 只有 file/auth/source/queuedAt，无 playID/generation/cancel。`:509-545` high-first FIFO、跳过 busy provider、全局队列有界是**dispatch priority/fairness**，不是 active preempt。
- `:638-674` runningCount 在 claimed + delay 前增加，delay 还占 provider slot；只有计数，没有 active task registry。`:651-667` timer 只监听 scheduler Stop。
- `:240-242,601-606,673-674` 使用进程 scheduler-owned context；Stop 在 `:573-598` 取消并 Wait 是已经实现的 shutdown ownership，应保留。
- `:114-115,693-698` RawURLFetcher 回调无 context；内建 fetchRawURL、inspect、ProbeRangeCompatibility 在 `:702-707,761` 有 probeCtx。不能声称加 cancel func 就能立即中断所有网络路径。
- `:801-816` pending 去重以 file key 为单位，不自动升级已排队 low task，也不表示有多个 generation 引用。`:765-777` “成功 warm”是 raw URL/metadata/range artifact，**不是**已预热 KDF 或首个 authenticated chunk。

## 3. Stage 3 设计

### 3.1 唯一选型：显式 new-file options，兼容读取不变

Proposed API（统一 CLI /本地任务语义，不改已有 constructor）：

```go
type V3NewFileOptions struct { ChunkSizeBytes int64 }
func ResolveV3NewFileOptions(requestBytes, configuredBytes int64) (V3NewFileOptions, error)
// request > 0 优先；再 configured > 0；两者 0 => 16<<20。
// 产品允许 1/2/4/8/16 MiB；格式 reader 的合法上限独立且不变。
```

- config：`AlistServer.v3NewFileChunkSizeKb`，0=兼容 16 MiB；UI playback preset 写入 1024。此字段是**新文件创建**设置，不是 proxy 解密 chunk override。`/encryptFile` 增 `v3ChunkSizeKb` request override；以 task 创建时快照传入每个文件，运行期间 reload 不改变 job。
- CLI：`--v3-chunk-size-kb 1024`，省略保持现有 16 MiB；CLI 不默认读 server config，不将其变成硬依赖。两条 writer 调用都贯通。`--v2` + 显式 V3 chunk option 报冲突（省略 option 不冲突）；解密只能读 header/trailer，显式 write-only option 提示错误，不能改旧容器几何。
- UI：本地加密增加“V3 AES-256-GCM / V2 compatibility”与“兼容16 MiB / playback1 MiB”选择；V3 时旧 encType 仅用于 filename/legacy兼容，不假称可选 RC4 的 V3 chunk cipher。解密禁用 chunk；setting-alist 可设置新任务缺省。server 校验拒绝非法值，未知旧 JSON 省略值保留现行为。
- 1 MiB 相对 16 MiB 把首块认证下载量降至约 1/16，代价 tag 数增多与最后块 padding：额外 tag 约16 bytes/MiB，尾部最多一个chunk padding。不能承诺等比例首帧改善：KDF/RTT/播放器 demux 仍可主导。
- 不迁移/重加密已有文件；不改 `v3DefaultChunkSize`；不改 V1/V2 reader；不改代理上传，尤其禁止只用 startOffset 判断“全新完整 upload”就启用 V3。

### 3.2 Full/Chunked 统一 budget（必须先落地）

Proposed API：

```go
type V3SkipPlan struct { CipherDiscardBytes, RecordsToSkip, InChunkSkip int64 }
func planV3FallbackSkip(meta ContentMeta, plainStart int64) (V3SkipPlan, error)
func checkV3FallbackBudget(plan V3SkipPlan, maxCipherDiscard int64) error
```

- 以 V3 header + `floor(start/chunkSize)*(chunkSize+16)` 计 ciphertext discard，安全 checked arithmetic；intra-record读取量记录为首个必须认证 chunk，不算跳过全 records，但计总资源测量。
- 统一 Full/fullRequestedRange 与 Chunked/activeRange；Range strategy（上游 exact chunk window）不做全容器 skip budget。新增预算语义可由现 `chunkedSeekMaxDiscardBytes` 值作为保守 cap 对 V3 解释；不要悄悄改变 V1/V2 的 plaintext-offset 语义。若产品坚持精确旧语义，显式增加 `v3FallbackMaxDiscardBytes`，缺省取当前已有有限默认值而不是 unlimited。
- 0 不等于无限下载：`internal/proxy/stream_range_compat.go:124-129` 已确认 nil cfg / 值<=0 返回 **8 MiB** effective cap，沿用这一有限缺省；明确“显式禁用 cap”属于另项 opt-in，非该优化缺省。旧16 MiB首record在start=0可认证，但start>=一整chunk的Full fallback会超过8 MiB；这是可预测资源拒绝，不是更改文件格式兼容性。
- 检查顺序：valid metadata/overflow → fallback budget → KDF admission → record memory/IO。不要让 rejected远seek先占CPU或读body。Range被200拒绝时先分类range failure，不为这个失败尝试KDF；后续 fallback 作同一统一检查。
- 超预算 typed reason `v3_seek_budget_exceeded`、`Retryable=false`、`NoLearning=true`；这里“不学习”是不把资源拒绝当provider坏，不抹除前一次真实Range unsupported学习。orchestrator 对此终止所有 Full/Chunked/URL fallback，并返回空 `503 Retry-After`/`no-store`（不是416：client interval在资源内有效），清掉未提交的成功Content-Range等header。
- 拒绝请求必须 close upstream body；更早能在构造 Full/Chunked request前预算拒绝则优先，防止已经发送巨大 GET。首版保留response处防御检查，形成双层保证。

### 3.3 V3 identity 与 authenticated chunk cache

Proposed proxy-internal API：

```go
type V3ObjectID [32]byte
type V3ChunkLease interface { Bytes() []byte; Release() }
func v3ObjectIdentity(stableObject, revision, authScope string, meta ContentMeta, password string) (V3ObjectID, error)
func (c *v3ChunkCache) Acquire(id V3ObjectID, index uint64) (V3ChunkLease, bool)
func (c *v3ChunkCache) PublishAuthenticated(id V3ObjectID, index uint64, plain []byte) bool
func (c *v3ChunkCache) ContiguousPrefix(id V3ObjectID, start, end int64, maxBytes int64) ([]V3ChunkLease, int64)
```

Identity 包含带长度/domain的 provider/config namespace、稳定真实encrypted对象路径、revision/ETag（若可靠）、auth scope、完整SHA-256 password digest、version/headerLen/plainSize/cipherSize/chunkSize/normalizedKDF/nonce。不要把不同 Alist server 的同 display path混为同对象。targetURL只在缺稳定对象/revision时作保守 fallback；有可信 identity 时去掉 signed URL query，不是随意strip query“创造稳定对象”。没有revision保障时绑定确切URL+有限TTL；对象 replacement 即使 same size也须 miss。密码hash不打印、不持久化，更不把raw Authorization入日志。

- 权限路径先验证，才查plaintext cache；anonymous/authenticated或两个scope不能互命中。若 scope来源暂不可确定，禁用 V3 cache而不是猜测。
- geometry必须validate：headerLen=48、nonce16、chunk>0且format合法、KDF规范化且资源策略允许、plain>=0、容器大小与record数/可选16byte trailer一致；checked multiply/add。拒绝未知 metadata，旧 entry 重探测。header/trailer不是密码证明；任何 plaintext发布必须来自当前身份对应AEAD成功。
- cache 实现独立 byte-LRU，可先共用 enable/max-MB配置而给V3分配明确预算，避免 V1/V2 cache与V3 cache各自吃满同一预算。大于cache cap的合法chunk直接stream不缓存。
- 在 `V3StreamReader` 成功Open、skip/limit之前添加 opt-in chunk hook，**发布整块copy**；不能引用它下一Read会重用的record backing array。最后块按PlainSize裁剪，padding不进入servable prefix。library 不引入proxy/config依赖。
- 支持cache hit时跳过对应 record IO/AEAD需由proxy的chunk source协调，不能单纯加hook后宣称“免下载”。第一版：进入请求前查chunk cache；miss后使用现顺序stream并publish；后续增加首miss的chunk-window精确fetch。不同请求同chunk miss合并可作为第二步，但必须使用与KDF相同service-owned waiter规则，不能拿首个HTTP req.ctx作shared leader。
- 缓存数据immutable；短请求可copy，长prefix用lease/io.Reader无整体大allocation。lease保证eviction不使正在写出的slice失效。**resident+evicted-but-pinned总和有界**：pins有独立cap，与cache和现recordbudget一起给总内存公式；超过pin预算只取有限prefix或miss，不允许每stream额外pin整个LRU。发布copy需预留新增resident bytes；未入cache的同块暂态内存也记录/受cap。

### 3.4 Open Range cached prefix：保持HTTP语义，不截断播放

- ParseRange保留client interval `[start,end]`（开放range end=PlainSize-1）。先请求缓存最长连续前缀，有限例如16 MiB/每request；命中prefix不足全interval**不是**直接短206。
- 缓存覆盖完整interval：正常206，长度原请求长度，不访问upstream/KDF。仅prefix：response Content-Range/Length仍为完整interval；reader串联 cached bytes + 从first missing plain offset起的新 V3 chunk window（不假装EOF，不改client end）。
- 缺口offset必须落在已缓存整chunk结束；首缓存chunk可从其intra offset切片，尾cachedprefix结束在chunk边界/真实文件tail。这样续接不重复输出/不漏字节。上游Range从missing chunk offset构造，不从HTTP已经输出的byte数盲猜。
- 最小可靠首版：**在成功header提交前**准备后半stream、验证其upstreamContent-Range、通过预算/KDF admission，随后写cachedprefix并续stream。这可能仍受cold setup latency，但不会把前缀写出后再尝试503/另一策略导致混合响应；更激进的“立即写prefix，再准备tail”不是首版必选。
- 若缓存首块后上游refuse missing Range：Full fallback仍从容器开头，统一预算按missing offset检查。cache不消除refusedRange网络skip。不得因已有prefix绕过budget。
- 成功header后disconnect/tag failure/truncation只终止body，不fallback换URL、不再次writeheader；日志记 authenticated prefix已输出字节，后续失败不发布失败chunk。`ResponseStarted`/预期长度沿现防重复response约束。
- 不支持multiple range就保留416；suffix range、end clamp、空文件沿现语义。`bytes=0-`大文件不复制整个文件；cache热只保证已有chunk的省下载，不保证整文件无上游。

### 3.5 KDF 有界队列、取消等待与共享leader

Proposed共享库服务，不把root config依赖塞到library：

```go
type KDFPriority uint8 // foreground > speculative
type V3KDFLimits struct { Active, Queue, MaxWaiters, ForegroundReserve int }
func DeriveV3KeyContext(ctx context.Context, password string, nonce []byte, iterations uint32, priority KDFPriority) ([]byte, error)
// 原 DeriveV3Key保留兼容包装；root playback切到context API。
```

- cache命中直接copy返回；miss规范化identity、在同一lock join/createflight。不同key flight受Queue cap；同keywaiter不占新flight queue但受MaxWaiters总/每flight上限，不能DoChan无限注册。Active起始1或2由bench定，speculative不能占完foregroundreserve。
- per-flight维护状态queued/running/done、waiter引用/priority、service-owneddonechannel、result/error；context只是该waiter等待生命周期，不是leader工作ctx。
- 原singleflight的去重语义保留；要实现withdraw queued、prioritypromotion与refcount，建议将这一段替换为显式flight registry，而不是在Do内等token（会产生无界等待goroutine），更不能同时维护两套flight所有权。既有keycache继续复用。legacywrapper也走同service，不能成为绕过admission的后门；因原签名无error，包装可阻塞等待legacy admission，但此类legacy等待的限制/优先级要明确，root在线入口必须使用可拒绝API。
- queued全部waiter取消：原子removequeue+registry+清secret引用，不做PBKDF2。queuedspeculative加入foreground：promote，同key仍一个flight。caller返回ctx.Err，不把其cancel记provider失败。
- running某waiter取消：caller立即返回；其他waiter/foreground仍等同leader；不得Forget同key启动第二个PBKDF2。全部runningwaiter取消时，现PBKDF2无法中断，worker继续到完成再释放Active；可按正常TTL存key（不表示plaintext授权），不复活已取消的playinterest。
- service shutdown不承诺硬停止runningPBKDF2，必须等待或明确bounded drain；不能取消“领头请求”的HTTP ctx导致另一个有效waiter失败。nonce/password在flight启动前复制快照，避免配置reload/复用slice数据race。
- queue满/waiters满 typed `ErrKDFBusy`，在成功header前返回503/Retry-After/NoLearning、不自动retry；runningCPU不能“preempt”而超发worker。恶意极大iterations必须先有显式读取资源上限，超限用typedresourceerror，不减弱为低iterations解密。具体上限需兼容已有文件，默认600000不是所有header都只允许600000的证据。
- metrics仅keycachehit/miss、active、queued、waiters、admissionrefused、cancelqueued/cancelwait、orphanrunning、queueduration/runduration；不得日志password/derivedkey。

## 4. Stage 4：Interest generation / Scheduler active preemption

### 4.1 只对预热所有权使用generation

```go
type PlaybackInterest struct { SessionID string; Generation uint64; CurrentObject string }
func (ps *ProbeScheduler) AdvanceInterest(scope string, interest PlaybackInterest) error
func (ps *ProbeScheduler) EnqueueInterest(file FileItem, auth http.Header, interest PlaybackInterest, kind WarmKind)
// WarmKind: foregroundmetadata > nextEpisode > directory/startup
```

- session必须由可信client显式播放意图产生，且绑定auth/configscope；不能采信任意外部header无限建map。未接入该协议的HTTP/DAV保持旧warm FIFO，无“自动abort用户旧片段”。root管理UI不是实际第三方播放器，新增UI字段也不会神奇提供播放session。
- generation只由明确`play new object/seek intent`升级，HTTP Range fan-out、HEAD、同片同时buffer/audio/video请求不升级；仅凭后来的Range start变化生成generation会把正常播放破坏。
- foreground HTTP stream的ctx仍是requestctx/服务shutdown/既有timeout，**绝不**挂在interestcancel上；generation变化只撤销该session对queued/runningspeculativewarm的引用。当前响应已经开始后，即使用户真的换集也由clientclose结束旧HTTP，不由全局interest主动杀掉。
- nextEpisode是独立低于foreground的WarmKind，不再冒用firstFrame。同session新generation删除旧nextEpisode引用；另一session仍关注同任务则保留。scope+filekey去重并记录多个interest，不把pending map的一个布尔值当引用计数。

### 4.2 实际active registry与协作抢占

- scheduler保留现provider-aware readydispatch/Stop语义；新增active map：taskID→kind/provider/interestRefs/cancel/phase/startedAt。`runningCount`保留compat诊断，但区分claimed/delay/io/finished，不能表示“用户当前active playback”。
- 每task childctx派生schedulerctx，不派生发起enqueue的短命HTTPctx；全部interest撤销时可cancel speculative task。新foreground demand可选择同provider无foreground引用的lowestpriorityactivewarm cancel；真正foregroundstream、共享foregroundresolver/KDFleader绝不能被cancel。
- slot只能在任务实际return后释放；调用cancel不等于资源已释放，不能提前decrement runningCount/sem来超发。delay最好移到claimprovider之前的readyAt调度，最小版至少delayctx可取消、所有exit走deferrelease/reservationcleanup。
- RawURLFetcher需要新的context-aware签名 `func(ctx context.Context, displayPath, realPath string, auth http.Header) string` 并贯通注册方。旧callback若暂保留adapter，必须标注不可抢占并限制timeout；不能承诺全流程preempt。resolver若sharedsingleflight同样检查leaderownership，cancel warmwaiter不能cancel foregroundwaiter。
- phase边界检查ctx/generation并在发布warm状态前二次检查interest仍有效。结构cache允许service-owned真实结果更新，但stalegeneration不能标warm_ready/发后续KDFchunkwarm；停止或抢占不能留下pendingreservation永久阻塞新任务。
- 首版nextEpisode仅metadata/rawURL/rangewarm；若扩展key/firstchunkwarm，分别走有界KDF与chunkcacheadmission，最多一个sibling首chunk，禁止扫描整目录预热所有PBKDF2/大record。
- registry、sessionmap、interestrefs有容量/TTL；无interest背景目录scan仍受现queuebounded。queue满时nextEpisode可drop，foreground不得靠“挤掉正在运行者”实现瞬间保证。

## 5. Owned files：未来实施边界与依赖

下表是后续实现ownership建议，不是本轮修改清单；本轮仅此doc独占。不要让fields/UI agent与core agent同时编辑相同文件。

| Owner/顺序 | 允许未来owned files | 不可顺手修改的边界 |
|---|---|---|
| Stage3-A 预算先行 | `internal/proxy/v3_download.go`, `internal/proxy/stream_download.go`, 新 `internal/proxy/v3_skip_budget.go`/`v3_skip_budget_test.go`, orchestrator终止分支相关 `internal/handler/playback_orchestrator.go`及专测 | 不改configuration/UI/KDF；先让Full拒绝failterminal。orchestrator与Stage4禁止并行编辑 |
| Stage3-B KDF | `shared/encryptcore/v3_stream.go`, `flow.go`, 新 `v3_kdf_service.go`/`v3_kdf_service_test.go`；root `v3_download.go`context调用（由A合并owner串行衔接） | 不改cipherformat/iteration生成默认，不做mobile适配；shared独立module需单独验证 |
| Stage3-C chunk/cache | `shared/encryptcore/v3_stream_plain.go`及专测（与B协调sharedowner）；新 `internal/proxy/v3_chunk_cache.go`/test、`v3_range_reader.go`/test；`stream_download.go`,`v3_download.go`,`requestmeta.go`,`stream_proxy.go`由proxy单owner | 不复用V1/V2输出blockentry当authenticated V3 chunk；不并行争用A文件 |
| Stage3-D new-file options/CLI | 新shared `v3_new_file_options.go`/test；`cmd/encrypt-tool/main.go`/test；`internal/handler/encrypt_file.go`/test | 不改`NewLatestContentEncryptor`/stream_upload；options contract先冻结 |
| Stage3-E fields/UI | `internal/config/config.go`,`parser.go`及专测；`configs/config.example.json`；`enc-webui/src/views/encrypt-local/index.vue`,`views/setting-alist/index.vue`,`store/config.js`及现API序列化触点；`docs/encrypt-tool.md` | 此owner只在D确定单位/default/API后开始；无需改metadataDAO/DB列；本轮禁止该owner写existingfiles |
| Stage4 scheduler | `internal/handler/probe_scheduler.go`/专测；新 `playback_interest.go`/test；`playback_orchestrator.go`,`episode_sibling.go`及callback注册触点 | 先完成Stage3接口；globalrequestctx不能换成generationctx |
| Validation后置 | `.github/workflows/release.yml`仅必要benchmarkregex/命令补充；新相关bench/test | 不新建release workflow，不触发manualrelease，不把编译mobile留给重本地build |

引用的UI serialize触点要实现前按真实payload审查：本设计不假定所有字段由store自动保存，也不授权改dist/web/public编译产物。

## 6. 具体 tests / 必须可证伪的验收

使用httptest、fakeclock、controlledKDF/barrier与request/bodyread计数，不用真实云端速度作单元断言。

### 6.1 Stage3预算（P0先有测试）

- `TestV3FullFallbackSkipBudgetRejectsBeforeKDFAndRead`：上游拒绝Range→Full，远offset超cap；KDFcalls=0、bodyreads=0，终止503且无Content-Range/ETag/Content-Length成功残留，bodyclosed一次。
- `TestV3ChunkedAndFullShareCipherSkipPlan`：同start、16MiB/1MiB/非2幂合法chunk；checked record+tag+header；等于cap允许、cap+1拒绝、start0允许。
- `TestV3RefusedRangeBudgetDoesNotTryAnotherURL`：orchestrator不同rawURL/internalURL均不能预算失败后继续；真实rangefailure仍记一次，预算拒绝NoLearning。
- overflow/maxchunk/negativeoffset/zero-length文件；伪206错起点、短window、200含错误Content-Range、416；确认没有成功header后retry。

### 6.2 配置与文件兼容

- `TestV3NewFileOptionsPrecedenceAndValidation`：省略/0→16MiB；config1024与request2048优先；非法/负值/非允许单位拒绝，不静默constructorfallback。
- CLI两个entry写header均为指定chunk；`--v2`冲突明确；localtask配置快照在reload后不变；UIpayload与serverJSON单位一致、解密无override。
- 旧V1/V2/旧16MiB V3、新1MiB V3逐byte解密相同；末块partial/empty/>1chunk/padding；更改newfileconfig后同一oldcontainerRange内容和geometry不变。
- 明确代理upload/resume仍产V2 regression，不将本次chunk配置应用其offset。

### 6.3 Chunk cache /开放range

- `TestV3TinyRangesReuseWholeAuthenticatedChunk`：首请求0-1，下一请求同chunk末尾2bytes，上游recordfetch=1、AEADopen=1；跨chunk请求精确2record；内容与plaintextreference相同。
- tag/密码错误chunk不缓存；已有首chunk+第二chunk认证失败仅首chunk可用；失败chunk重试无sticky错误plaintext。
- identitytable逐项变更password/authscope/provider/path/revision/nonce/chunk/KDF/sizes必须miss；可信signedURLrotation命中；无稳定revision的rotation保守miss；permissiondeny时cache不读。
- `TestV3OpenRangeCachedPrefixContinuesExactTail`：`bytes=0-`大于16MiB，缓存首1MiB；完整206长度正确、tail Range从chunk1开始、没有duplicate/gap、内存不随文件大小增长。
- nonzeroopen/suffix/endclamp/尾块trim/缓存gap/全cachedinterval/HEAD/multipleRange；prefix+tailrefusedRange同样预算拒绝且**尚未提交prefix**。
- immutablepublishcopy、并发replacement/eviction/lease；sum resident+pinned+records<=预算；disconnect释放lease；慢writer不能pin整个cache；hook不引用reusedrecord。race测试覆盖并发samechunk。

### 6.4 KDF

- 保留并强化 `v3_key_cache_test.go`：samekey Ncall一次、distinctnonce/iterations/password不同、normalize0与600000同identity、copy不可改cache、TTL/256eviction。
- `TestV3KDFGlobalAdmissionBounded`：Ndistinctcoldkey只Active执行、Queue等待；剩余ErrBusy，peakgoroutine/registry/waiters有界；cachehit不占queue。
- `TestV3KDFCanceledWaiterDoesNotCancelSharedLeader`：A开始Bjoin，cancelA立即返回而B得到key；executioncount=1、未提前releaseactive；取消所有running仍不重复leader。
- 全queuedwaiter撤销不执行PBKDF2；foregroundjoin promotes queuedspeculative；queue满时已有keyjoin策略/maxwaiters边界；shutdown/drain、cancel与complete同刻race、cachefill与enqueue同刻二次查cache。
- 超KDFresourcepolicy在CPU前拒绝，错误不降iterations、不当provider失败；HEAD完整metadata零KDF。

### 6.5 Interest /preempt（Stage4）

- `TestPlaybackInterestDoesNotCancelCurrentHTTPStream`：当前slowstream持续读，新generation切nextEpisode；旧speculativectx取消但stream继续正确body，无第二header。
- 同session同object多个Range不advance；不同session看同片，一个advance不撤销另一个task引用；anonymous无session不猜测cancel；stalescope/token拒绝且map有界。
- foreground入队抢占只选同providerlowactive；provider slot直到callback真正return才释放；blocked/non-contextcallback不谎报即时preempt。
- 原pendinglowtask被foreground加入后提升而不是skipdup；generation撤销清pending/reservation，下一代可立即enqueue；delaycancel/shutdown等所有path无goroutine/slot泄漏。
- stale任务完成不发布warm_ready/不触发下一阶段首chunkwarm；独立结构metadata保存允许但intereststatus不能复活；保留现knownsibling不fabricate规则。

## 7. Workflow needed / bench max（不在本轮执行）

已存在 `.github/workflows/release.yml:9-11` PR触发；`:57-100` `test-concurrency-performance` 有20minute job cap、race与network-freebench、performance artifact。`:92-93` 已用 `-benchtime=200ms -count=3`，不是缺performanceworkflow。新增bench若命名 `BenchmarkV3...`/`BenchmarkPlayback...`（shared）、`BenchmarkDecrypted...`/`BenchmarkProbe...`（root）能被现regex发现；`BenchmarkKDF...` 或 `BenchmarkInterest...` 则需明确扩regex，不能假称自动跑。

| 后续验证 | 最小命令/预算 | 验收信号 |
|---|---|---|
| 本地轻门禁（获实施授权后） | changedfile gofmt/diff；shared/root focusedtest各短timeout；不本地重编mobile | syntax与focusedbehavior，不代替CI |
| shared KDF | `go test -mod=readonly -run '^$' -bench '^BenchmarkV3KDF' -benchmem -benchtime=200ms -count=3` | cold/hit/coalesced/distinct+cancel；CPUactivepeak/queuewait，冷600k真实iterations单独记录 |
| cache/range | root `BenchmarkDecryptedV3...`，同200ms×3 | coldtiny、hot同块末尾、openprefix、1/16MiBchunk；B/op、bytesfetched/AEADcalls，不能只记录ns/op |
| scheduler | `BenchmarkProbeInterest...` | busyprovider/hotgeneration、多session引用；queue/activebounded、cancel到slotrelease延迟 |
| integration/race | 现PRjob的race包与shared独立模块测试 | HTTPexactbody与precommitbudget、noabortcurrent、无race/leak |
| rendered首帧 | 现 `test-playback-probe` 只验证measurement semantics；真实播放器1MiB/16MiB对照另artifact | TTFF须renderedframe，不以responseheader/首byte替代 |

**bench max 约束建议**：保留现单benchmark200ms×3，不用秒级全矩阵增长；新增三组bench合计墙钟预算≤3min（不是保证200ms=总耗时，Go自动校准、setup与真实600kKDF会超出）。不同key冷KDF并发矩阵最多 active=1/2、client=1/8，chunk矩阵1/16MiB、请求tiny/openprefix/seek；每组合三次即可。refused-range大seek、旧chunk超预算用fakecount测试，不生成多GiBbuffer或下载远端。CI现20min总cap不放大；单focusedfaultsuite1min、新增race目标≤3min，重编成本由已有CI承担。耗时达到预算后删多余矩阵/拆现teststep，不重试更长本地timeout。

**workflow needed判定**：普通DraftPR矩阵足够覆盖root/shared/UI；仅当新bench名称未匹配现regex、缺少resourcecounterartifact或需要新增renderedplayback实验时修改既有workflow的对应step。不得用workflow_dispatch做普通验证（会启release），不得本轮运行cloudworkflow/bench。上传环境Go/CPU/config和baseline相同runner结果；相对改善与资源上界优先，不制定跨机绝对TTFF数字。未实测之前1MiB是可实施preset候选，不是性能通过结论。

## 8. 完成定义与不承诺的能力

Stage3完成必须同时满足：Full/Chunked预算统一且beforeKDF/IO；oldreadergeometry不受新config影响；密码与scope隔离；整chunk只在认证后发布；openRange不截断clientresponse；KDF跨key有界且waitcancel不伤sharedleader。Stage4完成必须证明active registry/任务context贯通，不把dispatchpriority宣传为preemption，且新interest不会abort正常currentstream。

本方案不承诺中断正在运行的PBKDF2、不绕开AEAD整record下载、不在上游refusedRange时凭cache无成本远seek、不给无session第三方播放器自动判断播放意图、不改V3格式/迁移旧文件、不把mobile现状升级为V3兼容。本轮没有任何tests或bench实测结果。
