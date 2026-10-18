# 本机坏媒体验收与恢复执行记录

## 已确认故障

- SNOS-397.part001：有限读取范围约2MiB至19MB为零，视频sample表仍声明有效帧；三处密文直读独立AES解密复核同样全零。part003/004在本机上传前已是262字节空壳。旧上传器仍判成功并删源。
- IPZZ-172_FHD_CH.mp4：明文2061432089字节，moov位于2051740507、大小9691582字节；moov相对1380147、2754107处是全零结构，正常box链中断，后续轨道与stco不能按容器树访问。两处独立上游密文解密复核全零。播放器跳过与损坏容器一致，不是外挂字幕404或此次代理Range偏移造成。
- 不声称已证明零数据最早由下载、入库还是分割哪一步产生；当时搬移日志确有rpc_completed，不能反过来伪称已证明任务未下载完。

## 已部署本机修复

应用前四份旧源码已私下备份，包含旧源码内历史凭据，不公开。

| 实际模块 | 新保护 |
|---|---|
| `/root/script/downloader_backend.py` | 真正终态complete、逐个selected文件完成、拒绝metadata/followedBy假完成；三路RPC完整快照失败关闭 |
| `/root/script/downloads_to_movies.py` | 同目录未完成任务阻断；只搬精确归属文件；验证前后重新核对状态和指纹；无效源/侧车/孤儿保留，不自动删除；不覆盖发布 |
| `/root/script/media_safety.py` | MP4完整box边界及样本表结构检查、头中尾包/零内容/解码检查；最终上传强制全文件音视频严格解码，不仅抽样 |
| `/root/script/alistauto2.0/alist_uploader.py` | 源/分片有效性、时长一致、完整manifest；提交与验收同版本绑定；大小匹配不再提前成功；旧part001标记不得删源；失败保留；原子隔离认领后复核删源，防并发同名替换误删 |
| `/root/script/remote_media_verify.py` | 上传后完整明文SHA256回读与本地全部字节比较，短读/超长/同长不同内容均失败；独立进程硬总时限防滴流，异常不泄露签名URL |

普通上传器及chunked上传器共享修复后的父类。服务已重启，两个上传器active/running；入库timer active，最近一次oneshot正常结束。chunked原有10:00–21:00静默窗口保留，不偷偷改变调度。

实测回归：18项本地上传安全测试（含真实FFmpeg正常/坏片）、5项真实HTTP回读测试、17项入库任务测试，共40项通过。部署后live import smoke通过；stage与部署哈希逐项核对。独立审查发现的早写成功历史、验收后变更、旧proof复用、删源竞态与滴流超时均已修正并加测试。

### 冗余校验及资源代价

- 本地全文件解码能查出解码错误，但不等于证明每一个原始画面或声音语义正确，静音/黑画面等不能一概当损坏。
- 云端全量SHA256保证实际交付字节与已验收本地字节相同，不只看文件大小；代价是额外完整回读带宽和本地解码CPU，不能同时宣称零额外成本。
- 当前分片按实际时长及累计时长验收，不能将累计时长宣传成逐帧无重叠/无缺段的源时间线证明；可恢复源保留至全部分片回读完成。
- 不会承诺绝对识别世界上所有媒体问题；对超时、不完整或不能证明安全的情况默认保留，不标成功、不删源。

## 恢复下载状态（未完成，不得称已修好视频）

旧云文件没有覆盖/删除。用户已批准无法恢复就重新下载。

- SNOS-397：首个元数据任务消失后改用另一精确匹配FHD候选，约6.98GB，GID `822c253ca6c3a847`，独立目录`/downloads/recovery-snos397-20261018`，manual_keep保护。
- IPZZ-172：选择另一约8.55GB候选，GID `b72758f7d6a45dac`，独立目录`/downloads/recovery-20261018/IPZZ-172`，manual_keep保护。
- 最近状态：IPZZ任务active但totalLength0（仍未解析到有效载荷）；SNOS waiting、totalLength0，已置队首。**两者均未完成下载，更未完成媒体验收或上传。** 不能把任务提交成功当成视频恢复。
- 恢复目录成品入库使用 `_recovered_20261018` 后缀，避免与已知损坏云文件同名冲突/历史误认。
- 后续需真实piece下载完成→入库媒体验收→上传前全解码→分片验收→全量云端解密回读→实际播放验收；如片源无数据继续换源，不能冒报完成。

## 外部清理旁路补漏与真实标签后端

续轮检查实际cron发现两处可绕过上述门禁的旧脚本，已直接修正：

- `/root/AI/cloud_dedup_clean.py`：原每20分钟仅按云端大小/分片累加删除本地、写成功历史。现main安全退出，停止这类删源与历史伪成功。cron保留但执行为非破坏性安全提示，实跑通过。
- `/root/AI/download_watchdog.py`：原每10分钟直接删除mtime超过30分钟的分片，既无实际上传锁也无回读证明。现移除该清理段，删源只归上传器验收事务；AST检查main无os.remove/unlink/rmdir调用。全量解码/回读可超过30分钟，旧年龄清理尤其危险。

恢复任务标签早先写入JSON，但统一管理器真实使用**MySQL**元数据后端，JSON标签不能保护该管理器清理。现通过create_download_client(load_config())给IPZZ/SNOS当前GID写入并回读manual_keep,pin。此为确认的保护配置错误；先前GID消失具体是哪条清理仍无独立日志归因，不冒充已证明。

SNOS第三元数据GID已complete，仅120386字节，不是视频完成；其payload子GID `699aafeb41ca9c47`已开始真实下载，总1563688960字节，采样411516928字节、约1.6MB/s，已对payload在MySQL补保护。该替代源体积小于原6.5GiB源，待完成后必须核验时长、分辨率、完整内容，不以小文件冒称同画质恢复。IPZZ增加另一1.95GiB中文字幕候选 `f37c45ee652cc8e3`，独立recovery目录、创建时即MySQL保护；旧8GiB候选保留。

## 与原播放性能任务关系

PR100/main273a1fe完整发布已绿。续轮已切换固定镜像 `sha256:b7b02a5b7e4d9ae3663aad29eab13ae79c42154f86fe882963be0eafe1d649af`，容器running、RestartCount0。原固定WA-596.part003样本被已有保护作用域门禁返回404（文件仍在目录，错误体Protected filename unavailable for this scope），不能将其3ms错误响应当性能改善；Basic和JWT均复现，正定位审计记录状态。另用可读IPZZ-172进行纯HTTP协议验证：30次PF207、HEAD200、prefix206；HEAD p50/p95=2.865/8.152ms，prefix413.460/472.504ms，EOF已返回416。该文件媒体本身损坏，HTTP协议通过不代表可播放。现场配置原本关闭明文块缓存，已在`/root/docker/alist-encrypt1/conf/config.json`开启（256MiB/256KiB有界），重启后混合PF/HEAD/GET仍419.451ms。再单独连续GET12次，全部206且同一SHA256，p50降至3.718ms；日志确认混合元数据请求导致上游签名fid跨次变化，从而块缓存targetHash失配，正定位如何保持定位符而不削弱对象/鉴权隔离。原性能计划未完成且保留device_unverified。

续轮还将真实坏片头/索引映射到临时稀疏夹具（未伪称完整原件）：部署版校验器拒绝IPZZ夹具`invalid zero-sized MP4 metadata box`，拒绝SNOS夹具解码错误。SNOS第二恢复GID再次消失，已换第三候选`3dbc8f2cc6f5dae7`、目录`/downloads/recovery-snos397-alt-20261018`并保护，最近仍waiting/0字节。IPZZ仍active/0字节，无peer；未恢复完成。
