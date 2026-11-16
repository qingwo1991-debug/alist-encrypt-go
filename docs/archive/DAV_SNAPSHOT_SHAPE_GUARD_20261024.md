# 未知目录快照不能伪装为空目录（2026-10-24）

## 独立复现，不冒认现场事故根因

生产第一次目录斜杠请求只返回自身、557 字节，随后暖后两种路径均恢复 1823 项。首次没有保存来源头或原始 XML，因此无法把现场现象确认为本缺陷；原始失败证据继续保留在 `DAV_PRODUCTION_ACCEPTANCE_20261024.md`。

源代码和无网络夹具可独立复现：`code:200` 但 data / content 缺失或 null，旧验证器将其转换为 nil 并接受；DAV 构建器随后输出仅目录自身的成功 multistatus。未知、畸形列表不是已证明的空目录。

## 修复与范围

独立工作树分支 `agent/dav-snapshot-shape-20261024`，精确提交：

`f0f03c49c00de52d299efcebf8f9ec074dceb68e`

[PR111](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/111) 的精确头完整矩阵 run `40056023133` 已成功，随后 squash 合并为 main `d4c6de044fb1d4d5711a632ed3d79a18655db910`；对应 main run `40057106864` 亦完整成功。后续仅文档合并 main `e8d333e0815cdb5c458633fdd2be75c092b67adb` 的 run `40057672706` 也已成功。两个临时分支已按门禁清理，但独立代码工作树保留在精确旧头的 detached 状态。**仍未将该修复部署到生产**。

三个文件变更：

- `internal/handler/dirsync.go`：共享解码契约要求业务 code 200、对象 data、显式数组 content；子项必须是对象，具有非空字符串 name 和布尔 is_dir。无法证明结构时拒绝缓存并回源，不跳过坏行后假装成功。
- `internal/handler/webdav_dirsync.go`：直接构建器使用同一契约，HTTP / DAV 两个保存入口也拒绝畸形结构。空内容与正数缓存 ItemCount 矛盾时拒绝。
- `internal/handler/dirsync_shape_test.go`：七组回归，约 20 种坏结构，包含 null、缺字段、类型错误和有效行混入坏行。

保留合法显式 `content:[]`；不盲目要求 `total == len(content)`，因为过滤 / 分页后的 total 可以不同。原 provider、auth、path、scope 检查保持不变。当前 OpenList 的 ObjResp 明确输出布尔 `is_dir`，无 omitempty，因此严格字段契约兼容正常上游。旧畸形缓存只失去命中并回源，不修改文件、claim 或数据库结构。

## 回归与独立审查

先加回归、旧代码重现 self-only，再实施修复。定向和扩展快照测试均通过；最终斜杠补强后的相关测试耗时 0.225 秒，gofmt 与 diff check 通过。

DAV 夹具双向覆盖：带斜杠冷请求回源后，不带斜杠暖请求命中；反向同样成立。每次断言恰好 self + child 两个 response、首次无 dir-snapshot 头而第二次命中、仅一次上游调用。另覆盖 HTTP 同 auth scope 的坏缓存回源及两个写入端不保存畸形内容。

独立审查精确最终头未发现 P0 / P1。审查者尝试本地 race，在 60 秒宿主编译期限内无输出而被终止，**不是通过也不是已知测试失败**；按仓库政策没有反复延长本地重编。随后该精确头的云端完整矩阵及 handler race 门禁已成功，不能把这个云端结果改写成本地 race 已通过。

生产仍是固定 v521，没有热替换该修复；不释放失败预留，不修改或删除云文件，不调用回收站。

## 已核对但尚未拉取 / 部署的发行候选

main 文档后继 `e8d333e0815cdb5c458633fdd2be75c092b67adb` 对应发行 `v2026.10.24.532`；main 完整工作流 `40057672706` 成功。只读 registry 核对得到索引 `sha256:6adc255490947b0ceb384ab9527140344e602d4383dffd9c08623b7982754a44`，amd64 manifest `sha256:a78dda35e7d54a5c4d0958ed5842073208939053fb353d782435fda9e57ef730`，两架构配置的 revision 标签均为该 main 提交。此处仅绑定源码与候选摘要，尚未拉取镜像或改 compose，更不是生产验收。发布 tag 是 GitHub 发行 tag，不能假定 registry 有同名 `v2026.10.24.532` 镜像 tag；工作流实际发布 `main` / `latest`，后续只能使用已核对固定摘要。

下一次单服务切换仍必须等当前测量结束、完整交付收据和自然空闲，重新建立停写后的冷备份 / 监控锁，并保留旧固定镜像及数据库状态。旧冷备份不能替代新切换时点的停写快照；不在实时浸泡测量中重启或切换被测服务。
