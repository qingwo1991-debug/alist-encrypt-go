# 未知目录快照不能伪装为空目录（2026-10-24）

## 独立复现，不冒认现场事故根因

生产第一次目录斜杠请求只返回自身、557 字节，随后暖后两种路径均恢复 1823 项。首次没有保存来源头或原始 XML，因此无法把现场现象确认为本缺陷；原始失败证据继续保留在 `DAV_PRODUCTION_ACCEPTANCE_20261024.md`。

源代码和无网络夹具可独立复现：`code:200` 但 data / content 缺失或 null，旧验证器将其转换为 nil 并接受；DAV 构建器随后输出仅目录自身的成功 multistatus。未知、畸形列表不是已证明的空目录。

## 修复与范围

独立工作树分支 `agent/dav-snapshot-shape-20261024`，精确提交：

`f0f03c49c00de52d299efcebf8f9ec074dceb68e`

[Draft PR111](https://github.com/qingwo1991-debug/alist-encrypt-go/pull/111)，完整矩阵 run `40056023133` **进行中，尚未合并或部署**。

三个文件变更：

- `internal/handler/dirsync.go`：共享解码契约要求业务 code 200、对象 data、显式数组 content；子项必须是对象，具有非空字符串 name 和布尔 is_dir。无法证明结构时拒绝缓存并回源，不跳过坏行后假装成功。
- `internal/handler/webdav_dirsync.go`：直接构建器使用同一契约，HTTP / DAV 两个保存入口也拒绝畸形结构。空内容与正数缓存 ItemCount 矛盾时拒绝。
- `internal/handler/dirsync_shape_test.go`：七组回归，约 20 种坏结构，包含 null、缺字段、类型错误和有效行混入坏行。

保留合法显式 `content:[]`；不盲目要求 `total == len(content)`，因为过滤 / 分页后的 total 可以不同。原 provider、auth、path、scope 检查保持不变。当前 OpenList 的 ObjResp 明确输出布尔 `is_dir`，无 omitempty，因此严格字段契约兼容正常上游。旧畸形缓存只失去命中并回源，不修改文件、claim 或数据库结构。

## 回归与独立审查

先加回归、旧代码重现 self-only，再实施修复。定向和扩展快照测试均通过；最终斜杠补强后的相关测试耗时 0.225 秒，gofmt 与 diff check 通过。

DAV 夹具双向覆盖：带斜杠冷请求回源后，不带斜杠暖请求命中；反向同样成立。每次断言恰好 self + child 两个 response、首次无 dir-snapshot 头而第二次命中、仅一次上游调用。另覆盖 HTTP 同 auth scope 的坏缓存回源及两个写入端不保存畸形内容。

独立审查精确最终头未发现 P0 / P1。审查者尝试本地 race，在 60 秒宿主编译期限内无输出而被终止，**不是通过也不是已知测试失败**；按仓库政策没有反复延长本地重编。PR 完整矩阵的现有 handler race 门禁必须完成，不能用旧提交的绿灯替代。

生产仍是固定 v521，没有热替换该修复；不释放失败预留，不修改或删除云文件，不调用回收站。
