# Ctrl+K 升级后生产真实浏览器验收（2026-10-24）

## 生产版本核对

在父代理明确发出 READY、完成受控部署后，于 **2026-10-24 02:30:20 UTC** 执行本次验收。浏览器访问实际生产容器 `alist-encrypt` 的根 OpenList 站点，而非历史副本、临时夹具或 `/public/` 管理页面。

操作前独立核对：

- 本机运行镜像 ID：`sha256:6e4d35e9a5b8f5e542fb2610f2badf47a0d446905842e31b2b7248dc4a2560a1`，与固定 v521 候选一致。
- Health：healthy；RestartCount：0。
- `com.centurylinklabs.watchtower.enable=false`。

## 真实键盘操作与网络结果：通过

1. 通过当前配置的合法上游用户调用上游 `/api/auth/login`，取得业务 code 200 的新会话。
2. 在 browserless Chrome 的全新独立上下文，向已核实的 OpenList `localStorage('token')` 注入该合法上游 token。凭据、token 均只在进程内存中，未写入报告或输出；没有使用管理 JWT。
3. 打开生产根站点，真实按下 **Ctrl+K**，出现 **1 个 role=dialog 搜索对话框**。
4. 在可见搜索框输入原基线相同的 `SNOS229`，按 Enter。
5. 浏览器网络捕获 `/api/fs/search`：出站 **Authorization 存在**，响应 **HTTP 200 / 业务 code 200**，`guest_disabled=false`。
6. 实际生产界面**没有出现 `Guest user is disabled` 错误**。
7. 使用同一 token 与刚刚捕获的精确浏览器搜索请求体直连上游，返回 **HTTP 200 / 业务 code 200**。

搜索响应内容可能为空，成功不等于找回缺失媒体。本次不输出搜索结果正文、对象路径或目录文件名。

## 与旧生产的可比基线

`CTRLK_BROWSER_BASELINE_20261024.md` 记录相同浏览器流程下旧生产代理的失败：Ctrl+K 可打开、客户端携带 Authorization，但代理响应业务 401，实际 UI 显示 guest-disabled；同一会话直连上游业务 200。

`CTRLK_BROWSER_FIXED_FIXTURE_20261024.md` 先验证固定修复镜像的受控夹具。此次进一步在**已部署生产入口**得到业务 200 且 UI 不报错，不再仅依赖单元测试或夹具结果。验收范围是合法上游会话的 Ctrl+K 搜索转发；不宣称验收登录表单本身、游客权限或搜索结果完整性。

## 请求安全限制与清理

- 浏览器仅允许生产网关来源的 GET / HEAD 和既定只读语义 POST：`/api/auth/login`、`/api/fs/search`、`/api/fs/list`、`/api/fs/get`。
- 所有其他 POST、PUT / PATCH / DELETE 及媒体扩展路径禁止。搜索过程中 blocked 列表为空。
- 没有容量、回收站 prepare / clear、媒体下载、上传或删除请求。
- 无截图、token、密码、账号或未脱敏正文输出。
- 自己创建的独立浏览器上下文及连接在 finally 中关闭。
- 本验收子任务没有启动、停止、重建生产容器，也没有修改配置或调度器。

**结论：升级后生产合法会话 Ctrl+K 搜索浏览器验收通过。** 其他 DAV、容量、回收站取消、媒体恢复及播放性能事项应分别依据各自证据判断。
