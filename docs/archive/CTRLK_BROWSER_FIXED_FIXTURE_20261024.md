# Ctrl+K 修复镜像真实浏览器夹具验证（2026-10-24）

## 适用范围：受控夹具，不是生产升级后验收

时间 2026-10-24 02:19:31 UTC。仅启动既有受控容器 `alist-encrypt-quota-ui-fixture-20261024`，镜像与已完整发行的 v521 相同，本机镜像 ID：

`sha256:6e4d35e9a5b8f5e542fb2610f2badf47a0d446905842e31b2b7248dc4a2560a1`

启动前核对容器原为 exited，三个挂载仅为私有夹具的 conf / configs / data，没有生产数据挂载，没有 DSN。其独立新建 Bolt 数据不代表生产数据库升级状态。本验证没有启动、停止或重建生产网关。

## 真实浏览器操作结果

使用现有 browserless Chrome 的全新独立上下文，打开该夹具根 OpenList 站点（不是 `/public/` 管理页）：

1. 通过配置中的合法上游账户向真实上游 `/api/auth/login` 登录，业务 code 200。合法 token 仅在内存中注入已从实际前端脚本核实的 `localStorage('token')`；不使用管理 JWT。
2. 真实按下 **Ctrl+K**，打开 **1 个 role=dialog 搜索对话框**。
3. 在可见搜索框输入同一基线关键字 `SNOS229`，按 Enter。
4. 浏览器捕获 `/api/fs/search` 出站 **Authorization 存在**；修复夹具返回 **HTTP 200 / 业务 code 200**，`guest_disabled=false`。
5. 实际界面中 **不存在 `Guest user is disabled` 错误**。
6. 用同一 token 和刚刚捕获的精确浏览器搜索请求体直连上游，返回 **HTTP 200 / 业务 code 200**。

这与 `CTRLK_BROWSER_BASELINE_20261024.md` 的旧生产代理结果（同样请求携带 Authorization，但代理业务 401、实际 UI 显示 guest-disabled）形成真实浏览器对照，证明修复镜像的搜索会话转发在受控夹具中生效。搜索返回空内容也属于成功响应；本次不输出搜索正文，不据此宣称任何缺失媒体已恢复。

## 安全边界与收尾

- 浏览器只允许夹具来源 GET / HEAD 和既定只读语义 POST：`/api/auth/login`、`/api/fs/search`、`/api/fs/list`、`/api/fs/get`。所有未知 POST、PUT / PATCH / DELETE 与媒体扩展路径禁止；最终搜索过程 blocked 列表为空。
- 不允许管理容量、回收站 prepare / clear、上传、删除或媒体内容下载。本次没有触发这些请求。
- 未输出 token、凭据、文件列表或未脱敏截图；未验收登录表单本身。
- 所创建的独立浏览器上下文与连接在 finally 中关闭。
- 同一夹具容器在 finally 中正常停止，stop exit 0；最终 **Status exited / ExitCode 0**。

生产部署后仍须在生产入口重复验证，本夹具结果不能代签生产验收。
