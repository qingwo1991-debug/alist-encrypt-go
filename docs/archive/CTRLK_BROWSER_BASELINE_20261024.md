# Ctrl+K 真实浏览器旧生产基线（2026-10-24）

## 范围与结果

2026-10-24 02:17:19 UTC，使用现有 browserless Chrome 的全新独立浏览器上下文，打开**升级前生产旧代理**根站点（不是 `/public/` 管理界面）。

1. 通过当前配置的合法上游账户向上游 `/api/auth/login` 登录，业务 code 200。凭据和 token 仅在进程内存中，不写入文档或日志。
2. 从当前实际静态脚本核实 OpenList 使用 `localStorage.getItem('token')` 设置 Axios 的 `Authorization`，将上述合法上游会话注入该新上下文；没有使用管理 JWT 或借用管理员网关认证。
3. 浏览器真实发送 **Ctrl+K**，出现 **1 个 role=dialog 搜索对话框**。向可见搜索框输入既定核验关键字 `SNOS229`，按 Enter。
4. 浏览器网络捕获确认 `/api/fs/search` 出站 **Authorization 存在**；旧代理返回 **HTTP 200 / 业务 code 401**，消息属于 `Guest user is disabled`。
5. 实际界面呈现 `Guest user is disabled` / `login please` 错误，而非仅凭 API 推断 UI。
6. 使用**同一 token、浏览器刚刚发出的精确搜索请求体**直连上游对照：**HTTP 200 / 业务 code 200**。

因此旧生产环境故障已在真正的浏览器操作中复现：搜索入口本身可以打开、客户端已经携带合法上游会话，但经旧代理后认证失败。此记录不等于修复后浏览器验收；部署后必须重复同样动作并核对新结果。

## 请求约束及清理

- 浏览器仅允许该旧代理来源的 GET / HEAD，以及 `/api/auth/login`、`/api/fs/search`、`/api/fs/list`、`/api/fs/get` 的只读语义 POST。
- 所有其他 POST 和 PUT / PATCH / DELETE 均拦截；媒体扩展路径也拦截。没有上传、下载媒体内容、回收站 prepare / clear 或云写操作。
- 最初尝试实际登录表单时发现前端使用 `/api/auth/login/hash`，该路径被既定严格允许列表拒绝，未放宽允许范围。因此本次采用已核实存储键注入合法上游会话，不声称验收了登录表单。
- 没有输出目录文件名、账号、密码、token、搜索响应正文或未脱敏截图。
- 每次结束都关闭自己的上下文和所创建浏览器连接；不操作其他用户浏览器上下文。
- 本轮没有修改生产配置或重启服务。
