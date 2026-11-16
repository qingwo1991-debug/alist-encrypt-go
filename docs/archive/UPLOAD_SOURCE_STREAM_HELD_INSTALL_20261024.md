# 来源流修复已安装，上传服务仍暂停（2026-10-24）

这是 `UPLOAD_SOURCE_STREAM_FROZEN_REVIEW_20261024.md` 暂存审查之后的独立后续记录，不把先前“尚未安装”的事实改写为当时已部署。

## 协调安装

三个源文件在上传器及夜间控制器均暂停、批准 sentinel 不存在、无上传器进程时协调替换。安装及测试前后摘要均与冻结审查版完全一致：

| 实际文件 | SHA256 |
| --- | --- |
| `/root/script/alistauto2.0/alist_uploader.py` | `2fc4d0d03fc84ec00988c31a0877350ea41a08cdcfcaf48d8f20127f4bebb1c8` |
| `/root/script/media_safety.py` | `2dd6f1f6957d7b7a83bda8e67ffcf8f6b9c871a69a3d49e75fe3364b0cec45f4` |
| `/root/script/upload_source_guard.py` | `034d8e06f325f8fd318f7ba638c413440b751cea6dbb4cb7b816ada9bca5e4a7` |

父代理独立核对三文件及条件门禁摘要。原始 uploader / validator 已以 O_EXCL、fsync 留在实际 0700 私有目录，备份实际 0600；不公开含历史敏感字段的完整上传器或备份。

全解码不能再被旧 false 配置关闭；固定 FD 解码、整文件 / 分块 SHA、发送前验证完整块、非重放 reader、边界复核、锁与 finally 清理均已安装。共享 validator 的 `source_fd=None` 保持未传 FD 调用者原先行为，未重启其他 worker。

## 安装路径实际测试

使用服务自身 `/opt/cf_bastip/venv/bin/python3`，Python 3.11.2 / Requests 2.32.5：

- 三文件 py_compile 通过。
- 安装路径 66 项收据、容量、上下文、全解码、review 与删源回归通过 **1.033 秒**；父代理独立重跑 **1.020 秒**，安装前后摘要不变。
- 安装路径 16 项来源流 AST / 假传输 + 1 项真实 Requests 本机 loopback 回归通过，合计 **2.976 秒**。稳定源完整收到 2,097,152 字节；晚变源只收到正确首个 1,048,576 字节，损坏后块零字节送达，返回 submit_failed + stop_round。
- 共 **83 项**，不是 83 次真实媒体解码。既有夹具适配仍明确：固定 guard / 接受指纹 / Mock 初始绑定 / 模拟 durable receipt / 假解码。初次 17 项运行暴露私有选择器误将共享 validator 定位到 uploader 子目录，修正测试路径后通过，没有因此改生产代码。

确认实际导入的共享 media / guard 均来自 `/root/script`，AST 读取实际 uploader 路径，没有静默使用暂存实现。完整安全报告和可复现选择器另存本地 `upload-stream-install-20261024`；未公开完整上传器。

## 持续保护与未完事项

安装后 `alist-uploader.service` 仍 inactive/dead、ConditionResult=no；夜间 timer 和 service 均 inactive；批准 sentinel 不存在、无上传器进程。持久 drop-in 摘要仍为 `2a32bd82d61f90facba5c2f7fb325526e701cbda518824a7d24a84b23a438cc4`。**未调用 systemctl start，未恢复服务。**

未运行真实媒体解码、真实云上传或生产数据库修改；网络回归只用禁代理的 127.0.0.1 合成数据。源流一致性保护不保证云 PUT 原子性，可能留下正确前缀构成的部分对象及 failed 独占声明，不自动删除或释放。

Torrent 来源及完整 piece 真实性的持久证明尚未实现，见 `TORRENT_SOURCE_PROOF_FOLLOWUP_20261024.md`；它与完整远端读回 / 收据 / 删源门槛、实际恢复验收仍是独立事项。**已安装不等于整体已修复，也不是恢复上传授权。**
