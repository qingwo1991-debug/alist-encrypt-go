# 分片上传验证说明

本文档用于验证本次修复涉及的分片上传与加密偏移链路。

## 快速验证

在仓库根目录执行：

```bash
bash tools/verify_chunk_upload.sh
```

脚本会依次验证：

1. 分片上传时加密偏移是否与全文件密文一致。
2. `Content-Range` / 上传尺寸解析是否稳定。
3. 策略观测统计（失败原因、provider 策略、事件）是否可读。

## 全量回归

```bash
go test ./...
```

建议在合并前至少执行一次全量回归。

## 生产环境建议

1. 开启 `/api/stats` 观察 `stream.strategy_reason_counts` 与 `stream.provider_strategy`。
2. 上传链路出现不稳定时，先看 `reason_counts` 是否集中在 `timeout/network_error/upstream_5xx`。
3. 先跑 `tools/verify_chunk_upload.sh`，再做线上参数调整，避免把配置问题误判成代码回归。
