# 生产调优建议

本次版本重点覆盖了加解密、视频播放和分片上传链路。以下参数可按场景调整。

## 场景 A：优先稳定（公网波动明显）

- `rangeFailToDowngrade`: `2`
- `rangeSuccessToRecover`: `5`
- `rangeReprobeMinutes`: `30`
- `rangeProbeTimeoutSeconds`: `8-12`
- `probeConcurrency`: `2-4`

效果：更快降级，恢复更保守，抖动场景更稳。

## 场景 B：优先性能（局域网/优质链路）

- `rangeFailToDowngrade`: `3`
- `rangeSuccessToRecover`: `3`
- `rangeReprobeMinutes`: `10-20`
- `rangeProbeTimeoutSeconds`: `5-8`
- `probeConcurrency`: `4-8`

效果：更积极维持 Range，提升拖拽与首播体验。

## 场景 C：上传高峰（大文件批量）

- 保持上传端 `Content-Range` + 总大小头完整。
- 按磁盘与网络情况控制分片并发，不建议一次拉满。
- 优先观察 `/api/stats` 的 `stream.strategy_reason_counts`，避免错误放大。

## 跨端分开考虑：`TUNING_PROFILE`

Docker 是 24h 在线的服务，移动端与 exe 却不一定。两者对后台探活与预热的资源取向应不同——用**一个**环境变量按部署形态施加一致的基准调优，无需手调十几 key；显式设置的 `PROBE_*` / `RANGE_*` / `MAX_ACTIVE_STREAMS` 等仍优先（profile 只是基准）。

- `TUNING_PROFILE=server`（默认/空）：24h 在线服务。保持出厂 aggressive 默认（积极后台预热、快速 Range 恢复）。
- `TUNING_PROFILE=client`（`mobile` / `exe` 为别名）：偶尔联网的移动端/exe。更保守的 Range 恢复（`rangeSuccessToRecover=5`）、更轻的后台预热（并发 2、队列 250、更长冷却）、更小的解密块缓存（64MB）、更少并发流（8）。

```bash
# 移动端 / exe / 桌面终端
TUNING_PROFILE=client ./alist-encrypt-go
```

## 观测重点

- `stream.strategy_reason_counts`: 策略降级原因聚合。
- `stream.provider_strategy`: 当前各 provider 实时策略。
- `stream.recent_strategy_events`: 最近策略切换事件。
- `proxy.file_size_resolver.hot_cache_hits`: 热缓存命中情况。
