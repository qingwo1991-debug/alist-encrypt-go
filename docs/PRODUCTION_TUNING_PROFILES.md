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

## 观测重点

- `stream.strategy_reason_counts`: 策略降级原因聚合。
- `stream.provider_strategy`: 当前各 provider 实时策略。
- `stream.recent_strategy_events`: 最近策略切换事件。
- `proxy.file_size_resolver.hot_cache_hits`: 热缓存命中情况。
