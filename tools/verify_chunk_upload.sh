#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

# 避免受宿主机缓存目录权限影响
export GOCACHE="${GOCACHE:-/tmp/go-build-cache}"
mkdir -p "${GOCACHE}"

echo "[1/3] 验证分片上传加密偏移..."
go test ./internal/proxy -run 'TestProxyUploadEncryptUsesStartOffsetForChunkedUpload|TestProxyUploadEncryptMultiChunkOffsetsRebuildFullCiphertext' -count=1

echo "[2/3] 验证上传 size/Content-Range 解析..."
go test ./internal/handler -run 'TestResolveUploadFileSizeByContentRange|TestParseContentRangeStart|TestParseContentRangeStartInvalid' -count=1

echo "[3/3] 验证策略观测统计出口..."
go test ./internal/handler -run 'TestGetSelectorStats|TestStrategySelectorStatsIncludesObservability' -count=1

echo "OK: 分片上传与策略观测关键链路测试通过"
