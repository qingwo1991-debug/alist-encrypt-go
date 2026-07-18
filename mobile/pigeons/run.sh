#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOBILE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
cd "$MOBILE_ROOT"

# 生成 Pigeon 桥接代码
flutter pub run pigeon \
  --input pigeons/pigeon.dart \
  --dart_out lib/generated_api.dart \
  --java_out android/app/src/main/java/com/openlist/pigeon/GeneratedApi.java \
  --java_package "com.openlist.pigeon"

echo "Pigeon code generated successfully!"
