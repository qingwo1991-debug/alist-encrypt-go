import 'dart:math';

import '../contant/log_level.dart';
import '../contant/native_bridge.dart';

class AppLogger {
  AppLogger._();

  static final Random _random = Random();

  static String newTraceId(String scope, {String? entityId}) {
    final ts = DateTime.now().millisecondsSinceEpoch.toRadixString(36);
    final rand = _random.nextInt(1 << 20).toRadixString(36);
    final entity = entityId == null || entityId.isEmpty ? '' : '-$entityId';
    return '$scope$entity-$ts-$rand';
  }

  static Future<void> trace(String msg) => _write(LogLevel.trace, msg);
  static Future<void> debug(String msg) => _write(LogLevel.debug, msg);
  static Future<void> info(String msg) => _write(LogLevel.info, msg);
  static Future<void> warn(String msg) => _write(LogLevel.warn, msg);
  static Future<void> error(String msg) => _write(LogLevel.error, msg);

  static Future<void> _write(int level, String msg) async {
    try {
      await NativeBridge.common.writeAppLog(level, msg);
    } catch (_) {
      // Keep logging best-effort only.
    }
  }
}
