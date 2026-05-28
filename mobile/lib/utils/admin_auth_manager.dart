import '../contant/native_bridge.dart';

/// 管理 API 认证管理器（单例）
///
/// 唯一可信的 token 来源：
/// - 通过 NativeBridge.syncTaskApi.acquireAuthToken() 获取
/// - 底层复用 SyncScheduler.acquireAuthToken() → AppConfig.encryptAdminPassword
/// - 不由 LocalMount 或其他模块自己猜密码
class AdminAuthManager {
  AdminAuthManager._();
  static final AdminAuthManager _instance = AdminAuthManager._();
  static AdminAuthManager get instance => _instance;

  String? _cachedToken;
  int _expiresAt = 0; // 简单的过期策略：5 分钟内不重新请求

  /// 获取有效的管理 API token
  ///
  /// 返回 null 表示当前无法获取 token（密码未配置或登录失败）
  Future<String?> getToken() async {
    // 缓存未过期直接返回
    if (_cachedToken != null &&
        _cachedToken!.isNotEmpty &&
        DateTime.now().millisecondsSinceEpoch < _expiresAt) {
      return _cachedToken;
    }

    try {
      _cachedToken = await NativeBridge.syncTaskApi.acquireAuthToken();
      if (_cachedToken != null && _cachedToken!.isNotEmpty) {
        _expiresAt = DateTime.now().millisecondsSinceEpoch + 5 * 60 * 1000; // 5 分钟
      }
    } catch (_) {
      _cachedToken = null;
    }
    return _cachedToken;
  }

  /// 清除缓存（密码变更后调用）
  void invalidate() {
    _cachedToken = null;
    _expiresAt = 0;
  }
}
