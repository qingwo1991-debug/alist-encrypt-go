import 'package:dio/dio.dart';

/// Page-owned login session for the Go server, never the DB_EXPORT account.
/// The origin is immutable and no redirect may carry credentials or a JWT.
class DirSyncRemoteSession {
  DirSyncRemoteSession(String baseUrl, {Dio? dio})
      : origin = parseOrigin(baseUrl),
        _dio = dio ?? Dio(BaseOptions(
          connectTimeout: const Duration(seconds: 4),
          receiveTimeout: const Duration(seconds: 8),
          sendTimeout: const Duration(seconds: 8),
        ));

  final Uri origin;
  final Dio _dio;
  CancelToken _cancelToken = CancelToken();
  String? _token;
  bool _disposed = false;
  int _generation = 0;

  bool get isAuthenticated => !_disposed && _token != null;

  static Uri parseOrigin(String value) {
    final uri = Uri.tryParse(value.trim());
    if (uri == null || !uri.hasAuthority || uri.host.isEmpty ||
        !['http', 'https'].contains(uri.scheme) || uri.userInfo.isNotEmpty ||
        uri.hasQuery || uri.hasFragment ||
        (uri.path.isNotEmpty && uri.path != '/') ||
        uri.port < 1 || uri.port > 65535) {
      throw const FormatException('请输入远端服务器源地址（http/https + 主机和端口，不含路径、账号或查询参数）');
    }
    return Uri.parse(uri.origin);
  }

  Future<void> login(String username, String password) async {
    logout();
    final generation = _generation;
    final data = await _request('/enc-api/login', method: 'POST', data: {
      'username': username,
      'password': password,
    });
    final token = data['jwtToken'];
    if (_disposed || generation != _generation) return;
    if (token is! String || token.trim().isEmpty ||
        token.contains('\r') || token.contains('\n')) {
      throw const DirSyncRemoteException('登录失败：服务器未返回有效 JWT');
    }
    _token = token;
  }

  Future<Map<String, dynamic>> overview() =>
      _authenticatedRequest('/api/encrypt/dir-sync/overview');

  Future<void> run() async {
    await _authenticatedRequest('/api/encrypt/dir-sync/run', method: 'POST');
  }

  Future<Map<String, dynamic>> _authenticatedRequest(String path,
      {String method = 'GET'}) {
    if (!isAuthenticated) {
      throw const DirSyncRemoteException('请先登录此远端服务器');
    }
    return _request(path, method: method, token: _token);
  }

  Future<Map<String, dynamic>> _request(String path,
      {String method = 'GET', Object? data, String? token}) async {
    if (_disposed) throw const DirSyncRemoteException('页面已关闭');
    try {
      final response = await _dio.requestUri(
        origin.resolve(path),
        data: data,
        cancelToken: _cancelToken,
        options: Options(
          method: method,
          followRedirects: false,
          maxRedirects: 0,
          validateStatus: (_) => true,
          headers: token == null ? const {} : {'Authorization': 'Bearer $token'},
          contentType: Headers.jsonContentType,
        ),
      );
      final status = response.statusCode ?? 0;
      final root = response.data;
      final code = root is Map ? root['code'] : null;
      if (status == 401 || status == 403 || code == 401 || code == 403) {
        logout();
        throw const DirSyncRemoteException('登录已失效或没有权限，请重新登录此远端服务器');
      }
      if (status >= 300 && status < 400) {
        throw const DirSyncRemoteException('已拒绝服务器重定向，请确认正确的远端源地址');
      }
      if (status < 200 || status >= 300 || root is! Map || code != 0) {
        // Do not surface raw responses/transport exceptions: they may echo
        // credentials, request headers, or private server details.
        throw DirSyncRemoteException(path == '/enc-api/login'
            ? '登录失败，请检查此服务器的账号和密码'
            : '远端请求失败（HTTP $status）');
      }
      final payload = root['data'];
      return payload is Map<String, dynamic> ? payload : <String, dynamic>{};
    } on DioException {
      throw const DirSyncRemoteException('无法连接远端服务器，请检查地址、网络和 TLS 证书');
    }
  }

  void logout() {
    _generation++;
    _token = null;
    _cancelToken.cancel();
    _cancelToken = CancelToken();
  }

  void dispose() {
    _disposed = true;
    logout();
    _dio.close(force: true);
  }
}

class DirSyncRemoteException implements Exception {
  const DirSyncRemoteException(this.message);
  final String message;
  @override
  String toString() => message;
}
