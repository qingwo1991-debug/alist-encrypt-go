import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'admin_auth_manager.dart';

/// OpenList 管理 API 客户端
///
/// 认证方式：通过 AdminAuthManager 获取统一 token（不自行管理密码）。
///
/// API：
/// - GET /api/admin/storage/list
/// - POST /api/admin/storage/create
/// - POST /api/admin/storage/delete
class OpenListApiClient {
  final Dio _dio;
  final String _baseUrl;
  final AdminAuthManager _authManager;
  final Future<String?> Function()? _tokenProvider;

  OpenListApiClient({
    required String baseUrl,
    AdminAuthManager? authManager,
    Dio? dio,
    Future<String?> Function()? tokenProvider,
    int connectTimeout = 5,
    int receiveTimeout = 10,
  })  : _baseUrl = baseUrl,
        _authManager = authManager ?? AdminAuthManager.instance,
        _tokenProvider = tokenProvider,
        _dio = dio ??
            Dio(BaseOptions(
              connectTimeout: Duration(seconds: connectTimeout),
              receiveTimeout: Duration(seconds: receiveTimeout),
              sendTimeout: Duration(seconds: 60),
            ));

  /// 唯一认证入口：从 AdminAuthManager 获取 token
  Future<String?> _getToken() =>
      _tokenProvider != null ? _tokenProvider() : _authManager.getToken();

  Future<Response> _authRequest(
    String method,
    String path, {
    Map<String, dynamic>? data,
  }) async {
    final token = await _getToken();
    if (token == null || token.isEmpty) {
      throw AuthException(
        AuthFailureReason.notConfigured,
        '未录入 OpenList 管理员密码，无法调用管理 API。\n请先输入当前密码校验；如果密码不一致，再到 OpenList 页面重置。',
      );
    }
    final headers = {'Authorization': token};
    final url = '$_baseUrl$path';
    try {
      final resp = await (method == 'GET'
          ? _dio.get(url, options: Options(headers: headers))
          : _dio.post(url, data: data, options: Options(headers: headers)));
      final payload = resp.data;
      if (payload is Map<String, dynamic>) {
        final code = payload['code'];
        if (code is int && code != 200) {
          throw ApiException(
            code,
            payload['message']?.toString() ?? 'OpenList API 调用失败',
            payload['data'],
          );
        }
      }
      return resp;
    } on DioException catch (e) {
      final statusCode = e.response?.statusCode ?? 0;
      if (statusCode == 401 || statusCode == 403) {
        _authManager.invalidate();
        throw AuthException(
          AuthFailureReason.invalidCredentials,
          'OpenList 管理员密码认证失败，无法调用管理 API。\n请重新输入正确密码；如果当前密码确实已变更，再到 OpenList 页面重置。',
        );
      }
      rethrow;
    } on ApiException {
      rethrow;
    }
  }

  Future<List<Map<String, dynamic>>> listStorages() async {
    try {
      final resp = await _authRequest(
        'GET',
        '/api/admin/storage/list?page=1&per_page=1000',
      );
      final data = resp.data;
      if (data is Map<String, dynamic> && data['code'] == 200) {
        final storages = data['data']?['content'] as List<dynamic>?;
        if (storages != null) {
          return storages.map((s) => s as Map<String, dynamic>).toList();
        }
      }
      return [];
    } on AuthException {
      rethrow;
    } on ApiException {
      rethrow;
    } catch (e) {
      debugPrint('[OpenListApiClient] listStorages error: $e');
      return [];
    }
  }

  Future<Map<String, dynamic>?> createLocalStorage({
    required String localPath,
    required String name,
    required String mountPath,
  }) async {
    try {
      final resp = await _authRequest(
        'POST',
        '/api/admin/storage/create',
        data: {
          'mount_path': mountPath,
          'driver': 'Local',
          'order': 0,
          'remark': name,
          'addition': json.encode({
            'root_folder_path': localPath,
            'thumbnail': false,
            'thumb_cache_folder': '',
            'show_hidden': true,
            'mkdir_perm': '777',
            'recycle_bin_path': 'delete permanently',
          }),
          'enable_sign': false,
          'order_by': '',
          'order_direction': '',
          'extract_folder': '',
          'web_proxy': false,
          'webdav_policy': 'native_proxy',
        },
      );
      final data = resp.data;
      if (data is Map<String, dynamic> && data['code'] == 200) {
        return data['data'] as Map<String, dynamic>?;
      }
      return null;
    } on AuthException {
      rethrow;
    } on ApiException {
      rethrow;
    } catch (e) {
      debugPrint('[OpenListApiClient] createLocalStorage error: $e');
      return null;
    }
  }

  Future<bool> deleteStorage(int id) async {
    try {
      final resp = await _authRequest(
        'POST',
        '/api/admin/storage/delete?id=$id',
      );
      final data = resp.data;
      return data is Map<String, dynamic> && data['code'] == 200;
    } on AuthException {
      rethrow;
    } on ApiException {
      rethrow;
    } catch (e) {
      debugPrint('[OpenListApiClient] deleteStorage error: $e');
      return false;
    }
  }

  Future<Map<String, dynamic>?> getStorage(int id) async {
    try {
      final resp = await _authRequest('GET', '/api/admin/storage/get?id=$id');
      final data = resp.data;
      if (data is Map<String, dynamic> && data['code'] == 200) {
        return data['data'] as Map<String, dynamic>?;
      }
      return null;
    } on AuthException {
      rethrow;
    } on ApiException {
      rethrow;
    } catch (e) {
      debugPrint('[OpenListApiClient] getStorage error: $e');
      return null;
    }
  }

  Future<bool> updateStorage(Map<String, dynamic> storage) async {
    try {
      final resp = await _authRequest(
        'POST',
        '/api/admin/storage/update',
        data: storage,
      );
      final data = resp.data;
      return data is Map<String, dynamic> && data['code'] == 200;
    } on AuthException {
      rethrow;
    } on ApiException {
      rethrow;
    } catch (e) {
      debugPrint('[OpenListApiClient] updateStorage error: $e');
      return false;
    }
  }

  Future<bool> ping() async {
    try {
      final resp = await _dio.get(
        '$_baseUrl/ping',
        options: Options(
          sendTimeout: const Duration(seconds: 2),
          receiveTimeout: const Duration(seconds: 2),
        ),
      );
      final code = resp.statusCode ?? 0;
      return code >= 200 && code < 500;
    } catch (e) {
      debugPrint('[OpenListApiClient] ping error: $e');
      return false;
    }
  }
}

class AuthException implements Exception {
  final AuthFailureReason reason;
  final String message;
  AuthException(this.reason, this.message);
  @override
  String toString() => message;
}

class ApiException implements Exception {
  final int code;
  final String message;
  final Object? data;

  ApiException(this.code, this.message, [this.data]);

  @override
  String toString() => 'OpenList API($code): $message';
}

enum AuthFailureReason {
  notConfigured,
  invalidCredentials,
}
