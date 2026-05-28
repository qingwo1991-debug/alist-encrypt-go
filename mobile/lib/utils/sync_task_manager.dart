import 'dart:convert';

import 'package:flutter/foundation.dart';

import 'admin_auth_manager.dart';
import '../contant/native_bridge.dart';
import '../models/local_mount.dart';
import '../models/sync_task.dart';
import 'openlist_api_client.dart';

/// 同步任务管理器
///
/// 负责 Flutter 端的同步任务 CRUD、持久化和调度触发
class SyncTaskManager extends ChangeNotifier {
  List<SyncTask> _tasks = [];
  bool _loaded = false;

  List<SyncTask> get tasks => List.unmodifiable(_tasks);
  bool get isLoaded => _loaded;

  /// 从原生持久化存储加载所有同步任务
  Future<void> loadTasks() async {
    try {
      final json = await NativeBridge.syncTaskApi.getSyncTasksJson();
      _tasks = SyncTask.listFromJsonString(json);
      _loaded = true;
      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load sync tasks: $e');
      _tasks = [];
      _loaded = true;
      notifyListeners();
    }
  }

  /// 持久化任务列表到原生存储
  Future<void> _saveTasks() async {
    final json = SyncTask.listToJsonString(_tasks);
    await NativeBridge.syncTaskApi.setSyncTasksJson(json);
  }

  /// 添加同步任务
  Future<void> addTask(SyncTask task) async {
    _tasks.add(task);
    await _saveTasks();
    notifyListeners();

    // 如果任务已启用，调度到 WorkManager
    if (task.enabled) {
      try {
        await NativeBridge.syncTaskApi.scheduleSyncTask(
          task.id,
          json.encode(task.toJson()),
        );
      } catch (e) {
        debugPrint('Failed to schedule task ${task.id}: $e');
      }
    }
  }

  /// 更新同步任务
  Future<void> updateTask(SyncTask updated) async {
    final index = _tasks.indexWhere((t) => t.id == updated.id);
    if (index == -1) return;

    _tasks[index] = updated;
    await _saveTasks();
    notifyListeners();

    // 先取消旧调度
    try {
      await NativeBridge.syncTaskApi.cancelSyncTask(updated.id);
    } catch (_) {}

    // 如果任务仍启用，重新调度
    if (updated.enabled) {
      try {
        await NativeBridge.syncTaskApi.scheduleSyncTask(
          updated.id,
          json.encode(updated.toJson()),
        );
      } catch (e) {
        debugPrint('Failed to reschedule task ${updated.id}: $e');
      }
    }
  }

  /// 删除同步任务
  Future<void> deleteTask(String taskId) async {
    _tasks.removeWhere((t) => t.id == taskId);
    await _saveTasks();
    notifyListeners();

    // 取消 WorkManager 调度
    try {
      await NativeBridge.syncTaskApi.cancelSyncTask(taskId);
    } catch (e) {
      debugPrint('Failed to cancel task $taskId: $e');
    }
  }

  /// 立即执行同步任务
  Future<void> runTaskNow(String taskId) async {
    try {
      await NativeBridge.syncTaskApi.runSyncTaskNow(taskId);
    } catch (e) {
      debugPrint('Failed to run task $taskId now: $e');
      rethrow;
    }
  }

  /// 获取同步任务状态（JSON）
  Future<Map<String, dynamic>?> getTaskStatus(String taskId) async {
    try {
      final statusJson = await NativeBridge.syncTaskApi.getSyncTaskStatus(taskId);
      if (statusJson.isEmpty || statusJson == '{}') return null;
      return json.decode(statusJson) as Map<String, dynamic>;
    } catch (e) {
      debugPrint('Failed to get task status $taskId: $e');
      return null;
    }
  }

  /// 获取同步任务历史记录
  Future<List<Map<String, dynamic>>> getTaskHistory(String taskId) async {
    try {
      final historyJson =
          await NativeBridge.syncTaskApi.getSyncTaskHistory(taskId);
      if (historyJson.isEmpty || historyJson == '[]') return [];
      final list = json.decode(historyJson) as List<dynamic>;
      return list.map((e) => e as Map<String, dynamic>).toList();
    } catch (e) {
      debugPrint('Failed to get task history $taskId: $e');
      return [];
    }
  }

  /// 获取或创建任务
  SyncTask? getTask(String taskId) {
    try {
      return _tasks.firstWhere((t) => t.id == taskId);
    } catch (_) {
      return null;
    }
  }
}

/// 本地挂载管理器
///
/// 管理本地目录挂载的生命周期：
/// - 持久化挂载配置到 AppConfig.localMountsJson
/// - 通过 OpenListApiClient 实际调用 /api/admin/storage/create/delete
/// - 挂载状态追踪（storageId 是否有效）
class LocalMountManager extends ChangeNotifier {
  List<LocalMount> _mounts = [];
  bool _loaded = false;
  LocalMountBackendStatus _backendStatus = LocalMountBackendStatus.checking;

  /// OpenList 管理 API 客户端（需要先调用 initClient 初始化）
  OpenListApiClient? _apiClient;

  List<LocalMount> get mounts => List.unmodifiable(_mounts);
  bool get isLoaded => _loaded;
  bool get hasApiClient => _apiClient != null;
  bool get isBackendReady => _backendStatus == LocalMountBackendStatus.ready;
  LocalMountBackendStatus get backendStatus => _backendStatus;

  /// 初始化 API 客户端
  ///
  /// 认证 token 统一由 AdminAuthManager 获取
  void initClient({required String baseUrl}) {
    _apiClient = OpenListApiClient(baseUrl: baseUrl);
  }

  Future<void> refreshBackendStatus() async {
    if (_apiClient == null) {
      _backendStatus = LocalMountBackendStatus.serviceUnavailable;
      notifyListeners();
      return;
    }
    final isServiceAlive = await _apiClient!.ping();
    if (!isServiceAlive) {
      _backendStatus = LocalMountBackendStatus.serviceUnavailable;
      notifyListeners();
      return;
    }

    final authManager = AdminAuthManager.instance;
    final hadCachedToken = authManager.hasValidCachedToken;
    final token = await authManager.getToken();
    if (token == null || token.isEmpty) {
      _backendStatus = hadCachedToken
          ? LocalMountBackendStatus.authInvalid
          : LocalMountBackendStatus.authMissing;
      notifyListeners();
      return;
    }

    _backendStatus = LocalMountBackendStatus.ready;
    notifyListeners();
  }

  /// 从原生持久化存储加载所有挂载
  Future<void> loadMounts() async {
    try {
      final json = await NativeBridge.syncTaskApi.getLocalMountsJson();
      _mounts = LocalMount.listFromJsonString(json);
      _loaded = true;
      notifyListeners();
    } catch (e) {
      debugPrint('Failed to load local mounts: $e');
      _mounts = [];
      _loaded = true;
      notifyListeners();
    }
  }

  /// 持久化挂载列表
  Future<void> _saveMounts() async {
    final json = LocalMount.listToJsonString(_mounts);
    await NativeBridge.syncTaskApi.setLocalMountsJson(json);
  }

  /// 添加本地挂载（会实际调用 OpenList API 创建存储）
  ///
  /// 成功时 mount 会带有 storageId，isSynced 变为 true
  Future<AddMountResult> addMount(LocalMount mount) async {
    if (_apiClient == null || !isBackendReady) {
      return AddMountResult.apiError(_backendStatus.message);
    }

    // 调用 OpenList API 创建存储
    try {
      final mountPoint = await _nextMountPath(mount.name);
      final result = await _apiClient!.createLocalStorage(
        localPath: mount.path,
        name: mount.name,
        mountPath: mountPoint,
      );

      if (result != null) {
        // 从 API 响应中获取 storage ID
        final storageId = int.tryParse(result['id']?.toString() ?? '');
        if (storageId != null) {
          final synced = mount.copyWith(
            storageId: storageId,
            virtualPath: mountPoint,
          );
          _mounts.add(synced);
          await _saveMounts();
          notifyListeners();
          debugPrint('[LocalMountManager] Mount synced to OpenList: id=$storageId');
          return AddMountResult.success(synced);
        }
      }
      debugPrint('[LocalMountManager] Create storage returned null/unexpected');
      return AddMountResult.apiError('创建存储失败：API 返回异常');
    } catch (e) {
      debugPrint('[LocalMountManager] Create storage error: $e');
      return AddMountResult.apiError('创建存储失败: $e');
    }
  }

  /// 删除本地挂载（会实际调用 OpenList API 删除存储）
  Future<bool> deleteMount(String mountId) async {
    final idx = _mounts.indexWhere((m) => m.id == mountId);
    if (idx < 0) return false;
    final mount = _mounts[idx];

    // 如果已同步到 OpenList，先调用删除 API
    if (mount.isSynced && _apiClient != null) {
      try {
        final success = await _apiClient!.deleteStorage(mount.storageId!);
        if (!success) {
          debugPrint('[LocalMountManager] Failed to delete OpenList storage (API returned false)');
          return false;
        }
        debugPrint('[LocalMountManager] Deleted OpenList storage id=${mount.storageId}');
      } catch (e) {
        debugPrint('[LocalMountManager] Failed to delete OpenList storage: $e');
        return false;
      }
    }

    // API 删除成功（或不需要删除），再清理本地配置
    _mounts.removeAt(idx);
    await _saveMounts();
    notifyListeners();
    return true;
  }

  /// 更新本地挂载
  Future<void> updateMount(LocalMount updated) async {
    final index = _mounts.indexWhere((m) => m.id == updated.id);
    if (index == -1) return;
    final current = _mounts[index];

    if (current.isSynced) {
      if (_apiClient == null || !isBackendReady) {
        throw StateError('OpenList 后台不可用，无法同步更新挂载信息。');
      }

      final remoteStorage = await _apiClient!.getStorage(current.storageId!);
      if (remoteStorage == null) {
        throw StateError('未找到对应的 OpenList 存储，无法更新挂载信息。');
      }

      final updatePayload = Map<String, dynamic>.from(remoteStorage)
        ..['remark'] = updated.name;
      final ok = await _apiClient!.updateStorage(updatePayload);
      if (!ok) {
        throw StateError('OpenList 存储更新失败。');
      }
    }

    _mounts[index] = updated;
    await _saveMounts();
    notifyListeners();
  }

  Future<String> _nextMountPath(String name) async {
    final normalizedName = _normalizeMountSegment(name);
    final existingPaths = <String>{
      for (final mount in _mounts)
        if (mount.virtualPath != null && mount.virtualPath!.isNotEmpty)
          mount.virtualPath!,
    };

    if (_apiClient != null) {
      final storages = await _apiClient!.listStorages();
      for (final storage in storages) {
        final mountPath = storage['mount_path']?.toString();
        if (mountPath != null && mountPath.isNotEmpty) {
          existingPaths.add(mountPath);
        }
      }
    }

    var candidate = '/local/$normalizedName';
    var suffix = 2;
    while (existingPaths.contains(candidate)) {
      candidate = '/local/$normalizedName-$suffix';
      suffix++;
    }
    return candidate;
  }

  String _normalizeMountSegment(String input) {
    final trimmed = input.trim().toLowerCase();
    final sanitized = trimmed
        .replaceAll(RegExp(r'[^a-z0-9._-]+'), '-')
        .replaceAll(RegExp(r'-+'), '-')
        .replaceAll(RegExp(r'^-+|-+$'), '');
    return sanitized.isEmpty ? 'mount' : sanitized;
  }
}

enum LocalMountBackendStatus {
  checking,
  serviceUnavailable,
  authMissing,
  authInvalid,
  ready,
}

extension LocalMountBackendStatusMessage on LocalMountBackendStatus {
  String get message {
    switch (this) {
      case LocalMountBackendStatus.checking:
        return '正在检查 OpenList 后台状态，请稍后重试。';
      case LocalMountBackendStatus.serviceUnavailable:
        return 'OpenList 后台不可用，请先确认本地 5244 服务已启动且可访问。';
      case LocalMountBackendStatus.authMissing:
        return '未配置管理员密码，请在 OpenList 页面顶部的“设置 Admin 密码”中设置。';
      case LocalMountBackendStatus.authInvalid:
        return '管理员密码认证失败，请在 OpenList 页面顶部的“设置 Admin 密码”中重新设置。';
      case LocalMountBackendStatus.ready:
        return 'OpenList 后台和管理员认证均已就绪。';
    }
  }
}

/// 添加挂载结果
class AddMountResult {
  final bool success;
  final LocalMount? mount;
  final String? errorMessage;

  AddMountResult._({required this.success, this.mount, this.errorMessage});

  factory AddMountResult.success(LocalMount mount) =>
      AddMountResult._(success: true, mount: mount);

  factory AddMountResult.apiError(String message) =>
      AddMountResult._(success: false, errorMessage: message);
}
