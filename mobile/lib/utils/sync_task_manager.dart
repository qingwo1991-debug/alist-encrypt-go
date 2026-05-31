import 'dart:convert';

import 'package:flutter/foundation.dart';

import '../contant/native_bridge.dart';
import '../utils/app_logger.dart';
import 'admin_auth_manager.dart';
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
    final previous = _tasks[index];

    if (_requiresRecordReset(previous, updated)) {
      try {
        await NativeBridge.syncTaskApi.clearSyncTaskRecords(updated.id);
      } catch (e) {
        debugPrint('Failed to clear sync records for ${updated.id}: $e');
      }
      updated
        ..lastSyncTime = null
        ..lastSyncFileCount = null
        ..lastError = null;
    }

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

    try {
      await NativeBridge.syncTaskApi.clearSyncTaskRecords(taskId);
    } catch (e) {
      debugPrint('Failed to clear sync records for $taskId: $e');
    }

    try {
      await NativeBridge.syncTaskApi.clearSyncTaskHistory(taskId);
    } catch (e) {
      debugPrint('Failed to clear sync history for $taskId: $e');
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

  Future<void> clearTaskRecords(String taskId) async {
    try {
      await NativeBridge.syncTaskApi.clearSyncTaskRecords(taskId);
    } catch (e) {
      debugPrint('Failed to clear sync records for $taskId: $e');
      rethrow;
    }

    final index = _tasks.indexWhere((t) => t.id == taskId);
    if (index >= 0) {
      _tasks[index]
        ..lastSyncTime = null
        ..lastSyncFileCount = null
        ..lastError = null;
      await _saveTasks();
      notifyListeners();
    }
  }

  Future<void> clearTaskHistory(String taskId) async {
    try {
      await NativeBridge.syncTaskApi.clearSyncTaskHistory(taskId);
    } catch (e) {
      debugPrint('Failed to clear sync history for $taskId: $e');
      rethrow;
    }

    final index = _tasks.indexWhere((t) => t.id == taskId);
    if (index >= 0) {
      _tasks[index]
        ..lastSyncTime = null
        ..lastSyncFileCount = null
        ..lastError = null;
      await _saveTasks();
      notifyListeners();
    }
  }

  Future<void> clearAllHistory() async {
    try {
      await NativeBridge.syncTaskApi.clearAllSyncTaskHistory();
    } catch (e) {
      debugPrint('Failed to clear all sync history: $e');
      rethrow;
    }

    for (final task in _tasks) {
      task
        ..lastSyncTime = null
        ..lastSyncFileCount = null
        ..lastError = null;
    }
    await _saveTasks();
    notifyListeners();
  }

  Future<void> rerunTaskFromScratch(String taskId) async {
    await clearTaskRecords(taskId);
    await runTaskNow(taskId);
  }

  Future<String> cleanUploadedSourceFiles(String taskId) async {
    return NativeBridge.syncTaskApi.cleanUploadedSourceFiles(taskId);
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

  bool _requiresRecordReset(SyncTask previous, SyncTask next) {
    return previous.sourcePath != next.sourcePath ||
        previous.targetPath != next.targetPath ||
        previous.preserveFolderStructure != next.preserveFolderStructure ||
        !_sameStringList(previous.fileExtensions, next.fileExtensions) ||
        !_sameStringList(previous.excludeFolders, next.excludeFolders);
  }

  bool _sameStringList(List<String> a, List<String> b) {
    if (identical(a, b)) return true;
    if (a.length != b.length) return false;
    final left = a.map((e) => e.trim()).toList()..sort();
    final right = b.map((e) => e.trim()).toList()..sort();
    for (var i = 0; i < left.length; i++) {
      if (left[i] != right[i]) return false;
    }
    return true;
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
    final traceId = AppLogger.newTraceId('mount-backend');
    if (_apiClient == null) {
      await AppLogger.warn('[mount][trace=$traceId] backend-check skipped: api client not initialized');
      _backendStatus = LocalMountBackendStatus.serviceUnavailable;
      notifyListeners();
      return;
    }
    final isServiceAlive = await _apiClient!.ping();
    if (!isServiceAlive) {
      await AppLogger.warn('[mount][trace=$traceId] backend-check failed: service unavailable');
      _backendStatus = LocalMountBackendStatus.serviceUnavailable;
      notifyListeners();
      return;
    }

    final authManager = AdminAuthManager.instance;
    final hadCachedToken = authManager.hasValidCachedToken;
    final token = await authManager.getToken();
    if (token == null || token.isEmpty) {
      await AppLogger.warn(
        '[mount][trace=$traceId] backend-check auth not ready: hadCachedToken=$hadCachedToken',
      );
      _backendStatus = hadCachedToken
          ? LocalMountBackendStatus.authInvalid
          : LocalMountBackendStatus.authMissing;
      notifyListeners();
      return;
    }

    await AppLogger.info('[mount][trace=$traceId] backend-check ready');
    _backendStatus = LocalMountBackendStatus.ready;
    notifyListeners();
  }

  Future<bool> verifyAndStoreAdminPassword(String password) async {
    final traceId = AppLogger.newTraceId('mount-auth');
    final normalized = password.trim();
    if (normalized.length < 4) {
      await AppLogger.warn('[mount][trace=$traceId] password verify rejected: too short');
      throw ArgumentError('管理员密码至少需要 4 位');
    }
    await AppLogger.info('[mount][trace=$traceId] password verify start');
    final token = await NativeBridge.syncTaskApi.acquireAuthTokenByPassword(
      normalized,
    );
    if (token == null || token.isEmpty) {
      await AppLogger.warn('[mount][trace=$traceId] password verify failed: token empty');
      return false;
    }
    AdminAuthManager.instance.invalidate();
    await AppLogger.info('[mount][trace=$traceId] password verify success');
    _backendStatus = LocalMountBackendStatus.ready;
    notifyListeners();
    return true;
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
    final traceId = AppLogger.newTraceId('mount-create', entityId: mount.id);
    if (_apiClient == null || !isBackendReady) {
      await AppLogger.warn(
        '[mount][trace=$traceId][mountId=${mount.id}] create blocked: backendStatus=${_backendStatus.name}',
      );
      return AddMountResult.apiError(_backendStatus.message);
    }

    // 调用 OpenList API 创建存储
    try {
      await AppLogger.info(
        '[mount][trace=$traceId][mountId=${mount.id}] create start name=${mount.name} path=${mount.path}',
      );
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
          await AppLogger.info(
            '[mount][trace=$traceId][mountId=${mount.id}] create success storageId=$storageId mountPath=$mountPoint',
          );
          debugPrint('[LocalMountManager] Mount synced to OpenList: id=$storageId');
          return AddMountResult.success(synced);
        }
      }
      await AppLogger.warn(
        '[mount][trace=$traceId][mountId=${mount.id}] create failed: unexpected api response',
      );
      debugPrint('[LocalMountManager] Create storage returned null/unexpected');
      return AddMountResult.apiError('创建存储失败：API 返回异常');
    } on ApiException catch (e) {
      await AppLogger.warn(
        '[mount][trace=$traceId][mountId=${mount.id}] create api error code=${e.code} message=${e.message}',
      );
      debugPrint('[LocalMountManager] Create storage api error: code=${e.code} message=${e.message} data=${e.data}');
      return AddMountResult.apiError('创建存储失败：${e.message}');
    } catch (e) {
      await AppLogger.error(
        '[mount][trace=$traceId][mountId=${mount.id}] create exception $e',
      );
      debugPrint('[LocalMountManager] Create storage error: $e');
      return AddMountResult.apiError('创建存储失败: $e');
    }
  }

  /// 删除本地挂载（会实际调用 OpenList API 删除存储）
  Future<bool> deleteMount(String mountId) async {
    final traceId = AppLogger.newTraceId('mount-delete', entityId: mountId);
    final idx = _mounts.indexWhere((m) => m.id == mountId);
    if (idx < 0) return false;
    final mount = _mounts[idx];
    await AppLogger.info(
      '[mount][trace=$traceId][mountId=${mount.id}] delete start synced=${mount.isSynced} storageId=${mount.storageId}',
    );

    // 如果已同步到 OpenList，先调用删除 API
    if (mount.isSynced && _apiClient != null) {
      try {
        final success = await _apiClient!.deleteStorage(mount.storageId!);
        if (!success) {
          final remoteStorage = await _apiClient!.getStorage(mount.storageId!);
          if (remoteStorage == null) {
            await AppLogger.warn(
              '[mount][trace=$traceId][mountId=${mount.id}] remote storage missing, remove local stale mount only',
            );
          } else {
            await AppLogger.warn(
              '[mount][trace=$traceId][mountId=${mount.id}] delete failed: api returned false storageId=${mount.storageId}',
            );
            debugPrint('[LocalMountManager] Failed to delete OpenList storage (API returned false)');
            return false;
          }
        }
        await AppLogger.info(
          '[mount][trace=$traceId][mountId=${mount.id}] remote delete success storageId=${mount.storageId}',
        );
        debugPrint('[LocalMountManager] Deleted OpenList storage id=${mount.storageId}');
      } catch (e) {
        await AppLogger.error(
          '[mount][trace=$traceId][mountId=${mount.id}] delete exception $e',
        );
        debugPrint('[LocalMountManager] Failed to delete OpenList storage: $e');
        return false;
      }
    }

    // API 删除成功（或不需要删除），再清理本地配置
    _mounts.removeAt(idx);
    await _saveMounts();
    notifyListeners();
    await AppLogger.info('[mount][trace=$traceId][mountId=${mount.id}] delete local config success');
    return true;
  }

  /// 更新本地挂载
  Future<void> updateMount(LocalMount updated) async {
    final traceId = AppLogger.newTraceId('mount-update', entityId: updated.id);
    final index = _mounts.indexWhere((m) => m.id == updated.id);
    if (index == -1) return;
    final current = _mounts[index];

    if (current.isSynced) {
      if (_apiClient == null || !isBackendReady) {
        throw StateError('OpenList 后台不可用，无法同步更新挂载信息。');
      }

      final remoteStorage = await _apiClient!.getStorage(current.storageId!);
      if (remoteStorage == null) {
        await AppLogger.warn(
          '[mount][trace=$traceId][mountId=${updated.id}] update failed: remote storage missing',
        );
        throw StateError('未找到对应的 OpenList 存储，无法更新挂载信息。');
      }

      final updatePayload = Map<String, dynamic>.from(remoteStorage)
        ..['remark'] = updated.name;
      final ok = await _apiClient!.updateStorage(updatePayload);
      if (!ok) {
        await AppLogger.warn(
          '[mount][trace=$traceId][mountId=${updated.id}] update failed: api returned false',
        );
        throw StateError('OpenList 存储更新失败。');
      }
    }

    _mounts[index] = updated;
    await _saveMounts();
    notifyListeners();
    await AppLogger.info(
      '[mount][trace=$traceId][mountId=${updated.id}] update success name=${updated.name}',
    );
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
        return 'OpenList 后台不可用，请先确认本地服务已启动且当前监听端口可访问。';
      case LocalMountBackendStatus.authMissing:
        return '未录入 OpenList 管理员密码。可直接输入当前密码校验，无需强制重置。';
      case LocalMountBackendStatus.authInvalid:
        return '当前缓存的 OpenList 管理员密码认证失败。请先重新输入现有密码校验；只有密码确实不一致时才需要重置。';
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
