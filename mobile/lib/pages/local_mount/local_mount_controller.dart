import 'package:get/get.dart';
import 'package:file_picker/file_picker.dart';

import '../../generated_api.dart';
import '../../models/local_mount.dart';
import '../../utils/sync_task_manager.dart';

class LocalMountController extends GetxController {
  final LocalMountManager _manager = LocalMountManager();

  List<LocalMount> get mounts => _manager.mounts;
  bool get isLoaded => _manager.isLoaded;
  bool get hasApiClient => _manager.hasApiClient;
  bool get isBackendReady => _manager.isBackendReady;
  LocalMountBackendStatus get backendStatus => _manager.backendStatus;

  String _generateId() =>
      'mount_${DateTime.now().millisecondsSinceEpoch}_${(_manager.mounts.length + 1)}';

  @override
  void onInit() {
    super.onInit();
    loadMounts();
  }

  /// 初始化 OpenList API 客户端
  ///
  /// 认证 token 统一由 AdminAuthManager 获取，不再接受密码参数
  Future<void> initApiClient() async {
    var port = 5244;
    try {
      port = await Android().getOpenListHttpPort();
    } catch (_) {
      port = 5244;
    }
    _manager.initClient(baseUrl: 'http://127.0.0.1:$port');
  }

  Future<void> refreshBackendStatus() async {
    await _manager.refreshBackendStatus();
    update();
  }

  Future<String?> verifyAndStoreAdminPassword(String password) async {
    try {
      final success = await _manager.verifyAndStoreAdminPassword(password);
      if (!success) {
        return '当前输入的密码无法登录本机 OpenList 管理接口(5244)。请确认这是当前 OpenList 管理员密码；如果密码已经改过，再到 OpenList 页面重置。';
      }
      await refreshBackendStatus();
      return null;
    } catch (e) {
      return e.toString();
    }
  }

  Future<void> loadMounts() async {
    await _manager.loadMounts();
    update();
  }

  /// 快捷创建 Download/DCIM 等挂载
  Future<String?> addQuickMount(
    String name,
    String path, {
    bool readOnly = false,
  }) async {
    final mount = LocalMount(
      id: _generateId(),
      name: name,
      path: path,
      readOnly: readOnly,
    );
    final result = await _manager.addMount(mount);
    update();

    if (!result.success) {
      return result.errorMessage ?? '挂载创建失败';
    }
    return null; // success
  }

  /// 通过目录选择器创建挂载
  Future<String?> addMountFromPicker() async {
    final result = await FilePicker.platform.getDirectoryPath(
      dialogTitle: '选择本地目录',
    );
    if (result == null) return '未选择目录';

    final dirName = result.split('/').last;
    final mount = LocalMount(
      id: _generateId(),
      name: dirName,
      path: result,
      readOnly: false,
    );
    final addResult = await _manager.addMount(mount);
    update();

    if (!addResult.success) {
      return addResult.errorMessage ?? '挂载创建失败';
    }
    return null; // success
  }

  /// 删除挂载
  Future<bool> deleteMount(String mountId) async {
    final result = await _manager.deleteMount(mountId);
    update();
    return result;
  }

  /// 更新挂载
  Future<String?> updateMount(LocalMount updated) async {
    try {
      await _manager.updateMount(updated);
    } catch (e) {
      return e.toString();
    }
    update();
    return null;
  }
}
