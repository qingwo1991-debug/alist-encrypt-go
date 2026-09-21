import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/pages/settings/playback_stats_page.dart';
import 'package:openlist_mobile/pages/settings/preference_widgets.dart';
import 'package:openlist_mobile/pages/settings/troubleshooting_page.dart';
import 'package:openlist_mobile/pages/settings/warm_stats_page.dart';
import 'package:openlist_mobile/utils/download_manager.dart';
import 'package:openlist_mobile/utils/config_export.dart';
import 'package:openlist_mobile/utils/language_controller.dart';
import 'package:dio/dio.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'package:permission_handler/permission_handler.dart';

import '../../generated/l10n.dart';
import '../../utils/storage_permission_helper.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({Key? key}) : super(key: key);

  @override
  State<SettingsScreen> createState() {
    return _SettingsScreenState();
  }
}

class _SettingsScreenState extends State<SettingsScreen> {
  late AppLifecycleListener _lifecycleListener;

  @override
  void initState() {
    _lifecycleListener = AppLifecycleListener(
      onResume: () async {
        final controller = Get.put(_SettingsController());
        controller.updateData();
      },
    );
    super.initState();
  }

  @override
  void dispose() {
    _lifecycleListener.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final controller = Get.put(_SettingsController());
    return Scaffold(
        body: Obx(
      () => RefreshIndicator(
        onRefresh: () async {
          final controller = Get.put(_SettingsController());
          controller.updateData();
        },
        child: ListView(
        children: [
          Visibility(
            visible: !controller._notificationGranted.value,
            child: DividerPreference(title: S.of(context).importantSettings),
          ),
          Visibility(
              visible: !controller._notificationGranted.value,
              child: BasicPreference(
                title: S.of(context).grantNotificationPermission,
                subtitle: S.of(context).grantNotificationPermissionDesc,
                onTap: () {
                  Permission.notification.request();
                },
              )),
          Visibility(
            visible: !controller._storageGranted.value,
            child: BasicPreference(
              title: '授予存储访问权限',
              subtitle: '挂载本地目录和加密同步功能需要此权限',
              leading: const Icon(Icons.folder_open, color: Colors.orange),
              onTap: () async {
                await StoragePermissionHelper.requestWithRationale(context);
                controller.updateData();
              },
            ),
          ),

          DividerPreference(title: S.of(context).general),

          // Language Settings
          BasicPreference(
            title: S.of(context).language,
            subtitle: _getLanguageDisplayName(),
            leading: const Icon(Icons.language),
            onTap: () {
              _showLanguageSelectionDialog(context);
            },
          ),

          SwitchPreference(
            title: S.of(context).autoCheckForUpdates,
            subtitle: S.of(context).autoCheckForUpdatesDesc,
            icon: const Icon(Icons.system_update),
            value: controller.autoUpdate,
            onChanged: (value) {
              controller.autoUpdate = value;
            },
          ),
          SwitchPreference(
            title: S.of(context).wakeLock,
            subtitle: S.of(context).wakeLockDesc,
            icon: const Icon(Icons.screen_lock_portrait),
            value: controller.wakeLock,
            onChanged: (value) {
              controller.wakeLock = value;
            },
          ),
          SwitchPreference(
            title: S.of(context).bootAutoStartService,
            subtitle: S.of(context).bootAutoStartServiceDesc,
            icon: const Icon(Icons.power_settings_new),
            value: controller.startAtBoot,
            onChanged: (value) {
              controller.startAtBoot = value;
            },
          ),
          BasicPreference(
            title: S.of(context).dataDirectory,
            subtitle: controller._dataDir.value,
            leading: const Icon(Icons.folder),
            onTap: () async {
              final path = await FilePicker.platform.getDirectoryPath();

              if (path == null) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                  content: Text(S.current.setDefaultDirectory),
                  duration: const Duration(seconds: 3),
                  action: SnackBarAction(
                    label: S.current.confirm,
                    onPressed: () {
                      controller.setDataDir("");
                    },
                  ),
                ));
              } else {
                controller.setDataDir(path);
              }
            },
          ),
          BasicPreference(
            title: S.of(context).downloadDirectory,
            subtitle: controller._downloadDir.value.isEmpty
                ? S.of(context).downloadDirectoryPathUnknown
                : controller._downloadDir.value,
            leading: const Icon(Icons.download),
            onTap: () async {
              final path = await FilePicker.platform.getDirectoryPath();
              if (path == null) {
                return;
              }
              controller.setDownloadDir(path);
            },
          ),
          DividerPreference(title: '配置备份'),
          BasicPreference(
            title: '导出加密配置',
            subtitle: '导出加密路径和代理设置（不含管理密码）',
            leading: const Icon(Icons.upload_file),
            onTap: () async {
              try {
                final path = await ConfigExport.exportConfig();
                if (path != null && context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('配置已导出'),
                      action: SnackBarAction(
                        label: '分享',
                        onPressed: () => ConfigExport.shareConfig(path),
                      ),
                    ),
                  );
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('导出失败: $e')),
                  );
                }
              }
            },
          ),
          BasicPreference(
            title: '导入加密配置',
            subtitle: '从备份文件恢复加密路径和代理设置',
            leading: const Icon(Icons.download),
            onTap: () async {
              final confirm = await showDialog<bool>(
                context: context,
                builder: (ctx) => AlertDialog(
                  title: const Text('确认导入'),
                  content: const Text('导入将覆盖当前加密配置（管理密码不受影响）。确定继续？'),
                  actions: [
                    TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('取消')),
                    FilledButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('导入')),
                  ],
                ),
              );
              if (confirm != true) return;
              try {
                await ConfigExport.importConfig();
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('配置已导入，重启应用生效')),
                  );
                }
              } catch (e) {
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('导入失败: $e')),
                  );
                }
              }
            },
          ),
          BasicPreference(
            title: '预热统计',
            subtitle: '首帧折线图 · 预热明细 · 播放记录',
            leading: const Icon(Icons.insights),
            onTap: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => const WarmStatsPage(),
                ),
              );
            },
          ),
          BasicPreference(
            title: '播放统计',
            subtitle: '设置统计导出密码并导出播放/删除记录',
            leading: const Icon(Icons.analytics),
            onTap: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (_) => const PlaybackStatsPage(),
                ),
              );
            },
          ),
          DividerPreference(title: S.of(context).uiSettings),
          SwitchPreference(
              icon: const Icon(Icons.pan_tool_alt_outlined),
              title: S.of(context).silentJumpApp,
              subtitle: S.of(context).silentJumpAppDesc,
              value: controller._silentJumpApp.value,
              onChanged: (value) {
                controller.silentJumpApp = value;
              }),
          // Log level filter
          BasicPreference(
            title: '日志级别',
            subtitle: '当前: ${controller.logLevelName}（低于此级别的日志不显示）',
            leading: const Icon(Icons.bug_report),
            onTap: () {
              _showLogLevelDialog(context, controller);
            },
          ),
          // 调试模式：开启后可提供更详细日志（含远程实时日志流）
          SwitchPreference(
            title: '调试模式 / 详细日志',
            subtitle: controller.debugMode
                ? '已开启：记录详细调试日志（含敏感路径，仅供诊断）'
                : '开启后记录详细请求/解密日志，并允许局域网远程实时查看日志（仅本机 LAN 可用）',
            icon: const Icon(Icons.troubleshoot),
            value: controller.debugMode,
            onChanged: (value) async {
              final ok = await controller.setDebugMode(value);
              if (!ok && context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    content: Text('开启失败：请确认加密代理正在运行'),
                    duration: Duration(seconds: 2),
                  ),
                );
              }
            },
          ),
          // 显示远程日志地址提示（调试模式开启时）
          if (controller.debugMode)
            BasicPreference(
              title: '实时查看日志方式',
              subtitle: '同局域网设备的浏览器访问：\n'
                  'http://${controller._lanAddr.value}:${controller.proxyPort}/api/logs/live\n'
                  '启用后同网段设备可远程 tail 本机日志（调试用，平时可关闭）',
              leading: const Icon(Icons.lan),
              onTap: () {},
            ),
          
          BasicPreference(
            title: S.of(context).troubleshooting,
            subtitle: S.of(context).troubleshootingDesc,
            leading: const Icon(Icons.help_outline),
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => const TroubleshootingPage(),
                ),
              );
            },
          ),
        ],
      ),
      ),
    ));
  }

  String _getLanguageDisplayName() {
    final languageController = Get.find<LanguageController>();
    final currentOption = languageController.currentLanguageOption;
    
    switch (currentOption.name) {
      case 'followSystem':
        return S.of(context).followSystem;
      case 'simplifiedChinese':
        return S.of(context).simplifiedChinese;
      case 'english':
        return S.of(context).english;
      default:
        return currentOption.name;
    }
  }

  void _showLanguageSelectionDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text(S.of(context).languageSettings),
          content: SingleChildScrollView(
            child: LanguageSelector(
              onLanguageChanged: () {
                Navigator.of(context).pop();
                setState(() {}); // 刷新界面以显示新的语言设置
              },
            ),
          ),
          actions: [
            TextButton(
              onPressed: () {
                Navigator.of(context).pop();
              },
              child: Text(S.of(context).cancel),
            ),
          ],
        );
      },
    );
  }

  void _showLogLevelDialog(BuildContext context, _SettingsController controller) {
    final levels = ['PANIC', 'FATAL', 'ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'];
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: const Text('选择日志级别'),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: List.generate(levels.length, (i) {
              return RadioListTile<int>(
                title: Text(levels[i]),
                subtitle: Text(i <= 2 ? '仅严重错误' : i <= 4 ? '常规信息' : '详细调试'),
                value: i,
                groupValue: controller.logLevel,
                onChanged: (value) {
                  controller.setLogLevel(value!);
                  Navigator.of(context).pop();
                },
              );
            }),
          ),
        );
      },
    );
  }
}

class _SettingsController extends GetxController {
  final _dataDir = "".obs;
  final _downloadDir = "".obs;
  final _autoUpdate = true.obs;
  final _notificationGranted = true.obs;
  final _storageGranted = true.obs;
  final _debugMode = false.obs;
  final _lanAddr = "127.0.0.1".obs;
  final proxyPort = "5344";

  bool get debugMode => _debugMode.value;
  String get lanAddr => _lanAddr.value;

  // 读取并保存加密代理的调试模式（debugEnabled），持久化在 v2 配置里。
  // 调用的端点与 encrypt_config_page 一致：GET/POST /api/encrypt/v2/config。
  Future<bool> setDebugMode(bool value) async {
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 3),
        receiveTimeout: const Duration(seconds: 5),
        sendTimeout: const Duration(seconds: 5),
      ));
      final resp = await dio.post(
        'http://127.0.0.1:$proxyPort/api/encrypt/v2/config',
        data: {'debugEnabled': value},
      );
      final data = resp.data is Map<String, dynamic>
          ? resp.data as Map<String, dynamic>
          : null;
      if (data?['code'] != 200) return false;
      _debugMode.value = value;
      _refreshLanAddr();
      return true;
    } catch (e) {
      debugPrint('setDebugMode failed: $e');
      return false;
    }
  }

  Future<void> _loadDebugMode() async {
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 3),
        receiveTimeout: const Duration(seconds: 5),
      ));
      final resp = await dio.get('http://127.0.0.1:$proxyPort/api/encrypt/v2/config');
      final data = resp.data is Map<String, dynamic>
          ? resp.data as Map<String, dynamic>
          : null;
      final cfg = data?['data']?['config'] as Map<String, dynamic>?;
      if (cfg == null) return;
      _debugMode.value = cfg['debugEnabled'] == true;
      _refreshLanAddr();
    } catch (e) {
      debugPrint('load debug mode failed: $e');
    }
  }

  void _refreshLanAddr() async {
    // 从 v2 配置的 dbExportBaseUrl 提取局域网地址（App 实际可见的 LAN IP），
    // 用于提示远程日志地址；失败时保持 127.0.0.1（App 无法直接可用时由用户自行查）。
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 3),
        receiveTimeout: const Duration(seconds: 5),
      ));
      final resp = await dio.get('http://127.0.0.1:$proxyPort/api/encrypt/v2/config');
      final data = resp.data is Map<String, dynamic>
          ? resp.data as Map<String, dynamic>
          : null;
      final cfg = data?['data']?['config'] as Map<String, dynamic>?;
      final base = (cfg?['dbExportBaseUrl'] as String?) ?? '';
      final uri = Uri.tryParse(base);
      if (uri != null && uri.host.isNotEmpty) {
        _lanAddr.value = uri.host;
      }
    } catch (_) {}
  }

  setDataDir(String value) async {
    NativeBridge.appConfig.setDataDir(value);
    _dataDir.value = await NativeBridge.appConfig.getDataDir();
  }

  get dataDir => _dataDir.value;

  setDownloadDir(String value) async {
    await DownloadManager.setConfiguredDownloadDirectoryPath(value);
    _downloadDir.value =
        await DownloadManager.getConfiguredDownloadDirectoryPath() ?? "";
  }

  set autoUpdate(value) => {
        _autoUpdate.value = value,
        NativeBridge.appConfig.setAutoCheckUpdateEnabled(value)
      };

  get autoUpdate => _autoUpdate.value;

  final _wakeLock = false.obs;

  set wakeLock(value) => {
        _wakeLock.value = value,
        NativeBridge.appConfig.setWakeLockEnabled(value)
      };

  get wakeLock => _wakeLock.value;

  final _autoStart = true.obs;

  set startAtBoot(value) => {
        _autoStart.value = value,
        NativeBridge.appConfig.setStartAtBootEnabled(value)
      };

  get startAtBoot => _autoStart.value;

  final _silentJumpApp = false.obs;

  get silentJumpApp => _silentJumpApp.value;

  set silentJumpApp(value) => {
        _silentJumpApp.value = value,
        NativeBridge.appConfig.setSilentJumpAppEnabled(value)
      };

  final _logLevel = 4.obs; // default INFO

  int get logLevel => _logLevel.value;
  String get logLevelName => _levelName(_logLevel.value);

  setLogLevel(int level) {
    _logLevel.value = level;
  }

  static String _levelName(int level) {
    switch (level) {
      case 0: return 'PANIC';
      case 1: return 'FATAL';
      case 2: return 'ERROR';
      case 3: return 'WARN';
      case 4: return 'INFO';
      case 5: return 'DEBUG';
      case 6: return 'TRACE';
      default: return 'INFO';
    }
  }

  @override
  void onInit() async {
    updateData();

    super.onInit();
  }

  void updateData() async {
    final cfg = AppConfig();
    cfg.isAutoCheckUpdateEnabled().then((value) => autoUpdate = value);
    cfg.isWakeLockEnabled().then((value) => wakeLock = value);
    cfg.isStartAtBootEnabled().then((value) => startAtBoot = value);
    cfg.isSilentJumpAppEnabled().then((value) => silentJumpApp = value);
    _loadDebugMode();

    _dataDir.value = await cfg.getDataDir();
    _downloadDir.value =
        await DownloadManager.getConfiguredDownloadDirectoryPath() ?? "";

    final sdk = await NativeBridge.common.getDeviceSdkInt();
    if (sdk >= 33) {
      _notificationGranted.value = await Permission.notification.isGranted;
    } else {
      _notificationGranted.value = true;
    }
    _storageGranted.value = await StoragePermissionHelper.isGranted();
  }
}
