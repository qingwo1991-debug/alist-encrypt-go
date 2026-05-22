import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:openlist_mobile/contant/log_level.dart';
import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/pages/settings/preference_widgets.dart';
import 'package:openlist_mobile/pages/settings/troubleshooting_page.dart';
import 'package:openlist_mobile/utils/language_controller.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'package:permission_handler/permission_handler.dart';

import '../../generated/l10n.dart';

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
      () => ListView(
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
          // AutoStartWebPage
          SwitchPreference(
            title: S.of(context).autoStartWebPage,
            subtitle: S.of(context).autoStartWebPageDesc,
            icon: const Icon(Icons.open_in_browser),
            value: controller._autoStartWebPage.value,
            onChanged: (value) {
              controller.autoStartWebPage = value;
            },
          ),

          BasicPreference(
            title: S.of(context).dataDirectory,
            subtitle: controller._dataDir.value,
            leading: const Icon(Icons.folder),
            onTap: () async {
              final path = await FilePicker.platform.getDirectoryPath();

              if (path == null) {
                Get.showSnackbar(GetSnackBar(
                    message: S.current.setDefaultDirectory,
                    duration: const Duration(seconds: 3),
                    mainButton: TextButton(
                      onPressed: () {
                        controller.setDataDir("");
                        Get.back();
                      },
                      child: Text(S.current.confirm),
                    )));
              } else {
                controller.setDataDir(path);
              }
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
  final _autoUpdate = true.obs;
  final _notificationGranted = true.obs;

  setDataDir(String value) async {
    NativeBridge.appConfig.setDataDir(value);
    _dataDir.value = await NativeBridge.appConfig.getDataDir();
  }

  get dataDir => _dataDir.value;

  set autoUpdate(value) => {
        _autoUpdate.value = value,
        NativeBridge.appConfig.setAutoCheckUpdateEnabled(value)
      };

  get autoUpdate => _autoUpdate.value;

  final _wakeLock = true.obs;

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

  final _autoStartWebPage = false.obs;

  set autoStartWebPage(value) => {
        _autoStartWebPage.value = value,
        NativeBridge.appConfig.setAutoOpenWebPageEnabled(value)
      };

  get autoStartWebPage => _autoStartWebPage.value;

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
    cfg.isAutoOpenWebPageEnabled().then((value) => autoStartWebPage = value);
    cfg.isSilentJumpAppEnabled().then((value) => silentJumpApp = value);

    _dataDir.value = await cfg.getDataDir();

    final sdk = await NativeBridge.common.getDeviceSdkInt();
    if (sdk >= 33) {
      _notificationGranted.value = await Permission.notification.isGranted;
    } else {
      _notificationGranted.value = true;
    }
  }
}
