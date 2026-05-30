import 'dart:async';
import 'dart:io';

import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/pages/openlist/about_dialog.dart';
import 'package:openlist_mobile/pages/openlist/pwd_edit_dialog.dart';
import 'package:openlist_mobile/pages/openlist/config_editor_page.dart';
import 'package:openlist_mobile/pages/app_update_dialog.dart';
import 'package:openlist_mobile/widgets/switch_floating_action_button.dart';
import 'package:openlist_mobile/utils/service_manager.dart';
import 'package:flutter/material.dart';
import 'package:get/get.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import '../../contant/native_bridge.dart';
import '../../generated/l10n.dart';
import '../../utils/admin_auth_manager.dart';
import '../local_mount/local_mount_controller.dart';
import 'log_list_view.dart';

class OpenListScreen extends StatelessWidget {
  const OpenListScreen({Key? key}) : super(key: key);

  Future<String?> _updateAdminPassword(String pwd) async {
    try {
      debugPrint('[OpenListScreen] setAdminPwd start');
      await NativeBridge.android.setAdminPwd(pwd);
      debugPrint('[OpenListScreen] setAdminPwd success');
      AdminAuthManager.instance.invalidate();
      if (Get.isRegistered<LocalMountController>()) {
        unawaited(
          Get.find<LocalMountController>()
              .refreshBackendStatus()
              .timeout(const Duration(seconds: 5))
              .catchError((e) {
            debugPrint(
              '[OpenListScreen] refreshBackendStatus after password update failed: $e',
            );
          }),
        );
      }
      Get.showSnackbar(const GetSnackBar(
        title: '管理员密码已更新',
        message: 'OpenList、本地挂载和同步任务将共用这份密码。',
        duration: Duration(seconds: 2),
      ));
      return null;
    } catch (e) {
      debugPrint('[OpenListScreen] setAdminPwd error: $e');
      return e.toString();
    }
  }

  @override
  Widget build(BuildContext context) {
    final ui = Get.put(OpenListController());

    return Scaffold(
        appBar: AppBar(
            backgroundColor: Theme.of(context).colorScheme.primaryContainer,
            title: Obx(() => Text("OpenList - ${ui.openlistVersion.value}")),
            actions: [
              IconButton(
                tooltip: S.current.setAdminPassword,
                onPressed: () {
                  showDialog(
                      context: context,
                      builder: (context) =>
                          PwdEditDialog(onConfirm: _updateAdminPassword));
                },
                icon: const Icon(Icons.password),
              ),
              IconButton(
                tooltip: S.of(context).editOpenListConfig,
                onPressed: () {
                  Get.to(() => const ConfigEditorPage());
                },
                icon: const Icon(Icons.edit_note),
              ),
              IconButton(
                tooltip: S.of(context).exportLogs,
                onPressed: () async {
                  await ui.exportLogs(context);
                },
                icon: const Icon(Icons.download),
              ),
              IconButton(
                tooltip: S.of(context).desktopShortcut,
                onPressed: () async  {
                  await NativeBridge.android.addShortcut();
                },
                icon: const Icon(Icons.add_home),
              ),
              PopupMenuButton(
                tooltip: S.of(context).moreOptions,
                onSelected: (value) async {
                  if (value == 1) {
                    await AppUpdateDialog.checkUpdateAndShowDialog(context, (b) {
                      if (!b) {
                        Get.showSnackbar(GetSnackBar(
                            message: S.of(context).currentIsLatestVersion,
                            duration: const Duration(seconds: 2)));
                      }
                    });
                  } else if (value == 2) {
                    if (!context.mounted) return;
                    showDialog(context: context, builder: ((context) {
                      return const AppAboutDialog();
                    }));
                  }
                },
                itemBuilder: (context) {
                  return [
                    PopupMenuItem(
                      value: 1,
                      child: Text(S.of(context).checkForUpdates),
                    ),
                    PopupMenuItem(
                      value: 2,
                      child: Text(S.of(context).about),
                    ),
                  ];
                },
                icon: const Icon(Icons.more_vert),
              )
            ]),
        floatingActionButton: Obx(
          () => SwitchFloatingButton(
              isSwitch: ui.isSwitch.value,
              onSwitchChange: (s) async {
                ui.clearLog();
                if (s) {
                  // 启动服务
                  await ServiceManager.instance.startService();
                } else {
                  // 停止服务
                  await ServiceManager.instance.stopService();
                }
              }),
        ),
        body: Obx(() => LogListView(logs: ui.logs.value)));
  }
}

class MyEventReceiver extends Event {
  Function(Log log) logCb;
  Function(bool isRunning) statusCb;

  MyEventReceiver(this.statusCb, this.logCb);

  @override
  void onServiceStatusChanged(bool isRunning) {
    statusCb(isRunning);
  }

  @override
  void onServerLog(int level, String time, String log) {
    logCb(Log(level, time, log));
  }
}

class OpenListController extends GetxController {
  final ScrollController _scrollController = ScrollController();
  var isSwitch = false.obs;
  var openlistVersion = "".obs;

  var logs = <Log>[].obs;

  void clearLog() {
    logs.clear();
  }

  void addLog(Log log) {
    logs.add(log);
    _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
  }

  Future<void> exportLogs(BuildContext context) async {
    if (logs.isEmpty) {
      Get.showSnackbar(GetSnackBar(
        message: S.of(context).noLogsToExport,
        duration: const Duration(seconds: 2),
      ));
      return;
    }

    try {
      // 构建日志内容
      final buffer = StringBuffer();
      buffer.writeln('OpenList Logs - Exported at ${DateTime.now().toIso8601String()}');
      buffer.writeln('=' * 60);
      buffer.writeln();
      
      for (final log in logs) {
        final levelStr = _getLevelString(log.level);
        buffer.writeln('[$levelStr] ${log.time}');
        buffer.writeln(log.content);
        buffer.writeln();
      }

      // 保存到临时文件
      final tempDir = await getTemporaryDirectory();
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final file = File('${tempDir.path}/openlist_logs_$timestamp.txt');
      await file.writeAsString(buffer.toString());

      // 分享文件
      await Share.shareXFiles(
        [XFile(file.path)],
        subject: 'OpenList Logs',
      );

      Get.showSnackbar(GetSnackBar(
        message: S.of(context).logsExportSuccess,
        duration: const Duration(seconds: 2),
      ));
    } catch (e) {
      Get.showSnackbar(GetSnackBar(
        message: '${S.of(context).logsExportFailed}: $e',
        duration: const Duration(seconds: 3),
      ));
    }
  }

  String _getLevelString(int level) {
    switch (level) {
      case 0:
        return 'TRACE';
      case 1:
        return 'DEBUG';
      case 2:
        return 'INFO';
      case 3:
        return 'WARN';
      case 4:
        return 'ERROR';
      case 5:
        return 'FATAL';
      default:
        return 'UNKNOWN';
    }
  }

  @override
  void onInit() {
    // 设置日志接收器，但状态变化只通过ServiceManager处理
    Event.setup(MyEventReceiver(
        (isRunning) {
          // 不在这里更新状态，避免冲突
          print('Event receiver status: $isRunning');
        }, 
        (log) => addLog(log)));
    
    NativeBridge.android.getOpenListVersion().then((value) => openlistVersion.value = value);
    
    // 获取初始状态
    ServiceManager.instance.checkServiceStatus().then((isRunning) {
      isSwitch.value = isRunning;
    });

    // 只监听ServiceManager的状态变化
    ServiceManager.instance.serviceStatusStream.listen((isRunning) {
      print('ServiceManager status changed: $isRunning');
      isSwitch.value = isRunning;
    });

    super.onInit();
  }
}
