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

import '../../contant/log_level.dart';
import '../../contant/native_bridge.dart';
import '../../generated/l10n.dart';
import '../../utils/admin_auth_manager.dart';
import '../local_mount/local_mount_controller.dart';
import 'log_list_view.dart';

class OpenListScreen extends StatelessWidget {
  const OpenListScreen({Key? key}) : super(key: key);

  Future<String?> _updateAdminPassword(BuildContext context, String pwd) async {
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
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text('管理员密码已更新，OpenList、本地挂载和同步任务将共用这份密码。'),
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
    final ui = Get.isRegistered<OpenListController>()
        ? Get.find<OpenListController>()
        : Get.put(OpenListController());

    return Scaffold(
        appBar: AppBar(
            backgroundColor: Theme.of(context).colorScheme.primaryContainer,
            elevation: 0,
            scrolledUnderElevation: 2,
            title: Obx(() => Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'OpenList',
                  style: Theme.of(context).textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
                ),
                Text(
                  ui.openlistVersion.value,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Theme.of(context).colorScheme.onPrimaryContainer.withOpacity(0.7),
                  ),
                ),
              ],
            )),
            actions: [
              IconButton(
                tooltip: S.current.setAdminPassword,
                onPressed: () {
                  showDialog(
                      context: context,
                      builder: (dialogCtx) =>
                          PwdEditDialog(onConfirm: (pwd) => _updateAdminPassword(context, pwd)));
                },
                icon: const Icon(Icons.password),
              ),
              IconButton(
                tooltip: S.of(context).editOpenListConfig,
                onPressed: () {
                  Navigator.push(context, MaterialPageRoute(builder: (_) => const ConfigEditorPage()));
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
                        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
content: Text(S.of(context).currentIsLatestVersion),
                            duration: const Duration(seconds: 2),
));
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
        body: Obx(() => LogListView(
              logs: ui.logs.toList(growable: false),
              controller: ui.scrollController,
            )));
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
  StreamSubscription<bool>? _serviceStatusSubscription;
  var isSwitch = false.obs;
  var openlistVersion = "".obs;

  var logs = <Log>[].obs;

  // 崩溃日志滚动落盘：内存 logs 在进程被杀/闪退时会清空，导致"日志留不下来"
  // （无电脑/数据线时尤其致命）。这里把每条日志同时 append 到应用私有目录的
  // 滚动文件，任何时刻崩溃，之前的日志都已持久化；重新打开 App（新进程）后，
  // 走 [persistedLogs] 兜底导出，不需要电脑也能拿到崩溃前日志。
  File? _persistedFile;
  int _persistedBytes = 0;
  static const int _maxPersistedBytes = 2 * 1024 * 1024; // 2MB，超出自动轮转截短

  Future<File?> _ensurePersistedFile() async {
    try {
      if (_persistedFile == null) {
        final dir = await getApplicationDocumentsDirectory();
        // 用一个固定的滚动文件名，便于"崩溃后导出"与"覆盖式轮转"。
        _persistedFile = File('${dir.path}/openlist_log_roll.txt');
        if (await _persistedFile!.exists()) {
          _persistedBytes = await _persistedFile!.length();
        }
      }
      return _persistedFile;
    } catch (_) {
      return null; // 日志持久化失败不影响主流程
    }
  }

  /// 读取崩溃前自动落盘的日志（内存清了也能拿）。
  Future<List<Log>> persistedLogs() async {
    try {
      final f = await _ensurePersistedFile();
      if (f == null || !await f.exists()) return const [];
      final text = await f.readAsString();
      final lines = text.split('\n');
      // 文件格式：每行 "[level] time" + content。这里简单按两行一组解析
      final result = <Log>[];
      for (var i = 0; i + 1 < lines.length; i += 1) {
        final lvlLine = lines[i];
        final content = lines[i + 1];
        if (lvlLine.isEmpty && content.isEmpty) continue;
        final m = RegExp(r'^\d+\|(\d+)\|(.*)$').firstMatch(lvlLine);
        final level = m != null ? int.tryParse(m.group(1)!) ?? 0 : 0;
        final time = m != null ? (m.group(2) ?? '') : '';
        result.add(Log(level, time, content));
      }
      return result;
    } catch (_) {
      return const [];
    }
  }

  /// 把一条日志追加到滚动文件，超限时截断保留尾部（不抛异常、不影响主流程）。
  Future<void> _appendPersisted(Log log) async {
    try {
      final f = await _ensurePersistedFile();
      if (f == null) return;
      final line =
          '${log.level}|${log.time}|${log.content.replaceAll('\n', ' ')}\n';
      if (_persistedBytes + line.length > _maxPersistedBytes) {
        // 轮转：保留最近 ~一半 + 新行，兼具"能拿崩溃前"与"不撑爆存储"。
        final current = await f.readAsString();
        final keep = current.length > _maxPersistedBytes ~/ 2
            ? current.substring(current.length - _maxPersistedBytes ~/ 2)
            : current;
        await f.writeAsString(keep + line);
        _persistedBytes = keep.length + line.length;
      } else {
        await f.writeAsString(line, mode: FileMode.append);
        _persistedBytes += line.length;
      }
    } catch (_) {
      // 忽略：持久化失败绝不拖垮日志收集主流程
    }
  }

  ScrollController get scrollController => _scrollController;

  /// exportLogs 的空内存兜底：加载崩溃前自动落盘日志，若为空返回 []。
  Future<List<Log>> _loadedPersistedForExport() async {
    try {
      final p = await persistedLogs();
      return p;
    } catch (_) {
      return const [];
    }
  }

  void clearLog() {
    logs.clear();
  }

  void addLog(Log log) {
    if (isClosed) return;
    logs.add(log);
    // 同步追加到滚动文件（尽力而为，失败不打断）
    unawaited(_appendPersisted(log));
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (isClosed || !_scrollController.hasClients) return;
      _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
    });
  }

  Future<void> exportLogs(BuildContext context) async {
    // 内存为空但崩溃前自动落盘文件存在时，也允许导出（崩溃恢复场景）
    final persisted = logs.isEmpty ? await _loadedPersistedForExport() : const <Log>[];
    if (logs.isEmpty && persisted.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
content: Text(S.of(context).noLogsToExport),
        duration: const Duration(seconds: 2),
));
      return;
    }

    try {
      // 构建日志内容（优先当前内存日志；若内存为空但崩溃前自动落盘文件存在，
      // 则导出持久化日志——解决"闪退重开后日志丢失、无电脑无法导出"的问题）
      final buffer = StringBuffer();
      final exportedLogs = logs.isNotEmpty ? logs : persisted;
      buffer.writeln('OpenList Logs - Exported at ${DateTime.now().toIso8601String()}');
      buffer.writeln('=' * 60);
      buffer.writeln();

      for (final log in exportedLogs) {
        final levelStr = _getLevelString(log.level);
        buffer.writeln('[$levelStr] ${log.time}');
        buffer.writeln(log.content);
        buffer.writeln();
      }
      if (logs.isEmpty && exportedLogs.isNotEmpty) {
        buffer.writeln('--- 以上为崩溃前自动落盘日志（崩溃后恢复导出） ---');
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

      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
content: Text(S.of(context).logsExportSuccess),
        duration: const Duration(seconds: 2),
));
    } catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
content: Text('${S.of(context).logsExportFailed}: $e'),
        duration: const Duration(seconds: 3),
));
    }
  }

  String _getLevelString(int level) {
    // 与 contant/log_level.dart 的 LogLevel 常量保持一致：
    // panic=0, fatal=1, error=2, warn=3, info=4, debug=5, trace=6。
    // 历史上这里映射错位导致 info 级日志导出后显示为 [ERROR]。
    return LogLevel.toStr(level);
  }

  @override
  void onInit() {
    super.onInit();
    // 设置日志接收器，但状态变化只通过ServiceManager处理
    Event.setup(MyEventReceiver(
        (isRunning) {
          // 不在这里更新状态，避免冲突
          print('Event receiver status: $isRunning');
        }, 
        (log) => addLog(log)));
    
    NativeBridge.android.getOpenListVersion().then((value) {
      if (!isClosed) {
        openlistVersion.value = value;
      }
    });
    
    // 获取初始状态
    ServiceManager.instance.checkServiceStatus().then((isRunning) {
      if (!isClosed) {
        isSwitch.value = isRunning;
      }
    });

    // 只监听ServiceManager的状态变化
    _serviceStatusSubscription =
        ServiceManager.instance.serviceStatusStream.listen((isRunning) {
      if (isClosed) return;
      print('ServiceManager status changed: $isRunning');
      isSwitch.value = isRunning;
    });
  }

  @override
  void onClose() {
    Event.setup(null);
    unawaited(_serviceStatusSubscription?.cancel());
    _serviceStatusSubscription = null;
    _scrollController.dispose();
    super.onClose();
  }
}
