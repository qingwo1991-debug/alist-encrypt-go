import 'dart:async';
import 'dart:io';

import 'package:openlist_mobile/generated/l10n.dart';
import 'package:openlist_mobile/pages/openlist/openlist.dart';
import 'package:openlist_mobile/pages/app_update_dialog.dart';
import 'package:openlist_mobile/pages/settings/settings.dart';
import 'package:openlist_mobile/pages/web/web.dart';
import 'package:openlist_mobile/pages/download_manager_page.dart';
import 'package:openlist_mobile/pages/encrypt/encrypt_config_page.dart';
import 'package:openlist_mobile/utils/download_manager.dart';
import 'package:openlist_mobile/utils/notification_manager.dart';
import 'package:openlist_mobile/utils/service_manager.dart';
import 'package:openlist_mobile/utils/language_controller.dart';
import 'package:fade_indexed_stack/fade_indexed_stack.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_svg/svg.dart';
import 'package:get/get.dart';

import 'contant/native_bridge.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // 初始化语言控制器
  Get.put(LanguageController());
  
  // 初始化通知管理器
  await NotificationManager.initialize();
  
  // 初始化服务管理器
  await ServiceManager.instance.initialize();
  
  // Android
  if (!kIsWeb &&
      kDebugMode &&
      defaultTargetPlatform == TargetPlatform.android) {
    await InAppWebViewController.setWebContentsDebuggingEnabled(kDebugMode);
  }

  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return GetBuilder<LanguageController>(
      builder: (languageController) {
        // 如果语言控制器设置为跟随系统，则使用null让系统自动选择
        // 否则使用指定的locale
        Locale? appLocale = languageController.locale;
        
        return GetMaterialApp(
          title: S.of(context).appName,
          themeMode: ThemeMode.system,
          theme: ThemeData(
            useMaterial3: true,
            colorSchemeSeed: Colors.teal, // 使用青色主题区分
            inputDecorationTheme: const InputDecorationTheme(
              border: OutlineInputBorder(),
            ),
          ),
          darkTheme: ThemeData(
            useMaterial3: true,
            brightness: Brightness.dark,
            colorSchemeSeed: Colors.teal,
            /* dark theme settings */
          ),
          locale: appLocale,
          fallbackLocale: const Locale('en'),
          supportedLocales: S.delegate.supportedLocales,
          localizationsDelegates: const [
            S.delegate,
            GlobalMaterialLocalizations.delegate,
            GlobalWidgetsLocalizations.delegate,
            GlobalCupertinoLocalizations.delegate,
          ],
          home: const MyHomePage(title: ""),
        );
      },
    );
  }
}

class MyHomePage extends StatelessWidget {
  const MyHomePage({super.key, required this.title});

  final String title;
  static const webPageIndex = 0;
  static const encryptPageIndex = 2; // 加密配置页面索引

  @override
  Widget build(BuildContext context) {
    final controller = Get.put(_MainController());

    return Scaffold(
        body: Obx(
          () => FadeIndexedStack(
            lazy: true,
            index: controller.selectedIndex.value,
            children: [
              WebScreen(key: webGlobalKey),
              const OpenListScreen(),
              const EncryptConfigPage(), // 加密配置页面
              const DownloadManagerPage(),
              const SettingsScreen()
            ],
          ),
        ),
        bottomNavigationBar: Obx(() => NavigationBar(
                destinations: [
                  NavigationDestination(
                    icon: const Icon(Icons.preview),
                    label: S.current.webPage,
                  ),
                  NavigationDestination(
                    icon: SvgPicture.asset(
                      "assets/openlist.svg",
                      color: Theme.of(context).hintColor,
                      width: 32,
                      height: 32,
                    ),
                    label: S.current.appName,
                  ),
                  // 加密配置入口
                  NavigationDestination(
                    icon: const Icon(Icons.lock),
                    selectedIcon: const Icon(Icons.lock_open),
                    label: '加密',
                  ),
                  NavigationDestination(
                    icon: const Icon(Icons.arrow_downward),
                    label: _getDownloadLabel(),
                  ),
                  NavigationDestination(
                    icon: const Icon(Icons.settings),
                    label: S.current.settings,
                  ),
                ],
                selectedIndex: controller.selectedIndex.value,
                onDestinationSelected: (int index) {
                  // Web
                  if (controller.selectedIndex.value == webPageIndex &&
                      index == webPageIndex) {
                    webGlobalKey.currentState?.onClickNavigationBar();
                  }

                  controller.setPageIndex(index);
                })));
  }

  String _getDownloadLabel() {
    int activeCount = DownloadManager.activeTasks.length;
    if (activeCount > 0) {
      return S.current.downloadManagerWithCount(activeCount);
    } else {
      return S.current.downloadManager;
    }
  }
}

class _MainController extends GetxController {
  final selectedIndex = 1.obs;
  static const _backendBootTimeoutSeconds = 20;
  static const _proxyBootTimeoutSeconds = 10;

  setPageIndex(int index) {
    selectedIndex.value = index;
  }

  Future<bool> _waitForLocalHTTPReady(String baseUrl, {int timeoutSeconds = 20}) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    final deadline = DateTime.now().add(Duration(seconds: timeoutSeconds));
    try {
      while (DateTime.now().isBefore(deadline)) {
        try {
          final req = await client.getUrl(Uri.parse('$baseUrl/ping'));
          final resp = await req.close().timeout(const Duration(seconds: 2));
          await resp.drain<void>();
          if (resp.statusCode >= 200 && resp.statusCode < 500) {
            return true;
          }
        } catch (_) {
          // Keep polling until timeout.
        }
        await Future.delayed(const Duration(milliseconds: 500));
      }
      return false;
    } finally {
      client.close(force: true);
    }
  }

  Future<void> _warmLocalServiceReadiness() async {
    final backendReady = await _waitForLocalHTTPReady(
      'http://127.0.0.1:5244',
      timeoutSeconds: _backendBootTimeoutSeconds,
    );
    if (!backendReady) {
      debugPrint('OpenList backend not ready within ${_backendBootTimeoutSeconds}s');
    }

    final proxyReady = await _waitForLocalHTTPReady(
      'http://127.0.0.1:5344',
      timeoutSeconds: _proxyBootTimeoutSeconds,
    );
    if (!proxyReady) {
      debugPrint('Encrypt proxy not ready within ${_proxyBootTimeoutSeconds}s');
    }
  }

  Future<void> _startLocalServers() async {
    await ServiceManager.instance.startService();

    final dataDir = await NativeBridge.appConfig.getDataDir();
    await NativeBridge.encryptProxy.initEncryptProxy('$dataDir/encrypt_config.json');
    await NativeBridge.encryptProxy.startEncryptProxy();

    unawaited(_warmLocalServiceReadiness());
  }

  @override
  void onInit() async {
    final webPage = await NativeBridge.appConfig.isAutoOpenWebPageEnabled();
    if (webPage) {
      setPageIndex(MyHomePage.webPageIndex);
    }

    try {
      await _startLocalServers();
    } catch (e) {
      debugPrint('Failed to start local servers: $e');
    }

    WidgetsBinding.instance.addPostFrameCallback((timeStamp) async {
      if (await NativeBridge.appConfig.isAutoCheckUpdateEnabled()) {
        AppUpdateDialog.checkUpdateAndShowDialog(Get.context!, null);
      }
    });

    super.onInit();
  }
}
