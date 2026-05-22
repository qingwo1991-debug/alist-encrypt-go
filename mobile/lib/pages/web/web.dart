import 'dart:developer';

import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/utils/intent_utils.dart';
import 'package:openlist_mobile/utils/download_manager.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:get/get.dart';

import '../../generated/l10n.dart';

GlobalKey<WebScreenState> webGlobalKey = GlobalKey();

class WebScreen extends StatefulWidget {
  const WebScreen({Key? key}) : super(key: key);

  @override
  State<StatefulWidget> createState() {
    return WebScreenState();
  }
}

class WebScreenState extends State<WebScreen> {
  InAppWebViewController? _webViewController;
  InAppWebViewSettings settings = InAppWebViewSettings(
    allowsInlineMediaPlayback: true,
    allowBackgroundAudioPlaying: true,
    iframeAllowFullscreen: true,
    javaScriptEnabled: true,
    mediaPlaybackRequiresUserGesture: false,
    useShouldOverrideUrlLoading: true,
  );

  double _progress = 0;
  String _url = "http://127.0.0.1:5244";
  bool _canGoBack = false;
  bool _serverReady = false;
  String _startupStatus = '';
  int _retryCount = 0;

  onClickNavigationBar() {
    log("onClickNavigationBar");
    _webViewController?.reload();
  }

  Future<void> _waitForServer() async {
    _retryCount = 0;
    while (!_serverReady && mounted) {
      final running = await Android().isRunning();
      if (running) {
        // Try a quick HTTP probe to confirm the server is actually accepting connections
        try {
          _startupStatus = '正在连接服务...';
          if (mounted) setState(() {});
          await Future.delayed(const Duration(seconds: 1));
        } catch (_) {}
        if (mounted) {
          setState(() {
            _serverReady = true;
            _startupStatus = '';
          });
          _webViewController?.reload();
        }
        return;
      }
      _retryCount++;
      final delay = (_retryCount < 10) ? 2000 : 5000;
      if (_retryCount <= 3) {
        _startupStatus = '正在启动 OpenList 服务...';
      } else if (_retryCount <= 30) {
        _startupStatus = '服务初始化中（${_retryCount}s）...';
      } else {
        _startupStatus = '服务启动较慢（${(_retryCount * 2 / 60).toStringAsFixed(1)}分钟），请耐心等待...';
      }
      if (mounted) setState(() {});
      await Future.delayed(Duration(milliseconds: delay));
    }
  }

  @override
  void initState() {
    Android().getOpenListHttpPort().then((port) async {
      final nextUrl = "http://127.0.0.1:$port";
      if (!mounted) return;
      setState(() {
        _url = nextUrl;
      });
      if (_webViewController != null) {
        await _webViewController!.loadUrl(
          urlRequest: URLRequest(url: WebUri(nextUrl)),
        );
      }
    });

    // Start background server readiness check
    _waitForServer();
    super.initState();
  }

  @override
  void dispose() {
    _webViewController?.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
        canPop: !_canGoBack,
        onPopInvoked: (didPop) async {
          log("onPopInvoked $didPop");
          if (didPop) return;
          _webViewController?.goBack();
        },
        child: Scaffold(
          body: Column(children: <Widget>[
            SizedBox(height: MediaQuery.of(context).padding.top),
            if (_startupStatus.isNotEmpty)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 16),
                color: Colors.orange.shade50,
                child: Row(
                  children: [
                    const SizedBox(
                      width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(_startupStatus,
                        style: const TextStyle(fontSize: 13, color: Colors.deepOrange)),
                    ),
                  ],
                ),
              ),
            LinearProgressIndicator(
              value: _progress,
              backgroundColor: Colors.grey[200],
              valueColor: const AlwaysStoppedAnimation<Color>(Colors.blue),
            ),
            Expanded(
              child: InAppWebView(
                initialSettings: settings,
                initialUrlRequest: URLRequest(url: WebUri(_url)),
                onWebViewCreated: (InAppWebViewController controller) {
                  _webViewController = controller;
                },
                onLoadStart: (InAppWebViewController controller, Uri? url) {
                  log("onLoadStart $url");
                  setState(() {
                    _progress = 0;
                  });
                },
                shouldOverrideUrlLoading: (controller, navigationAction) async {
                  log("shouldOverrideUrlLoading ${navigationAction.request.url}");

                  var uri = navigationAction.request.url!;
                  if (![
                    "http",
                    "https",
                    "file",
                    "chrome",
                    "data",
                    "javascript",
                    "about"
                  ].contains(uri.scheme)) {
                    log("shouldOverrideUrlLoading ${uri.toString()}");
                    final silentMode =
                        await NativeBridge.appConfig.isSilentJumpAppEnabled();
                    if (silentMode) {
                      NativeCommon().startActivityFromUri(uri.toString());
                    } else {
                      Get.showSnackbar(GetSnackBar(
                          message: S.current.jumpToOtherApp,
                          duration: const Duration(seconds: 5),
                          mainButton: TextButton(
                            onPressed: () {
                              NativeCommon()
                                  .startActivityFromUri(uri.toString());
                            },
                            child: Text(S.current.goTo),
                          )));
                    }

                    return NavigationActionPolicy.CANCEL;
                  }

                  return NavigationActionPolicy.ALLOW;
                },
                onReceivedError: (controller, request, error) async {
                  if (!await Android().isRunning()) {
                    // Server is not running yet, keep waiting
                    _serverReady = false;
                    _waitForServer();
                  }
                },
                onDownloadStartRequest: (controller, url) async {
                  Get.showSnackbar(GetSnackBar(
                    title: S.of(context).downloadThisFile,
                    message: url.suggestedFilename ??
                        url.contentDisposition ??
                        url.toString(),
                    duration: const Duration(seconds: 5),
                    mainButton: Column(children: [
                      TextButton(
                        onPressed: () async {
                          Get.closeCurrentSnackbar();
                          // 使用内置下载管理器后台下载
                          DownloadManager.downloadFileInBackground(
                            url: url.url.toString(),
                            filename: url.suggestedFilename,
                          );
                        },
                        child: Text(S.of(context).directDownload),
                      ),
                      TextButton(
                        onPressed: () {
                          IntentUtils.getUrlIntent(url.url.toString())
                              .launchChooser(S.of(context).selectAppToOpen);
                        },
                        child: Text(S.of(context).selectAppToOpen),
                      ),
                      TextButton(
                        onPressed: () {
                          IntentUtils.getUrlIntent(url.url.toString()).launch();
                        },
                        child: Text(S.of(context).browserDownload),
                      ),
                    ]),
                    onTap: (_) {
                      Clipboard.setData(
                          ClipboardData(text: url.url.toString()));
                      Get.closeCurrentSnackbar();
                      Get.showSnackbar(GetSnackBar(
                        message: S.of(context).copiedToClipboard,
                        duration: const Duration(seconds: 1),
                      ));
                    },
                  ));
                },
                onLoadStop:
                    (InAppWebViewController controller, Uri? url) async {
                  setState(() {
                    _progress = 0;
                  });
                },
                onProgressChanged:
                    (InAppWebViewController controller, int progress) {
                  setState(() {
                    _progress = progress / 100;
                    if (_progress == 1) _progress = 0;
                  });
                  controller.canGoBack().then((value) => setState(() {
                        _canGoBack = value;
                      }));
                },
                onUpdateVisitedHistory: (InAppWebViewController controller,
                    WebUri? url, bool? isReload) {
                  _url = url.toString();
                },
              ),
            ),
          ]),
        ));
  }
}
