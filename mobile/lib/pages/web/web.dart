import 'dart:developer';
import 'dart:io';

import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/utils/download_manager.dart';
import 'package:openlist_mobile/utils/intent_utils.dart';
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
  String _loadError = '';
  int _retryCount = 0;

  onClickNavigationBar() {
    log("onClickNavigationBar");
    _webViewController?.reload();
  }

  Future<bool> _probeServerReady() async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    final probes = <Uri>[
      Uri.parse('$_url/ping'),
      Uri.parse(_url),
    ];
    try {
      for (final probe in probes) {
        try {
          final request = await client.getUrl(probe);
          final response = await request.close();
          await response.drain<void>();
          if (response.statusCode >= 200 && response.statusCode < 500) {
            return true;
          }
        } catch (_) {}
      }
      return false;
    } finally {
      client.close(force: true);
    }
  }

  Future<void> _waitForServer() async {
    _retryCount = 0;
    while (!_serverReady && mounted) {
      final running = await Android().isRunning();
      if (running) {
        _startupStatus = '服务已启动，正在加载页面资源...';
        if (mounted) setState(() {});
        final ready = await _probeServerReady();
        if (ready) {
          if (mounted) {
            setState(() {
              _serverReady = true;
              _startupStatus = '';
              _loadError = '';
            });
            _webViewController?.loadUrl(
              urlRequest: URLRequest(url: WebUri(_url)),
            );
          }
          return;
        }
      } else {
        _retryCount++;
        final delay = (_retryCount < 10) ? 2000 : 5000;
        if (_retryCount <= 3) {
          _startupStatus = '正在启动 OpenList 服务...';
        } else if (_retryCount <= 30) {
          _startupStatus = '服务初始化中（${_retryCount}s）...';
        } else {
          _startupStatus =
              '服务启动较慢（${(_retryCount * 2 / 60).toStringAsFixed(1)}分钟），请耐心等待...';
        }
        if (mounted) setState(() {});
        await Future.delayed(Duration(milliseconds: delay));
        continue;
      }
      await Future.delayed(const Duration(seconds: 1));
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
      if (_webViewController != null && _serverReady) {
        await _webViewController!.loadUrl(
          urlRequest: URLRequest(url: WebUri(nextUrl)),
        );
      }
    });

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
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(_startupStatus,
                          style: const TextStyle(
                              fontSize: 13, color: Colors.deepOrange)),
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
              child: Stack(
                children: [
                  InAppWebView(
                    initialSettings: settings,
                    initialUrlRequest: URLRequest(url: WebUri(_url)),
                    onWebViewCreated: (InAppWebViewController controller) {
                      _webViewController = controller;
                    },
                    onLoadStart: (InAppWebViewController controller, Uri? url) {
                      log("onLoadStart $url");
                      setState(() {
                        _progress = 0;
                        _loadError = '';
                      });
                    },
                    shouldOverrideUrlLoading:
                        (controller, navigationAction) async {
                      log(
                          "shouldOverrideUrlLoading ${navigationAction.request.url}");

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
                        final silentMode = await NativeBridge
                            .appConfig
                            .isSilentJumpAppEnabled();
                        if (silentMode) {
                          NativeCommon().startActivityFromUri(uri.toString());
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                          content: Text(S.current.jumpToOtherApp),
                          duration: const Duration(seconds: 5),
                          action: SnackBarAction(
                            label: S.current.goTo,
                            onPressed: () {
                              NativeCommon()
                                  .startActivityFromUri(uri.toString());
                            },
                          ),
                        ));
                        }

                        return NavigationActionPolicy.CANCEL;
                      }

                      return NavigationActionPolicy.ALLOW;
                    },
                    onReceivedError: (controller, request, error) async {
                      if (mounted) {
                        setState(() {
                          _loadError =
                              '页面加载失败: ${error.type} ${error.description}'
                                  .trim();
                        });
                      }
                      if (!await Android().isRunning()) {
                        _serverReady = false;
                        _waitForServer();
                      }
                    },
                    onReceivedHttpError:
                        (controller, request, errorResponse) async {
                      if (mounted) {
                        setState(() {
                          _loadError =
                              '页面加载失败: HTTP ${errorResponse.statusCode} ${request.url}';
                        });
                      }
                    },
                    onConsoleMessage: (controller, consoleMessage) {
                      log(
                          "console ${consoleMessage.messageLevel}: ${consoleMessage.message}");
                    },
                    onDownloadStartRequest: (controller, url) async {
                      final filename = url.suggestedFilename ??
                          url.contentDisposition ??
                          url.toString();
                      if (!context.mounted) {
                        return;
                      }
                      await showModalBottomSheet<void>(
                        context: context,
                        builder: (sheetContext) => SafeArea(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              ListTile(
                                title: Text(S.of(context).downloadThisFile),
                                subtitle: Text(
                                  filename,
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              ListTile(
                                leading: const Icon(Icons.download),
                                title: Text(S.of(context).directDownload),
                                onTap: () {
                                  Navigator.pop(sheetContext);
                                  DownloadManager.downloadFileInBackground(
                                    url: url.url.toString(),
                                    filename: url.suggestedFilename,
                                  );
                                },
                              ),
                              ListTile(
                                leading: const Icon(Icons.open_in_new),
                                title: Text(S.of(context).selectAppToOpen),
                                onTap: () {
                                  Navigator.pop(sheetContext);
                                  IntentUtils.getUrlIntent(url.url.toString())
                                      .launchChooser(
                                        S.of(context).selectAppToOpen,
                                      );
                                },
                              ),
                              ListTile(
                                leading: const Icon(Icons.language),
                                title: Text(S.of(context).browserDownload),
                                onTap: () {
                                  Navigator.pop(sheetContext);
                                  IntentUtils.getUrlIntent(url.url.toString())
                                      .launch();
                                },
                              ),
                              ListTile(
                                leading: const Icon(Icons.copy),
                                title: Text(S.of(context).copiedToClipboard),
                                onTap: () {
                                  Clipboard.setData(
                                    ClipboardData(text: url.url.toString()),
                                  );
                                  Navigator.pop(sheetContext);
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    SnackBar(
                                      content: Text(
                                        S.of(context).copiedToClipboard,
                                      ),
                                      duration: const Duration(seconds: 1),
                                    ),
                                  );
                                },
                              ),
                            ],
                          ),
                        ),
                      );
                    },
                    onLoadStop:
                        (InAppWebViewController controller, Uri? url) async {
                      setState(() {
                        _progress = 0;
                        _loadError = '';
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
                  if (_loadError.isNotEmpty)
                    Align(
                      alignment: Alignment.topCenter,
                      child: Container(
                        width: double.infinity,
                        margin: const EdgeInsets.all(12),
                        padding: const EdgeInsets.symmetric(
                            vertical: 10, horizontal: 12),
                        decoration: BoxDecoration(
                          color: Colors.red.shade50,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: Colors.red.shade200),
                        ),
                        child: Text(
                          _loadError,
                          style: TextStyle(
                            fontSize: 13,
                            color: Colors.red.shade700,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ]),
        ));
  }
}
