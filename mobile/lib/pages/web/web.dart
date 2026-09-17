import 'dart:async';
import 'dart:developer';
import 'package:openlist_mobile/utils/readiness_loop.dart';
import 'dart:io';

import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/utils/download_manager.dart';
import 'package:openlist_mobile/utils/intent_utils.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

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
  late final ReadinessLoop _readiness;
  HttpClient? _probeClient;
  bool _backCheckPending = false;
  final Stopwatch _startupElapsed = Stopwatch();

  onClickNavigationBar() {
    log("onClickNavigationBar");
    _webViewController?.reload();
  }

  Future<bool> _probeServerReady() async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
    _probeClient = client;
    final probes = <Uri>[
      Uri.parse('$_url/ping'),
      Uri.parse(_url),
    ];
    try {
      for (final probe in probes) {
        try {
          if (!mounted) return false;
          final request = await client.getUrl(probe).timeout(const Duration(seconds: 2));
          request.followRedirects = false;
          final response = await request.close().timeout(const Duration(seconds: 2));
          await response.drain<void>().timeout(const Duration(seconds: 2));
          if (response.statusCode >= 200 && response.statusCode < 500) {
            return true;
          }
        } catch (_) {}
      }
      return false;
    } finally {
      client.close(force: true);
      if (identical(_probeClient, client)) _probeClient = null;
    }
  }

  void _setStartupStatus(String value) {
    if (mounted && _startupStatus != value) setState(() => _startupStatus = value);
  }

  Future<bool> _checkServerReady() async {
    final running = await Android().isRunning();
    if (!mounted) return false;
    if (running) {
      _setStartupStatus('服务已启动，正在加载页面资源...');
      return _probeServerReady();
    }
    _setStartupStatus('服务初始化中（${_startupElapsed.elapsed.inSeconds}s）...');
    return false;
  }

  void _waitForServer() {
    if (!mounted || _serverReady) return;
    if (!_startupElapsed.isRunning) _startupElapsed.start();
    _readiness.start();
  }

  Future<void> _initializeServer() async {
    try {
      final port = await Android().getOpenListHttpPort();
      if (!mounted) return;
      final nextUrl = 'http://127.0.0.1:$port';
      if (_url != nextUrl) setState(() => _url = nextUrl);
    } catch (_) {
      _setStartupStatus('无法读取端口，正在重试连接服务...');
    }
    _waitForServer();
  }

  Future<void> _updateCanGoBack(InAppWebViewController controller) async {
    if (!mounted || _backCheckPending) return;
    _backCheckPending = true;
    try {
      final value = await controller.canGoBack();
      if (mounted && identical(controller, _webViewController) && value != _canGoBack) {
        setState(() => _canGoBack = value);
      }
    } catch (_) {
      // Native WebView may have been destroyed while checking history.
    } finally {
      _backCheckPending = false;
    }
  }

  void _resetProgress() {
    if (mounted && (_progress != 0 || _loadError.isNotEmpty)) {
      setState(() {
        _progress = 0;
        _loadError = '';
      });
    }
  }

  Future<void> _loadReadyPage() async {
    try {
      await _webViewController?.loadUrl(urlRequest: URLRequest(url: WebUri(_url)));
    } catch (_) {
      if (mounted) setState(() => _loadError = '页面加载失败，请重试');
    }
  }

  @override
  void initState() {
    super.initState();
    _readiness = ReadinessLoop(
      check: _checkServerReady,
      onReady: () {
        if (!mounted) return;
        _startupElapsed.stop();
        setState(() {
          _serverReady = true;
          _startupStatus = '';
          _loadError = '';
        });
        unawaited(_loadReadyPage());
      },
      onError: (_) => _setStartupStatus('服务状态读取失败，正在重试...'),
    );
    unawaited(_initializeServer());
  }

  @override
  void dispose() {
    _readiness.dispose();
    _probeClient?.close(force: true);
    _startupElapsed.stop();
    _webViewController?.dispose();
    _webViewController = null;
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
                      _resetProgress();
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
                        if (!mounted) return NavigationActionPolicy.CANCEL;
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
                      if (!mounted || request.isForMainFrame == false) return;
                      final message = '页面加载失败: ${error.type} ${error.description}'.trim();
                      if (_loadError != message) setState(() => _loadError = message);
                      try {
                        final running = await Android().isRunning();
                        if (!mounted) return;
                        if (!running) {
                          _serverReady = false;
                          _waitForServer();
                        }
                      } catch (_) {
                        if (!mounted) return;
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
                      _resetProgress();
                    },
                    onProgressChanged:
                        (InAppWebViewController controller, int progress) {
                      if (!mounted) return;
                      final value = progress >= 100 ? 0.0 : progress / 100;
                      if (_progress != value) setState(() => _progress = value);
                    },
                    onUpdateVisitedHistory: (InAppWebViewController controller,
                        WebUri? url, bool? isReload) {
                      // History may point off-origin; readiness always probes
                      // the local server, never the last visited page.
                      unawaited(_updateCanGoBack(controller));
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
