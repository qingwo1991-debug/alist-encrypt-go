import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/contant/native_bridge.dart';
import 'package:openlist_mobile/generated_api.dart';
import 'package:openlist_mobile/pages/encrypt/encrypt_config_page.dart';

class _AppConfig extends AppConfig {
  @override
  Future<String> getDataDir() async => '/test';
}

class _EncryptProxy extends EncryptProxy {
  Completer<String>? configRequest;
  Completer<void>? hostSave;
  int hostSaves = 0;
  int portSaves = 0;
  bool failHost = false;

  @override
  Future<void> initEncryptProxy(String configPath) async {}

  @override
  Future<bool> isEncryptProxyRunning() async => false;

  @override
  Future<String> getEncryptConfigJson() async =>
      configRequest == null ? '{}' : await configRequest!.future;

  @override
  Future<void> setEncryptAlistHost(String host, int port, bool https) async {
    hostSaves++;
    if (hostSave != null) await hostSave!.future;
    if (failHost) throw StateError('host failed');
  }

  @override
  Future<void> setEncryptProxyPort(int port) async { portSaves++; }

  @override
  Future<void> setEncryptDbExportSyncConfig(bool enabled, String baseUrl,
      int intervalSeconds, bool authEnabled, String username, String password) async {}

  @override
  Future<void> setEncryptNetworkPolicy(int upstreamTimeoutSeconds,
      int probeTimeoutSeconds, int probeBudgetSeconds,
      int upstreamBackoffSeconds, bool enableLocalBypass) async {}

  @override
  Future<void> startEncryptProxy() async => throw StateError('offline');
}

void main() {
  late AppConfig originalAppConfig;
  late EncryptProxy originalProxy;
  late _EncryptProxy proxy;

  setUp(() {
    originalAppConfig = NativeBridge.appConfig;
    originalProxy = NativeBridge.encryptProxy;
    NativeBridge.appConfig = _AppConfig();
    proxy = _EncryptProxy();
    NativeBridge.encryptProxy = proxy;
  });

  tearDown(() {
    NativeBridge.appConfig = originalAppConfig;
    NativeBridge.encryptProxy = originalProxy;
  });

  Finder saveButton() => find.byWidgetPredicate(
        (widget) => widget is IconButton && widget.tooltip == '保存',
      );

  Future<void> showPage(WidgetTester tester) async {
    await tester.pumpWidget(const MaterialApp(home: EncryptConfigPage()));
    await tester.pump();
    await tester.pump();
  }

  testWidgets('late config response does not update disposed controllers', (tester) async {
    proxy.configRequest = Completer<String>();
    await showPage(tester);
    await tester.pumpWidget(const SizedBox.shrink());
    proxy.configRequest!.complete('{"alistHost":"late-host"}');
    await tester.pump();
    expect(tester.takeException(), isNull);
  });

  testWidgets('save is disabled while loading', (tester) async {
    proxy.configRequest = Completer<String>();
    await showPage(tester);
    final save = tester.widget<IconButton>(saveButton());
    expect(save.onPressed, isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    proxy.configRequest!.complete('{}');
    await tester.pump();
  });

  testWidgets('duplicate saves are ignored and failure releases the lock', (tester) async {
    await showPage(tester);
    proxy.hostSave = Completer<void>();
    proxy.failHost = true;
    final save = tester.widget<IconButton>(saveButton()).onPressed!;
    save();
    save();
    await tester.pump();
    expect(proxy.hostSaves, 1);
    expect(tester.widget<IconButton>(saveButton()).onPressed, isNull);
    proxy.hostSave!.complete();
    await tester.pumpAndSettle();
    expect(proxy.portSaves, 1);
    expect(tester.widget<IconButton>(saveButton()).onPressed, isNotNull);
    save();
    await tester.pumpAndSettle();
    expect(proxy.hostSaves, 2);
  });

  testWidgets('dispose during save stops remaining controller-dependent sections', (tester) async {
    await showPage(tester);
    proxy.hostSave = Completer<void>();
    tester.widget<IconButton>(saveButton()).onPressed!();
    await tester.pumpWidget(const SizedBox.shrink());
    proxy.hostSave!.complete();
    await tester.pump();
    expect(proxy.portSaves, 0);
    expect(tester.takeException(), isNull);
  });
}
