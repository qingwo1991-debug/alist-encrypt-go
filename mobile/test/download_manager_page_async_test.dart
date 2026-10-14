import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/generated/l10n.dart';
import 'package:openlist_mobile/pages/download_manager_page.dart';
import 'package:openlist_mobile/utils/download_manager.dart';

DownloadedFile file(int index) => DownloadedFile(
      path: '/downloads/file-$index.txt',
      size: 1024,
      modified: DateTime(2025, 1, 2),
    );

Future<void> showPage(
  WidgetTester tester, {
  required Stream<List<DownloadedFile>> Function() scan,
  Future<DownloadedFile?> Function(String)? read,
}) async {
  await tester.pumpWidget(MaterialApp(
    locale: const Locale('en'),
    localizationsDelegates: [S.delegate],
    supportedLocales: S.delegate.supportedLocales,
    home: DownloadManagerPage(
      scanDownloadedFiles: scan,
      readDownloadedFile: read,
      getDownloadDirectoryPath: () async => '/downloads',
    ),
  ));
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 100));
  await tester.tap(find.byIcon(Icons.download_done).first);
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 400));
}

Future<void> requestInfo(WidgetTester tester) async {
  await tester.tap(find.text('file-0.txt').first);
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 400));
  await tester.tap(find.byIcon(Icons.info));
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 400));
}

// Drain microtasks plus frames until an observable lifecycle gate is reached.
// No time-based sleeps or pumpAndSettle (the loading spinner never settles).
Future<void> pumpUntil(WidgetTester tester, bool Function() ready) async {
  for (var frames = 0; frames < 20; frames++) {
    await tester.pump();
    if (ready()) return;
  }
  fail('Lifecycle gate was not reached within 20 zero-time frames');
}

Future<void> disposePage(WidgetTester tester) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
}

void main() {
  testWidgets('gated scan yields UI events and batches render lazily',
      (tester) async {
    final scan = StreamController<List<DownloadedFile>>.broadcast();
    await showPage(tester, scan: () => scan.stream);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);

    // Refresh remains tappable while enumeration has not yielded anything.
    scan.add(List.generate(10000, file));
    await tester.pump();
    expect(find.text('file-0.txt'), findsOneWidget);
    expect(find.text('file-9999.txt'), findsNothing);
    expect(find.byType(ListTile).evaluate().length, lessThan(100));
    await tester.tap(find.byIcon(Icons.refresh));
    await tester.pump();
    expect(tester.takeException(), isNull);
    await disposePage(tester);
    await scan.close();
  });

  testWidgets('refresh cancels old scan and dispose cancels current scan',
      (tester) async {
    var firstCancelled = false;
    var secondCancelled = false;
    var secondListening = false;
    final first = StreamController<List<DownloadedFile>>(
      onCancel: () => firstCancelled = true,
    );
    final second = StreamController<List<DownloadedFile>>(
      onListen: () => secondListening = true,
      onCancel: () => secondCancelled = true,
    );
    var scans = 0;
    await showPage(tester,
        scan: () => ++scans == 1 ? first.stream : second.stream);
    first.add([file(0)]);
    await tester.pump();
    await tester.tap(find.byIcon(Icons.refresh));
    await pumpUntil(tester, () => secondListening);
    expect(firstCancelled, isTrue);
    first.add([file(99)]);
    second.add([file(1)]);
    await pumpUntil(tester, () => find.text('file-1.txt').evaluate().isNotEmpty);
    expect(find.text('file-99.txt'), findsNothing);
    expect(find.text('file-1.txt'), findsOneWidget);
    await disposePage(tester);
    expect(secondCancelled, isTrue);
    await first.close();
    await second.close();
    expect(tester.takeException(), isNull);
  });

  testWidgets('overlapping refreshes join cancellation before newest scan',
      (tester) async {
    final cancellation = Completer<void>();
    var cancelStarted = false;
    var latestListening = false;
    final first = StreamController<List<DownloadedFile>>(
      onCancel: () {
        cancelStarted = true;
        return cancellation.future;
      },
    );
    final latest = StreamController<List<DownloadedFile>>(
      onListen: () => latestListening = true,
    );
    var scans = 0;
    await showPage(tester,
        scan: () => ++scans == 1 ? first.stream : latest.stream);
    await tester.tap(find.byIcon(Icons.refresh));
    await pumpUntil(tester, () => cancelStarted);
    await tester.tap(find.byIcon(Icons.refresh));
    await tester.pump();
    await tester.pump();
    expect(scans, 1);
    expect(latestListening, isFalse);
    cancellation.complete();
    await pumpUntil(tester, () => latestListening);
    expect(scans, 2);
    latest.add([file(7)]);
    await pumpUntil(tester, () => find.text('file-7.txt').evaluate().isNotEmpty);
    await disposePage(tester);
    await first.close();
    await latest.close();
    expect(tester.takeException(), isNull);
  });

  testWidgets('scan failure remains visible and refresh recovers', (tester) async {
    var scans = 0;
    await showPage(tester,
        scan: () => ++scans == 1
            ? Stream<List<DownloadedFile>>.error(StateError('scan denied'))
            : Stream.value([file(0)]));
    expect(find.textContaining('scan denied'), findsOneWidget);
    await tester.tap(find.byIcon(Icons.refresh).first);
    await pumpUntil(tester, () => find.text('file-0.txt').evaluate().isNotEmpty);
    expect(scans, 2);
    expect(find.text('file-0.txt'), findsOneWidget);
    expect(find.textContaining('scan denied'), findsNothing);
    await disposePage(tester);
    expect(tester.takeException(), isNull);
  });

  testWidgets('info deduplicates clicks and reports disappeared file',
      (tester) async {
    final pending = Completer<DownloadedFile?>();
    var reads = 0;
    await showPage(tester,
        scan: () => Stream.value([file(0)]),
        read: (_) {
          reads++;
          return pending.future;
        });
    await requestInfo(tester);
    await requestInfo(tester);
    expect(reads, 1);
    pending.complete(null);
    await pumpUntil(tester,
        () => find.text(S.current.fileNotFound).evaluate().isNotEmpty);
    expect(tester.takeException(), isNull);
    expect(find.text(S.current.fileNotFound), findsOneWidget);
    expect(find.byType(AlertDialog), findsNothing);
    await disposePage(tester);
  });

  testWidgets('file options and long info fit a small viewport', (tester) async {
    tester.view.physicalSize = const Size(800, 400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await showPage(tester,
        scan: () => Stream.value([file(0)]),
        read: (_) async => DownloadedFile(
          path: '/downloads/${List.filled(100, 'long-directory').join('/')}/file.txt',
          size: 1024,
          modified: DateTime(2025, 1, 2),
        ));
    await tester.tap(find.text('file-0.txt').first);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
    expect(tester.takeException(), isNull);
    await tester.ensureVisible(find.byIcon(Icons.info));
    await tester.tap(find.byIcon(Icons.info));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 400));
    await pumpUntil(tester, () => find.byType(AlertDialog).evaluate().isNotEmpty);
    expect(tester.takeException(), isNull);
    await disposePage(tester);
  });

  testWidgets('info errors show snackbar and disposal ignores late read',
      (tester) async {
    final pending = Completer<DownloadedFile?>();
    var reads = 0;
    await showPage(tester,
        scan: () => Stream.value([file(0)]),
        read: (_) {
          if (++reads == 1) return Future.error(StateError('permission denied'));
          return pending.future;
        });
    await requestInfo(tester);
    expect(find.textContaining('permission denied'), findsOneWidget);
    expect(find.byType(AlertDialog), findsNothing);
    await requestInfo(tester);
    await disposePage(tester);
    pending.complete(file(0));
    await tester.pump();
    expect(find.byType(AlertDialog), findsNothing);
    expect(tester.takeException(), isNull);
  });
}
