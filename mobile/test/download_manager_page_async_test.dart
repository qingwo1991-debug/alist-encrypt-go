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
    final first = StreamController<List<DownloadedFile>>(
      onCancel: () => firstCancelled = true,
    );
    final second = StreamController<List<DownloadedFile>>(
      onCancel: () => secondCancelled = true,
    );
    var scans = 0;
    await showPage(tester,
        scan: () => ++scans == 1 ? first.stream : second.stream);
    first.add([file(0)]);
    await tester.pump();
    await tester.tap(find.byIcon(Icons.refresh));
    await tester.pump();
    expect(firstCancelled, isTrue);
    first.add([file(99)]);
    second.add([file(1)]);
    await tester.pump();
    expect(find.text('file-99.txt'), findsNothing);
    expect(find.text('file-1.txt'), findsOneWidget);
    await disposePage(tester);
    expect(secondCancelled, isTrue);
    await first.close();
    await second.close();
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
    await tester.pump();
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
    await tester.pump();
    expect(find.text(S.current.fileNotFound), findsOneWidget);
    expect(find.byType(AlertDialog), findsNothing);
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
