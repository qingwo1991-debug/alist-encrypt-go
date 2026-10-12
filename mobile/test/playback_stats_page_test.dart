import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/pages/settings/playback_stats_page.dart';

Map<String, dynamic> record(int timestamp, {num? firstByte, num? header}) => {
      'path': '/video-$timestamp',
      'played_at': timestamp,
      if (firstByte != null) 'first_byte_latency_ms': firstByte,
      if (header != null) 'header_latency_ms': header,
    };

Future<void> showPage(WidgetTester tester, List<dynamic> records) async {
  await tester.pumpWidget(MaterialApp(
    home: PlaybackStatsPage(loadStats: () async => {'playbacks': records}),
  ));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('body-first-byte quantiles exclude absent fields and retain zero',
      (tester) async {
    await showPage(tester, [
      record(1, header: 999),
      record(2, firstByte: 0, header: 500),
      record(3, firstByte: 20),
      record(4, firstByte: 40),
      record(5, firstByte: 100),
    ]);
    expect(find.text('服务端正文首字节 · p50 40ms · p95 100ms'), findsOneWidget);
    expect(find.textContaining('均非播放器真实首帧'), findsOneWidget);
    await tester.scrollUntilVisible(find.text('/video-2'), 200);
    expect(find.textContaining('正文首字节0ms · 上游响应头500ms'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('current header-only mobile export is unknown not a fallback',
      (tester) async {
    await showPage(tester, [record(1, header: 999)]);
    expect(find.text('服务端正文首字节 · 暂无正文首字节数据'), findsOneWidget);
    await tester.scrollUntilVisible(find.text('/video-1'), 200);
    expect(find.textContaining('正文首字节-ms · 上游响应头999ms'), findsOneWidget);
    expect(find.textContaining('首帧耗时'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('all-zero measured latency paints without an exception',
      (tester) async {
    await showPage(tester, [record(1, firstByte: 0)]);
    expect(find.text('服务端正文首字节 · p50 0ms · p95 0ms'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
