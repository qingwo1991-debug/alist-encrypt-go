import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/download_manager.dart';

class _Adapter implements HttpClientAdapter {
  final Future<ResponseBody> Function(RequestOptions, Future<void>?) handler;
  _Adapter(this.handler);

  @override
  Future<ResponseBody> fetch(RequestOptions options,
      Stream<Uint8List>? requestStream, Future<void>? cancelFuture) {
    return handler(options, cancelFuture);
  }

  @override
  void close({bool force = false}) {}
}

ResponseBody _head(int size) => ResponseBody.fromString('', 200, headers: {
      'content-length': ['$size'],
      'accept-ranges': ['bytes'],
    });

void main() {
  late Directory directory;
  late HttpClientAdapter original;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('download-resilience-');
    original = DownloadManager.networkClientForTesting.httpClientAdapter;

  });
  tearDown(() async {
    DownloadManager.networkClientForTesting.httpClientAdapter = original;
    DownloadManager.headerBudget = const Duration(seconds: 20);
    DownloadManager.idleBudget = const Duration(seconds: 20);
    expect(DownloadManager.cancellationSubscriptions, 0);
    await directory.delete(recursive: true);
  });

  Future<void> download(String name, {CancelToken? token,
    List<String>? urls, void Function(int, int)? progress}) {
    return DownloadManager.downloadToPathForTesting(
      url: 'https://download.invalid/$name',
      urls: urls,
      filePath: '${directory.path}/$name',
      cancelToken: token,
      onProgress: progress ?? (_, __) {},
    );
  }

  test('pending downloads reserve distinct paths before files exist', () async {
    final originalPath = '${directory.path}/pending.bin';
    final reserved = <String>[];
    try {
      final first = DownloadManager.reserveDownloadPathForTesting(originalPath);
      reserved.add(first);
      final second = DownloadManager.reserveDownloadPathForTesting(originalPath);
      reserved.add(second);
      final third = DownloadManager.reserveDownloadPathForTesting(originalPath);
      reserved.add(third);
      expect(first, originalPath);
      expect(second, '${directory.path}/pending_1.bin');
      expect(third, '${directory.path}/pending_2.bin');
      expect(await File(first).exists(), isFalse);
      expect(await File(second).exists(), isFalse);
      DownloadManager.releaseDownloadPathForTesting(first);
      final reused = DownloadManager.reserveDownloadPathForTesting(originalPath);
      reserved.add(reused);
      expect(reused, originalPath);
      await File(reused).writeAsString('existing download');
      DownloadManager.releaseDownloadPathForTesting(reused);
      final next = DownloadManager.reserveDownloadPathForTesting(originalPath);
      reserved.add(next);
      expect(next, '${directory.path}/pending_3.bin');
    } finally {
      for (final path in reserved.toSet()) {
        DownloadManager.releaseDownloadPathForTesting(path);
      }
    }
  });

  test('four streams interleave batches with exact bytes at every offset',
      () async {
    const size = 10 * 1024 * 1024 + 7; // Uneven last chunk as well.
    final expected = Uint8List.fromList(
      List.generate(size, (i) => (i * 31 + i ~/ 8191) & 255),
    );
    final streams = List.generate(4, (_) => StreamController<Uint8List>());
    final ready = Completer<void>();
    var requests = 0;
    var fallback = false;
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      if (options.method == 'HEAD') return _head(size);
      final range = options.headers['Range'] as String?;
      if (range == null) {
        fallback = true;
        throw StateError('range download must not fall back');
      }
      final numbers = range.substring(6).split('-').map(int.parse).toList();
      final index = numbers[0] ~/ (size ~/ 4);
      if (++requests == 4) ready.complete();
      return ResponseBody(streams[index].stream, 206, headers: {
        'content-range': ['bytes ${numbers[0]}-${numbers[1]}/$size'],
        'content-length': ['${numbers[1] - numbers[0] + 1}'],
      });
    });
    Completer<void>? written;
    final result = download('interleaved', progress: (_, __) {
      final ack = written;
      if (ack != null && !ack.isCompleted) ack.complete();
    });
    await ready.future;
    // Acknowledgements come after the owned asynchronous seek/write finishes.
    // This forces exact alternation rather than relying on scheduler timing.
    for (final order in [<int>[0, 1, 2, 3], <int>[3, 1, 0, 2]]) {
      for (final index in order) {
        final start = index * (size ~/ 4);
        final end = index == 3 ? size : (index + 1) * (size ~/ 4);
        final middle = start + (end - start) ~/ 2;
        final first = order.first == 0;
        written = Completer<void>();
        streams[index].add(Uint8List.sublistView(
          expected, first ? start : middle, first ? middle : end,
        ));
        await written.future;
      }
    }
    await Future.wait(streams.map((stream) => stream.close()));
    await result;
    expect(fallback, isFalse);
    expect(await File('${directory.path}/interleaved').readAsBytes(),
        orderedEquals(expected));
  });

  test('failed chunk cancels hanging siblings before fallback, not user',
      () async {
    const size = 10 * 1024 * 1024;
    final ready = Completer<void>();
    final streams = List.generate(4, (_) => StreamController<Uint8List>());
    final cancelled = <int>{};
    for (var i = 0; i < 4; i++) {
      streams[i].onCancel = () { cancelled.add(i); };
    }
    var requests = 0;
    final user = CancelToken();
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      if (options.method == 'HEAD') return _head(size);
      final range = options.headers['Range'] as String?;
      if (range == null) {
        expect(cancelled, containsAll([0, 1, 2, 3]));
        expect(user.isCancelled, isFalse);
        return ResponseBody.fromString('fallback bytes', 200);
      }
      final start = int.parse(range.substring(6).split('-').first);
      final index = start ~/ (size ~/ 4);
      if (++requests == 4) ready.complete();
      return ResponseBody(streams[index].stream, 206, headers: {
        'content-range': ['bytes $start-${start + size ~/ 4 - 1}/$size'],
      });
    });
    final written = Completer<void>();
    var progressEvents = 0;
    final result = download('fallback', token: user, progress: (_, __) {
      if (++progressEvents == 3) written.complete();
    });
    await ready.future;
    // Three simultaneous producers exercise queued async positional writes
    // before the fourth fails. Fallback must join them and truncate residue.
    for (var index = 1; index < 4; index++) {
      streams[index].add(Uint8List.fromList([index, index + 1]));
    }
    await written.future;
    await streams[0].close(); // EOF before expected length; others hang.
    await result.timeout(const Duration(seconds: 2));
    expect(user.isCancelled, isFalse);
    expect(await File('${directory.path}/fallback').readAsString(),
        'fallback bytes');
    for (final stream in streams.skip(1)) {
      await stream.close();
    }
  });

  test('two global slots; queued cancellation settles and never requests',
      () async {
    final ready = Completer<void>();
    final release = Completer<void>();
    var heads = 0;
    final paths = <String>[];
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      paths.add(options.path);
      if (options.method == 'HEAD') {
        if (++heads == 2) ready.complete();
        await release.future;
        return _head(1);
      }
      return ResponseBody.fromString('x', 200);
    });
    final first = download('first');
    final second = download('second');
    await ready.future;
    final cancel = CancelToken();
    final queued = download('queued', token: cancel);
    final expectation = expectLater(queued, throwsA(isA<DioException>()));
    cancel.cancel('user cancelled while queued');
    await expectation;
    expect(paths.where((path) => path.endsWith('/queued')), isEmpty);
    expect(heads, 2);
    release.complete();
    await Future.wait([first, second]);
    await download('after'); // Cancellation did not leak or over-release slots.
  });

  test('queue rejects transfer 33 without a request or slot leak', () async {
    final ready = Completer<void>();
    final release = Completer<void>();
    var heads = 0;
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      if (options.method == 'HEAD') {
        if (++heads == 2) ready.complete();
        await release.future;
        return _head(1);
      }
      return ResponseBody.fromString('x', 200);
    });
    final first = download('bounded-first');
    final second = download('bounded-second');
    await ready.future;
    final tokens = List.generate(32, (_) => CancelToken());
    final cancellations = <Future<void>>[];
    for (var index = 0; index < tokens.length; index++) {
      cancellations.add(expectLater(
        download('pending-$index', token: tokens[index]),
        throwsA(isA<DioException>()),
      ));
    }
    await expectLater(download('overflow'), throwsA(isA<StateError>()));
    expect(heads, 2); // Rejection happens before any network or slot ownership.
    for (final token in tokens) {
      token.cancel('clear bounded queue');
    }
    await Future.wait(cancellations);
    // Removing all queued waiters permits new admission while both slots run.
    final admitted = download('new-pending');
    expect(heads, 2);
    release.complete();
    await Future.wait([first, second, admitted]);
    expect(heads, 3);
    await download('after-overflow');
    expect(heads, 4);
  });

  test('idle first mirror advances and cancels its body subscription', () async {
    DownloadManager.idleBudget = const Duration(milliseconds: 20);
    final hanging = StreamController<Uint8List>();
    final bodyCancelled = Completer<void>();
    hanging.onCancel = () { bodyCancelled.complete(); };
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      if (options.method == 'HEAD') return _head(1);
      if (options.uri.host == 'idle.invalid') {
        return ResponseBody(hanging.stream, 200);
      }
      // Dio's adapter cancellation is delivered asynchronously; require
      // actual underlying onCancel, not just the outer iterator completing.
      await bodyCancelled.future.timeout(const Duration(seconds: 2));
      return ResponseBody.fromString('healthy', 200);
    });
    await download('idle', urls: [
      'https://idle.invalid/file', 'https://healthy.invalid/file',
    ]);
    expect(await File('${directory.path}/idle').readAsString(), 'healthy');
    await hanging.close();
  });

  test('user cancellation interrupts active idle body without fallback',
      () async {
    final listening = Completer<void>();
    final hanging = StreamController<Uint8List>(
      onListen: () => listening.complete(),
    );
    var gets = 0;
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      if (options.method == 'HEAD') return _head(1);
      gets++;
      return ResponseBody(hanging.stream, 200);
    });
    final token = CancelToken();
    final result = download('active-cancel', token: token, urls: [
      'https://first.invalid/file', 'https://second.invalid/file',
    ]);
    final expectation = expectLater(result, throwsA(isA<DioException>()));
    await listening.future;
    token.cancel('user');
    await expectation.timeout(const Duration(seconds: 2));
    expect(gets, 1);
    await hanging.close();
  });

  test('reused user token leaves no cancellation subscriptions after EOF',
      () async {
    final token = CancelToken();
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, _) async {
      if (options.method == 'HEAD') return _head(1);
      return ResponseBody.fromString('x', 200);
    });
    for (var index = 0; index < 40; index++) {
      await download('reuse-$index', token: token);
      expect(DownloadManager.cancellationSubscriptions, 0);
      expect(token.isCancelled, isFalse);
    }
    token.cancel('after all completed');
    expect(DownloadManager.cancellationSubscriptions, 0);
  });

  test('first mirror header failure falls through to next source', () async {
    DownloadManager.headerBudget = const Duration(milliseconds: 20);
    final visited = <String>[];
    DownloadManager.networkClientForTesting.httpClientAdapter =
        _Adapter((options, cancelFuture) async {
      visited.add('${options.method} ${options.uri.host}');
      if (options.uri.host == 'hung.invalid') {
        await cancelFuture; // Real hang until the independent header budget.
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.cancel,
        );
      }
      return ResponseBody.fromString('second source', 200);
    });
    final token = CancelToken();
    await download('mirrors', token: token, urls: [
      'https://hung.invalid/file', 'https://good.invalid/file',
    ]);
    expect(token.isCancelled, isFalse);
    expect(visited, contains('GET good.invalid'));
    expect(await File('${directory.path}/mirrors').readAsString(),
        'second source');
  });
}
