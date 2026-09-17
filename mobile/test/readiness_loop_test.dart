import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/readiness_loop.dart';

void main() {
  test('stops polling once check reports ready and fires onReady once',
      () async {
    var calls = 0;
    var readyCount = 0;
    final loop = ReadinessLoop(
      check: () async {
        calls++;
        return calls >= 3;
      },
      onReady: () => readyCount++,
      retryDelay: const Duration(milliseconds: 5),
    );
    loop.start();
    await Future<void>.delayed(const Duration(milliseconds: 80));
    expect(readyCount, 1);
    final callsWhenReady = calls;
    await Future<void>.delayed(const Duration(milliseconds: 40));
    expect(calls, callsWhenReady);
  });

  test('only one check runs at a time even if start is called repeatedly',
      () async {
    var concurrent = 0;
    var maxConcurrent = 0;
    Timer? timer;
    final loop = ReadinessLoop(
      check: () async {
        concurrent++;
        maxConcurrent = maxConcurrent > concurrent ? maxConcurrent : concurrent;
        await Future<void>.delayed(const Duration(milliseconds: 20));
        concurrent--;
        return false;
      },
      onReady: () {},
      retryDelay: const Duration(milliseconds: 5),
    );
    loop.start();
    loop.start();
    loop.start();
    await Future<void>.delayed(const Duration(milliseconds: 90));
    loop.dispose();
    timer?.cancel();
    expect(maxConcurrent, 1);
  });

  test('dispose stops further retries and swallows late results', () async {
    var calls = 0;
    final loop = ReadinessLoop(
      check: () async {
        calls++;
        await Future<void>.delayed(const Duration(milliseconds: 10));
        return false;
      },
      onReady: () {},
      retryDelay: const Duration(milliseconds: 5),
    );
    loop.start();
    await Future<void>.delayed(const Duration(milliseconds: 5));
    loop.dispose();
    final callsAtDispose = calls;
    await Future<void>.delayed(const Duration(milliseconds: 60));
    expect(calls, callsAtDispose);
  });

  test('check errors are reported and polling continues', () async {
    var calls = 0;
    Object? reported;
    final loop = ReadinessLoop(
      check: () async {
        calls++;
        throw StateError('boom');
      },
      onReady: () {},
      onError: (e) => reported ??= e,
      retryDelay: const Duration(milliseconds: 5),
    );
    loop.start();
    await Future<void>.delayed(const Duration(milliseconds: 40));
    loop.dispose();
    expect(reported, isA<StateError>());
    expect(calls, greaterThan(1));
  });
}
