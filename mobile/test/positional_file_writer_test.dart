import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/positional_file_writer.dart';

class _Handle implements PositionalFileHandle {
  final List<String> events = [];
  final List<int> output = List.filled(16, 0);
  final entered = Completer<void>();
  final release = Completer<void>();
  int position = 0;
  int closes = 0;
  bool failWrite = false;
  bool failFlush = false;
  bool gateWrite = false;
  final writeEntered = Completer<void>();
  final releaseWrite = Completer<void>();

  @override
  Future<void> setPosition(int offset) async {
    events.add('seek:$offset');
    position = offset;
    if (!entered.isCompleted) {
      entered.complete();
      await release.future;
    }
  }

  @override
  Future<void> writeFrom(List<int> bytes) async {
    events.add('write:$position');
    if (failWrite) throw StateError('disk failure');
    if (gateWrite) {
      writeEntered.complete();
      await releaseWrite.future;
    }
    output.setRange(position, position + bytes.length, bytes);
    position += bytes.length;
    await Future<void>.value();
  }

  @override
  Future<void> flush() async {
    events.add('flush');
    if (failFlush) throw StateError('flush failure');
  }

  @override
  Future<void> close() async {
    events.add('close');
    closes++;
  }
}

void main() {
  test('bounded admission owns buffers and serializes async seek plus write',
      () async {
    final handle = _Handle();
    final writer = PositionalFileWriter(handle);
    final source = Uint8List.fromList([1, 2]);
    final writes = [writer.writeAt(6, source)];
    await handle.entered.future;
    source[0] = 99;
    writes.add(writer.writeAt(0, [3, 4]));
    writes.add(writer.writeAt(4, [5, 6]));
    writes.add(writer.writeAt(2, [7, 8]));
    expect(writer.pendingWrites, 4);
    await expectLater(writer.writeAt(8, [9]), throwsStateError);
    expect(handle.events, ['seek:6']);
    handle.release.complete();
    await Future.wait(writes);
    expect(writer.pendingWrites, 0);
    expect(handle.output.sublist(0, 8), [3, 4, 7, 8, 5, 6, 1, 2]);
    expect(handle.events, [
      'seek:6', 'write:6', 'seek:0', 'write:0',
      'seek:4', 'write:4', 'seek:2', 'write:2',
    ]);
    await writer.close();
  });

  test('close seals admissions then drains queued writes and closes once',
      () async {
    final handle = _Handle();
    final writer = PositionalFileWriter(handle);
    final first = writer.writeAt(0, [1]);
    await handle.entered.future;
    final second = writer.writeAt(1, [2]);
    var closed = false;
    final closing = writer.close();
    closing.then((_) => closed = true);
    expect(identical(closing, writer.close()), isTrue);
    await expectLater(writer.writeAt(2, [3]), throwsStateError);
    expect(closed, isFalse);
    expect(handle.closes, 0);
    handle.release.complete();
    await Future.wait([first, second, closing]);
    expect(handle.events, [
      'seek:0', 'write:0', 'seek:1', 'write:1', 'flush', 'close',
    ]);
    expect(handle.closes, 1);
    expect(writer.pendingWrites, 0);
  });

  test('cancellation after seek skips write and poisons queued transactions',
      () async {
    final handle = _Handle();
    var cancelled = false;
    final writer = PositionalFileWriter(handle, checkCancelled: () {
      if (cancelled) throw StateError('cancelled');
    });
    final first = writer.writeAt(0, [1]);
    final firstFailure = expectLater(first, throwsStateError);
    await handle.entered.future;
    final second = writer.writeAt(1, [2]);
    final secondFailure = expectLater(second, throwsStateError);
    cancelled = true;
    final closing = writer.close();
    expect(handle.closes, 0);
    handle.release.complete();
    await Future.wait([firstFailure, secondFailure, closing]);
    expect(handle.events, ['seek:0', 'flush', 'close']);
    expect(writer.pendingWrites, 0);
    expect(handle.closes, 1);
  });

  test('cancellation joins an already running native write before close',
      () async {
    final handle = _Handle()..gateWrite = true;
    var cancelled = false;
    final writer = PositionalFileWriter(handle, checkCancelled: () {
      if (cancelled) throw StateError('cancelled');
    });
    final failure = expectLater(writer.writeAt(0, [1]), throwsStateError);
    await handle.entered.future;
    handle.release.complete();
    await handle.writeEntered.future;
    cancelled = true;
    final closing = writer.close();
    expect(writer.pendingWrites, 1);
    expect(handle.closes, 0);
    handle.releaseWrite.complete();
    await Future.wait([failure, closing]);
    expect(handle.output[0], 1); // In-flight native writes cannot be undone.
    expect(handle.events, ['seek:0', 'write:0', 'flush', 'close']);
    expect(writer.pendingWrites, 0);
    expect(handle.closes, 1);
  });

  test('disk failure releases all queued ownership before close', () async {
    final handle = _Handle()..failWrite = true;
    final writer = PositionalFileWriter(handle);
    final firstFailure = expectLater(writer.writeAt(0, [1]), throwsStateError);
    await handle.entered.future;
    final secondFailure = expectLater(writer.writeAt(1, [2]), throwsStateError);
    final closing = writer.close();
    handle.release.complete();
    await Future.wait([firstFailure, secondFailure, closing]);
    expect(handle.events, ['seek:0', 'write:0', 'flush', 'close']);
    expect(writer.pendingWrites, 0);
    expect(handle.closes, 1);
  });

  test('flush failure still closes exactly once and keeps admission sealed',
      () async {
    final handle = _Handle()..failFlush = true;
    final writer = PositionalFileWriter(handle);
    final closing = writer.close();
    await expectLater(closing, throwsStateError);
    expect(identical(closing, writer.close()), isTrue);
    await expectLater(writer.close(), throwsStateError);
    await expectLater(writer.writeAt(0, [1]), throwsStateError);
    expect(handle.events, ['flush', 'close']);
    expect(handle.closes, 1);
  });

  test('real file async positional writes preserve every offset', () async {
    final directory = await Directory.systemTemp.createTemp('owned-writer-');
    try {
      final file = File('${directory.path}/bytes');
      final writer = await PositionalFileWriter.open(file);
      await Future.wait([
        writer.writeAt(6, [7, 8]),
        writer.writeAt(2, [3, 4]),
        writer.writeAt(0, [1, 2]),
        writer.writeAt(4, [5, 6]),
      ]);
      await writer.close();
      expect(await file.readAsBytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
    } finally {
      await directory.delete(recursive: true);
    }
  });
}
