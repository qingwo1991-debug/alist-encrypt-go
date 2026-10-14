import 'dart:async';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/download_file_owner.dart';

String _path(String name) =>
    File('download-owner-tests/$name').absolute.uri.normalizePath().toFilePath();

DownloadedFile _metadata(String path) => DownloadedFile(
      path: path,
      size: 17,
      modified: DateTime.utc(2024, 1, 2),
    );

class _Cancelled implements Exception {}

/// Every disk boundary can be suspended independently without doing real IO.
class _FakeFileSystem extends DownloadFileSystem {
  final Set<String> files = {};
  final List<String> existsCalls = [];
  final List<String> createCalls = [];
  final List<String> deleteCalls = [];
  final List<String> readCalls = [];
  final Map<String, FileSystemException> readErrors = {};
  final Map<String, FileSystemException> deleteErrors = {};
  final Set<String> missingMetadata = {};
  Future<bool> Function(String)? onExists;
  Future<void> Function(String)? onCreate;
  Stream<String> Function(String)? onList;

  @override
  Future<bool> exists(String path) async {
    existsCalls.add(path);
    final hook = onExists;
    return hook == null ? files.contains(path) : await hook(path);
  }

  @override
  Future<void> create(String path) async {
    createCalls.add(path);
    await onCreate?.call(path);
    files.add(path);
  }

  @override
  Future<void> delete(String path) async {
    deleteCalls.add(path);
    final error = deleteErrors[path];
    if (error != null) throw error;
    files.remove(path);
  }

  @override
  Stream<String> list(String directory) =>
      onList?.call(directory) ?? Stream<String>.fromIterable(files.toList());

  @override
  Future<DownloadedFile?> read(String path) async {
    readCalls.add(path);
    final error = readErrors[path];
    if (error != null) throw error;
    if (!files.contains(path) || missingMetadata.contains(path)) return null;
    return _metadata(path);
  }
}

void main() {
  group('DownloadFileOwner async reservations', () {
    test('gated exists lets event-loop work progress before creation', () async {
      final fs = _FakeFileSystem();
      final entered = Completer<void>();
      final gate = Completer<bool>();
      fs.onExists = (_) {
        entered.complete();
        return gate.future;
      };
      final owner = DownloadFileOwner(fileSystem: fs);
      final reservation = owner.reserve(_path('pending.bin'));
      await entered.future;

      var eventRan = false;
      await Future<void>.delayed(Duration.zero, () { eventRan = true; });
      expect(eventRan, isTrue);
      expect(fs.createCalls, isEmpty);
      expect(owner.reservedPaths, isEmpty);

      gate.complete(false);
      final path = await reservation;
      expect(owner.reservedPaths, {path});
      expect(fs.createCalls, [path]);
      await owner.release(path);
    });

    test('concurrent same-name reservations serialize across awaited exists',
        () async {
      final fs = _FakeFileSystem();
      final entered = Completer<void>();
      final gate = Completer<bool>();
      fs.onExists = (path) {
        if (!entered.isCompleted) {
          entered.complete();
          return gate.future;
        }
        return Future<bool>.value(fs.files.contains(path));
      };
      final owner = DownloadFileOwner(fileSystem: fs);
      final original = _path('multi.part.zip');
      final first = owner.reserve(original);
      await entered.future;
      final second = owner.reserve(original);
      final third = owner.reserve(original);
      await Future<void>.delayed(Duration.zero);
      expect(fs.existsCalls, [original]);
      expect(fs.createCalls, isEmpty);

      gate.complete(false);
      final paths = await Future.wait([first, second, third]);
      expect(paths, [original, _path('multi.part_1.zip'),
        _path('multi.part_2.zip')]);
      expect(paths.toSet(), hasLength(3));
      expect(owner.reservedPaths, paths.toSet());
      expect(fs.createCalls, paths);
    });

    test('cancellation during exists never creates or retains a lease', () async {
      final fs = _FakeFileSystem();
      final entered = Completer<void>();
      final gate = Completer<bool>();
      var cancelled = false;
      fs.onExists = (_) {
        entered.complete();
        return gate.future;
      };
      final owner = DownloadFileOwner(fileSystem: fs);
      final pending = owner.reserve(_path('cancel.bin'), checkCancelled: () {
        if (cancelled) throw _Cancelled();
      });
      final failure = expectLater(pending, throwsA(isA<_Cancelled>()));
      await entered.future;
      cancelled = true;
      gate.complete(false);
      await failure;
      expect(fs.createCalls, isEmpty);
      expect(owner.reservedPaths, isEmpty);
    });

    test('cancellation during create discards created file and frees name',
        () async {
      final fs = _FakeFileSystem();
      final entered = Completer<void>();
      final gate = Completer<void>();
      var cancelled = false;
      fs.onCreate = (_) {
        entered.complete();
        return gate.future;
      };
      final owner = DownloadFileOwner(fileSystem: fs);
      final path = _path('cancel-created.bin');
      final pending = owner.reserve(path, checkCancelled: () {
        if (cancelled) throw _Cancelled();
      });
      final failure = expectLater(pending, throwsA(isA<_Cancelled>()));
      await entered.future;
      expect(owner.reservedPaths, {path});
      cancelled = true;
      gate.complete();
      await failure;
      expect(fs.deleteCalls, [path]);
      expect(fs.files, isEmpty);
      expect(owner.reservedPaths, isEmpty);
      fs.onCreate = null;
      expect(await owner.reserve(path), path);
    });

    test('permission failure creating a file frees reservation and queue',
        () async {
      final fs = _FakeFileSystem();
      final owner = DownloadFileOwner(fileSystem: fs);
      final path = _path('denied.bin');
      fs.onCreate = (_) async {
        throw FileSystemException('Permission denied', path,
            const OSError('Permission denied', 13));
      };
      await expectLater(owner.reserve(path),
          throwsA(isA<FileSystemException>()));
      expect(owner.reservedPaths, isEmpty);
      expect(fs.deleteCalls, isEmpty);
      fs.onCreate = null;
      expect(await owner.reserve(path), path);
    });
  });

  group('DownloadFileOwner cleanup and joined writers', () {
    test('clear and delete skip active and unlisted callback leases', () async {
      final fs = _FakeFileSystem();
      final owner = DownloadFileOwner(fileSystem: fs);
      final active = await owner.reserve(_path('active.bin'));
      // A callback download has a lease but no task/UI-list entry.
      final callback = await owner.reserve(_path('callback.bin'));
      final inactive = _path('completed.bin');
      fs.files.add(inactive);
      fs.onList = (_) => Stream.fromIterable([active, callback, inactive]);

      expect(await owner.clear(_path('')), isTrue);
      expect(fs.deleteCalls, [inactive]);
      expect(fs.readCalls, [inactive]);
      expect(fs.files, {active, callback});
      expect(await owner.delete(active), isFalse);
      expect(await owner.delete(callback), isFalse);
      expect(owner.reservedPaths, {active, callback});
      expect(fs.deleteCalls, [inactive]);
    });

    test('release with discard runs only after transfer worker joins', () async {
      final fs = _FakeFileSystem();
      final owner = DownloadFileOwner(fileSystem: fs);
      final path = await owner.reserve(_path('worker.bin'));
      final workerStarted = Completer<void>();
      final workerExit = Completer<void>();
      var joined = false;
      final worker = () async {
        workerStarted.complete();
        await workerExit.future;
        // Model the last writer access before its handle/worker is joined.
        expect(fs.files, contains(path));
        joined = true;
      }();
      final transfer = () async {
        await worker;
        await owner.release(path, discard: true);
      }();
      await workerStarted.future;
      expect(await owner.clear(_path('')), isTrue);
      expect(await owner.delete(path), isFalse);
      expect(joined, isFalse);
      expect(fs.deleteCalls, isEmpty);
      expect(owner.reservedPaths, {path});

      workerExit.complete();
      await transfer;
      expect(joined, isTrue);
      expect(fs.deleteCalls, [path]);
      expect(fs.files, isEmpty);
      expect(owner.reservedPaths, isEmpty);
      await owner.release(path, discard: true);
      expect(fs.deleteCalls, [path]);
    });

    test('ordinary release retains completed file for scan and cleanup',
        () async {
      final fs = _FakeFileSystem();
      final owner = DownloadFileOwner(fileSystem: fs);
      final path = await owner.reserve(_path('completed.bin'));
      await owner.release(path);
      expect(owner.reservedPaths, isEmpty);
      expect(fs.files, {path});
      final batches = await owner.scan(_path('')).toList();
      expect(batches.single.single.path, path);
      expect(await owner.clear(_path('')), isTrue);
      expect(fs.files, isEmpty);
    });

    test('clear reports per-item errors but processes remaining entries',
        () async {
      final fs = _FakeFileSystem();
      final vanished = _path('vanished.bin');
      final unreadable = _path('unreadable.bin');
      final undeletable = _path('undeletable.bin');
      final directory = _path('not-a-file');
      final good = _path('good.bin');
      fs.files.addAll([unreadable, undeletable, directory, good]);
      fs.missingMetadata.add(directory);
      fs.readErrors[unreadable] = FileSystemException('Permission denied');
      fs.deleteErrors[undeletable] = FileSystemException('Permission denied');
      fs.onList = (_) => Stream.fromIterable(
          [vanished, unreadable, undeletable, directory, good]);
      final owner = DownloadFileOwner(fileSystem: fs);
      expect(await owner.clear(_path('')), isFalse);
      expect(fs.readCalls,
          [vanished, unreadable, undeletable, directory, good]);
      expect(fs.deleteCalls, [undeletable, good]);
      expect(fs.files, {unreadable, undeletable, directory});
    });

    test('discard delete failure still releases the lease', () async {
      final fs = _FakeFileSystem();
      final owner = DownloadFileOwner(fileSystem: fs);
      final path = await owner.reserve(_path('discard-denied.bin'));
      fs.deleteErrors[path] = FileSystemException('Permission denied');
      await expectLater(owner.release(path, discard: true),
          throwsA(isA<FileSystemException>()));
      expect(owner.reservedPaths, isEmpty);
      fs.deleteErrors.clear();
      expect(await owner.delete(path), isTrue);
    });
  });

  group('DownloadFileOwner streamed enumeration', () {
    test('gated list permits event progress and delivers incremental metadata',
        () async {
      final fs = _FakeFileSystem();
      final listening = Completer<void>();
      final input = StreamController<String>(onListen: listening.complete);
      fs.onList = (_) => input.stream;
      final owner = DownloadFileOwner(fileSystem: fs);
      final firstBatch = Completer<List<DownloadedFile>>();
      final subscription = owner.scan(_path(''), batchSize: 1)
          .listen(firstBatch.complete);
      await listening.future;
      await Future<void>.delayed(Duration.zero);
      expect(firstBatch.isCompleted, isFalse);
      expect(fs.readCalls, isEmpty);
      final path = _path('incremental.bin');
      fs.files.add(path);
      input.add(path);
      expect((await firstBatch.future).single.path, path);
      await subscription.cancel();
      await input.close();
    });

    test('scan tolerates disappearance, permission errors and non-files',
        () async {
      final fs = _FakeFileSystem();
      final vanished = _path('vanished.bin');
      final disappearedDuringStat = _path('disappeared-stat.bin');
      final denied = _path('denied.bin');
      final directory = _path('directory');
      final good = _path('good.bin');
      fs.files.addAll([disappearedDuringStat, denied, directory, good]);
      fs.missingMetadata.add(directory);
      fs.readErrors[disappearedDuringStat] =
          FileSystemException('No such file', disappearedDuringStat,
              const OSError('No such file', 2));
      fs.readErrors[denied] = FileSystemException('Permission denied', denied,
          const OSError('Permission denied', 13));
      fs.onList = (_) => Stream.fromIterable(
          [vanished, disappearedDuringStat, denied, directory, good]);
      final batches = await DownloadFileOwner(fileSystem: fs)
          .scan(_path('')).toList();
      expect(batches.single.map((item) => item.path), [good]);
      expect(fs.readCalls,
          [vanished, disappearedDuringStat, denied, directory, good]);
    });

    test('scan skips leases even when callback download has no UI task',
        () async {
      final fs = _FakeFileSystem();
      final owner = DownloadFileOwner(fileSystem: fs);
      final callback = await owner.reserve(_path('callback.bin'));
      final completed = _path('completed.bin');
      fs.files.add(completed);
      final batches = await owner.scan(_path('')).toList();
      expect(batches.single.map((item) => item.path), [completed]);
      expect(fs.readCalls, [completed]);
      expect(owner.reservedPaths, {callback});
    });

    test('default batches are bounded at 32 with no eager read-ahead', () async {
      final fs = _FakeFileSystem();
      final paths = List.generate(97, (index) => _path('$index.bin'));
      fs.files.addAll(paths);
      final sizes = <int>[];
      final observed = <String>[];
      await for (final batch in DownloadFileOwner(fileSystem: fs)
          .scan(_path(''))) {
        sizes.add(batch.length);
        expect(batch.length, lessThanOrEqualTo(32));
        observed.addAll(batch.map((item) => item.path));
        expect(fs.readCalls.length, observed.length);
        expect(() => batch.add(_metadata(_path('extra.bin'))),
            throwsUnsupportedError);
      }
      expect(sizes, [32, 32, 32, 1]);
      expect(observed, paths);
    });

    test('cancelling scan cancels list subscription without scanning remainder',
        () async {
      final fs = _FakeFileSystem();
      final cancelled = Completer<void>();
      final input = StreamController<String>(onCancel: cancelled.complete);
      fs.onList = (_) => input.stream;
      final paths = List.generate(100, (index) => _path('$index.bin'));
      fs.files.addAll(paths);
      final first = DownloadFileOwner(fileSystem: fs)
          .scan(_path('')).take(1).toList();
      for (final path in paths) {
        input.add(path);
      }
      final batches = await first;
      await cancelled.future;
      expect(batches.single, hasLength(32));
      expect(fs.readCalls, paths.take(32).toList());
      await input.close();
    });

    test('invalid batch sizes fail before opening list', () async {
      final fs = _FakeFileSystem();
      var listCalls = 0;
      fs.onList = (_) {
        listCalls++;
        return const Stream<String>.empty();
      };
      final owner = DownloadFileOwner(fileSystem: fs);
      for (final size in [0, -1, 129]) {
        await expectLater(owner.scan(_path(''), batchSize: size).toList(),
            throwsArgumentError);
      }
      expect(listCalls, 0);
    });
  });

  test('real temporary filesystem preserves multi-dot naming and file kinds',
      () async {
    final directory = await Directory.systemTemp.createTemp('download-owner-');
    addTearDown(() async { await directory.delete(recursive: true); });
    final owner = DownloadFileOwner();
    final original = '${directory.path}/archive.multi.part.zip';
    await File(original).writeAsString('existing');
    final paths = await Future.wait([
      owner.reserve(original),
      owner.reserve(original),
      owner.reserve('${directory.path}/.hidden'),
      owner.reserve('${directory.path}/.hidden'),
      owner.reserve('${directory.path}/no-extension'),
      owner.reserve('${directory.path}/no-extension'),
    ]);
    expect(paths, [
      '${directory.path}/archive.multi.part_1.zip',
      '${directory.path}/archive.multi.part_2.zip',
      '${directory.path}/.hidden',
      '${directory.path}/.hidden_1',
      '${directory.path}/no-extension',
      '${directory.path}/no-extension_1',
    ]);
    final child = await Directory('${directory.path}/keep-directory').create();
    final nested = await File('${child.path}/nested.bin').writeAsString('keep');
    final batches = await owner.scan(directory.path).toList();
    expect(batches.expand((batch) => batch).map((item) => item.path), [original]);
    expect(await owner.clear(directory.path), isTrue);
    expect(await File(original).exists(), isFalse);
    for (final path in paths) {
      expect(await File(path).exists(), isTrue);
      await owner.release(path, discard: true);
      expect(await File(path).exists(), isFalse);
    }
    expect(await nested.exists(), isTrue);
    expect(owner.reservedPaths, isEmpty);
  });
}
