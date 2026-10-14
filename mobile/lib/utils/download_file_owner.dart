import 'dart:async';
import 'dart:io';

/// Immutable metadata: widgets never perform filesystem IO during build.
class DownloadedFile {
  final String path;
  final int size;
  final DateTime modified;
  const DownloadedFile({required this.path, required this.size,
    required this.modified});
  String get name => path.split('/').last;
}

/// Injectable async disk boundary. No per-stat isolates or synchronous IO.
class DownloadFileSystem {
  Future<bool> exists(String path) => FileSystemEntity.type(path,
    followLinks: false).then((type) => type != FileSystemEntityType.notFound);
  Future<void> create(String path) async {
    await File(path).parent.create(recursive: true);
    await File(path).create();
  }
  Future<void> delete(String path) => File(path).delete();
  Stream<String> list(String directory) => Directory(directory)
    .list(followLinks: false).map((entity) => entity.path);
  Future<DownloadedFile?> read(String path) async {
    if (await FileSystemEntity.type(path, followLinks: false) !=
        FileSystemEntityType.file) return null;
    final stat = await FileStat.stat(path);
    if (stat.type != FileSystemEntityType.file) return null;
    return DownloadedFile(path: path, size: stat.size, modified: stat.modified);
  }
}

/// One owner in the application isolate. Selection + reservation + creation are
/// one serial async command, including every awaited exists. File.create is NOT
/// O_EXCL. This protects participating downloads only: other isolates/processes
/// and external writers can still race/overwrite; no cross-process guarantee.
/// A lease is released only after all transfer workers/handles have joined.
class DownloadFileOwner {
  final DownloadFileSystem fileSystem;
  DownloadFileOwner({DownloadFileSystem? fileSystem})
    : fileSystem = fileSystem ?? DownloadFileSystem();
  Future<void> _tail = Future<void>.value();
  final Set<String> _reserved = {};
  int _commands = 0;
  Set<String> get reservedPaths => Set.unmodifiable(_reserved);
  String _canonical(String path) => File(path).absolute.uri.normalizePath().toFilePath();

  Future<T> _command<T>(Future<T> Function() run, {bool admission = false}) {
    // Releases must always drain, even when new admissions are rejected.
    if (admission && _commands >= 64) {
      return Future<T>.error(StateError('File command queue full'));
    }
    _commands++;
    final result = _tail.then((_) => run());
    _tail = result.then<void>((_) {}, onError: (Object _, StackTrace __) {})
      .whenComplete(() { _commands--; });
    return result;
  }

  Future<String> reserve(String originalPath, {void Function()? checkCancelled}) =>
    _command(() async {
      checkCancelled?.call();
      final original = _canonical(originalPath);
      final slash = original.lastIndexOf('/');
      final dot = original.lastIndexOf('.');
      final hasExtension = dot > slash + 1;
      final stem = hasExtension ? original.substring(0, dot) : original;
      final extension = hasExtension ? original.substring(dot) : '';
      var candidate = original;
      var counter = 0;
      while (_reserved.contains(candidate) || await fileSystem.exists(candidate)) {
        checkCancelled?.call();
        candidate = '${stem}_${++counter}$extension';
      }
      checkCancelled?.call();
      _reserved.add(candidate);
      var created = false;
      try {
        await fileSystem.create(candidate);
        created = true;
        checkCancelled?.call();
        return candidate;
      } catch (_) {
        if (created) {
          try { await fileSystem.delete(candidate); } catch (_) {}
        }
        _reserved.remove(candidate);
        rethrow;
      }
    }, admission: true);

  /// discard is for unsuccessful transfers, called AFTER writer join, never
  /// by cleanup while a writer can still access the path.
  Future<void> release(String path, {bool discard = false}) => _command(() async {
    final canonical = _canonical(path);
    if (!_reserved.contains(canonical)) return;
    if (discard) {
      try {
        if (await fileSystem.exists(canonical)) await fileSystem.delete(canonical);
      } finally { _reserved.remove(canonical); }
    } else {
      _reserved.remove(canonical);
    }
  });

  Future<bool> delete(String path) => _command(() async {
    final canonical = _canonical(path);
    if (_reserved.contains(canonical)) return false; // skip, never delete a writer
    if (!await fileSystem.exists(canonical)) return false;
    await fileSystem.delete(canonical);
    return true;
  }, admission: true);

  /// Only regular downloaded files; never recurse into directories or symlinks.
  /// Reservations (including callback downloads not shown in task UI) are skipped.
  Future<bool> clear(String directory) => _command(() async {
    var success = true;
    await for (final path in fileSystem.list(directory)) {
      if (_reserved.contains(_canonical(path))) continue;
      try {
        if (await fileSystem.read(path) != null) await fileSystem.delete(path);
      } on FileSystemException { success = false; }
    }
    return success;
  }, admission: true);

  Future<DownloadedFile?> read(String path) => fileSystem.read(path);

  /// Stream cancellation propagates to Directory.list, batch memory is bounded.
  /// Per-entry disappearance/permission errors do not discard other results.
  Stream<List<DownloadedFile>> scan(String directory, {int batchSize = 32}) async* {
    if (batchSize < 1 || batchSize > 128) throw ArgumentError.value(batchSize);
    var batch = <DownloadedFile>[];
    await for (final path in fileSystem.list(directory)) {
      if (_reserved.contains(_canonical(path))) continue;
      try {
        final item = await read(path);
        if (item != null) batch.add(item);
      } on FileSystemException { continue; }
      if (batch.length == batchSize) {
        yield List<DownloadedFile>.unmodifiable(batch);
        batch = <DownloadedFile>[];
        await Future<void>.delayed(Duration.zero); // allow UI events between batches
      }
    }
    if (batch.isNotEmpty) yield List<DownloadedFile>.unmodifiable(batch);
  }
}
