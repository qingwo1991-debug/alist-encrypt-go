import 'dart:io';
import 'dart:typed_data';

/// Minimal disk boundary: production uses asynchronous RandomAccessFile methods.
abstract class PositionalFileHandle {
  Future<void> setPosition(int offset);
  Future<void> writeFrom(List<int> bytes);
  Future<void> flush();
  Future<void> close();
}

class _RandomAccessHandle implements PositionalFileHandle {
  final RandomAccessFile file;

  _RandomAccessHandle(this.file);

  @override
  Future<void> setPosition(int offset) async {
    await file.setPosition(offset);
  }

  @override
  Future<void> writeFrom(List<int> bytes) async {
    await file.writeFrom(bytes);
  }

  @override
  Future<void> flush() async {
    await file.flush();
  }

  @override
  Future<void> close() async {
    await file.close();
  }
}

/// Owns one file cursor and serializes the entire async seek/write transaction.
/// Each producer must await writeAt before submitting its next batch. Admission
/// includes the active write, so no more than [maxPendingWrites] batches are
/// copied/retained. A running native disk operation cannot be interrupted;
/// close seals admission synchronously and joins it before releasing the file.
class PositionalFileWriter {
  final PositionalFileHandle _handle;
  final int maxPendingWrites;
  final void Function()? _checkCancelled;
  Future<void> _tail = Future<void>.value();
  Future<void>? _closing;
  Object? _failure;
  StackTrace? _failureStack;
  int _pending = 0;
  bool _sealed = false;

  PositionalFileWriter(
    PositionalFileHandle handle, {
    this.maxPendingWrites = 4,
    void Function()? checkCancelled,
  }) : _handle = handle,
       _checkCancelled = checkCancelled {
    if (maxPendingWrites < 1) {
      throw ArgumentError.value(maxPendingWrites, 'maxPendingWrites');
    }
  }

  static Future<PositionalFileWriter> open(
    File file, {
    int maxPendingWrites = 4,
    void Function()? checkCancelled,
  }) async {
    if (maxPendingWrites < 1) {
      throw ArgumentError.value(maxPendingWrites, 'maxPendingWrites');
    }
    final handle = await file.open(mode: FileMode.write);
    return PositionalFileWriter(
      _RandomAccessHandle(handle),
      maxPendingWrites: maxPendingWrites,
      checkCancelled: checkCancelled,
    );
  }

  int get pendingWrites => _pending;

  Future<void> writeAt(int offset, List<int> bytes) {
    if (_sealed) return Future<void>.error(StateError('writer is closing'));
    if (offset < 0) return Future<void>.error(ArgumentError.value(offset));
    if (_pending >= maxPendingWrites) {
      return Future<void>.error(StateError('positional writer admission full'));
    }
    // Private ownership protects queued writes from source-buffer reuse.
    final owned = Uint8List.fromList(bytes);
    _pending++;
    final result = _tail.then<void>((_) async {
      try {
        final failure = _failure;
        if (failure != null) {
          Error.throwWithStackTrace(failure, _failureStack!);
        }
        _checkCancelled?.call();
        await _handle.setPosition(offset);
        _checkCancelled?.call();
        await _handle.writeFrom(owned);
        _checkCancelled?.call();
      } catch (error, stack) {
        _failure ??= error;
        _failureStack ??= stack;
        rethrow;
      } finally {
        _pending--;
      }
    });
    // The internal join must always settle successfully so already-admitted
    // operations can observe poison and release ownership. The caller still
    // receives the original error via result, not this internal continuation.
    _tail = result.then<void>((_) {}, onError: (Object _, StackTrace __) {});
    return result;
  }

  Future<void> close() {
    _sealed = true;
    return _closing ??= _drainAndClose();
  }

  Future<void> _drainAndClose() async {
    await _tail;
    try {
      await _handle.flush();
    } finally {
      await _handle.close();
    }
  }
}
