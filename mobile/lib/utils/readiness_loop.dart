import 'dart:async';

/// At most one check (including its async work) and one retry timer at a time.
class ReadinessLoop {
  ReadinessLoop({required this.check, required this.onReady,
    this.retryDelay = const Duration(seconds: 2), this.onError});

  final Future<bool> Function() check;
  final void Function() onReady;
  final void Function(Object error)? onError;
  final Duration retryDelay;
  Timer? _timer;
  bool _checking = false;
  bool _disposed = false;

  void start() {
    if (_disposed || _checking || _timer != null) return;
    _poll();
  }

  Future<void> _poll() async {
    _checking = true;
    var ready = false;
    try {
      ready = await check();
      if (!_disposed && ready) onReady();
    } catch (error) {
      if (!_disposed) onError?.call(error);
    } finally {
      _checking = false;
      if (!_disposed && !ready) {
        _timer = Timer(retryDelay, () {
          _timer = null;
          _poll();
        });
      }
    }
  }

  void dispose() {
    _disposed = true;
    _timer?.cancel();
    _timer = null;
  }
}
