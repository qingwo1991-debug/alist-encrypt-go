import 'dart:async';

/// Caller supplies a transport bound to its authenticated, confirmed server.
/// Raw download URLs and WebView JS cannot create canonical object identity.
abstract class PlaybackInterestTransport {
  Future<Map<String, dynamic>?> capabilities();
  Future<void> report(Map<String, dynamic> request);
}

/// Only create after the caller's fs/get confirmation in the current auth/rule
/// scope. This adapter never guesses a logical path from a signed/raw URL.
class ConfirmedPlaybackChoice {
  final String canonicalPath;
  final Uri serverOrigin;
  const ConfirmedPlaybackChoice(this.canonicalPath, this.serverOrigin);
}

/// One owner for explicit application choices, not actual external player state.
/// Capability/report failure must never block ordinary launch. Unknown energy/
/// network inputs disable optional speculative warming; this sends none.
class PlaybackInterestOwner {
  final PlaybackInterestTransport transport;
  final Uri trustedOrigin;
  final String session;
  int _generation = 0;
  bool _disposed = false;
  Future<void> _pending = Future<void>.value();

  PlaybackInterestOwner(this.transport, this.trustedOrigin, this.session);

  Future<void> _report(int generation, String? path) async {
    try {
      final capability = await transport.capabilities()
          .timeout(const Duration(seconds: 2));
      final supported = capability?['version'] == 2 &&
          capability?['available'] == true && capability?['clear'] == true &&
          capability?['canonicalPathsOnly'] == true;
      if (!supported) return;
      await transport.report({
        'session': session, 'generation': generation,
        if (path != null) 'path': path else 'clear': true,
      }).timeout(const Duration(seconds: 2));
    } catch (_) {
      // Old service, failed auth, or offline reporting is not failed playback.
    }
  }

  void _enqueue(int generation, String? path) {
    _pending = _pending.then((_) => _report(generation, path));
  }

  void _clearCurrentChoice() {
    if (_generation > 0) _enqueue(_generation, null);
  }

  /// The launcher runs immediately, independently of capability and reporting.
  /// A failed/canceled *owned choice* withdraws only that generation; a late
  /// completion from an older chooser cannot erase a newer launch.
  Future<void> launchChoice(
      ConfirmedPlaybackChoice? choice, Future<void> Function() launch) async {
    if (_disposed) { await launch(); return; }
    final path = choice?.canonicalPath;
    final canonical = path != null && path.startsWith('/') &&
        !path.contains('\\') && !path.contains('\u0000') &&
        !path.contains('//') && (path == '/' || !path.endsWith('/')) &&
        !path.split('/').any((part) => part == '..' || part == '.');
    final adapted = canonical && choice!.serverOrigin == trustedOrigin;
    if (adapted) _enqueue(++_generation, path);
    final launchedGeneration = _generation;
    try {
      await launch();
    } catch (_) {
      if (adapted && !_disposed && launchedGeneration == _generation) {
        _enqueue(launchedGeneration, null);
      }
      rethrow;
    }
  }

  /// Explicit app-owned cancellation only; app foreground/resume is not exit.
  void withdrawChoice() { if (!_disposed) _clearCurrentChoice(); }

  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    _clearCurrentChoice();
    await _pending;
  }

  Future<void> get settled => _pending;
}
