import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import '../lib/utils/playback_interest.dart';

class MockInterestTransport implements PlaybackInterestTransport {
  Map<String, dynamic>? capability = {
    'version': 2, 'available': true, 'clear': true, 'canonicalPathsOnly': true,
  };
  final reports = <Map<String, dynamic>>[];
  bool fail = false;
  @override
  Future<Map<String, dynamic>?> capabilities() async => capability;
  @override
  Future<void> report(Map<String, dynamic> request) async {
    if (fail) throw StateError('offline');
    reports.add(request);
  }
}

void main() {
  final origin = Uri.parse('http://127.0.0.1:5244');
  test('old/missing capability and failed reporting never block launch', () async {
    for (final missing in [true, false]) {
      final transport = MockInterestTransport();
      if (missing) transport.capability = null;
      transport.fail = true;
      final owner = PlaybackInterestOwner(transport, origin, 'owned');
      var launched = false;
      await owner.launchChoice(ConfirmedPlaybackChoice('/A.mp4', origin), () async { launched = true; });
      expect(launched, true);
      await owner.dispose();
    }
  });
  test('late canceled chooser cannot withdraw newer choice', () async {
    final transport = MockInterestTransport();
    final owner = PlaybackInterestOwner(transport, origin, 'owned');
    final gate = Completer<void>();
    final old = owner.launchChoice(ConfirmedPlaybackChoice('/A.mp4', origin), () => gate.future);
    final expectedError = expectLater(old, throwsStateError);
    await owner.launchChoice(ConfirmedPlaybackChoice('/B.mp4', origin), () async {});
    gate.completeError(StateError('old chooser canceled'));
    await expectedError;
    await owner.settled;
    expect(transport.reports.map((r) => r['path']).toList(), ['/A.mp4', '/B.mp4']);
    await owner.dispose();
    expect(transport.reports.last['clear'], true);
    expect(transport.reports.last['generation'], 2);
  });
  test('URL-only and foreign origin choices do not infer canonical identity', () async {
    final transport = MockInterestTransport();
    final owner = PlaybackInterestOwner(transport, origin, 'owned');
    await owner.launchChoice(null, () async {});
    await owner.launchChoice(ConfirmedPlaybackChoice('/A.mp4', Uri.parse('https://foreign.invalid')), () async {});
    await owner.settled;
    expect(transport.reports, isEmpty);
  });
  test('explicit choice failure withdraws its own warm interest', () async {
    final transport = MockInterestTransport();
    final owner = PlaybackInterestOwner(transport, origin, 'owned');
    await expectLater(owner.launchChoice(ConfirmedPlaybackChoice('/A.mp4', origin), () async { throw StateError('canceled'); }), throwsStateError);
    await owner.settled;
    expect(transport.reports.last['clear'], true);
    expect(transport.reports.last['generation'], 1);
    await owner.launchChoice(ConfirmedPlaybackChoice('/B.mp4', origin), () async {});
    await owner.settled;
    expect(transport.reports.last['generation'], 2);
    expect(transport.reports.last['path'], '/B.mp4');
  });
}
