import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/download_manager.dart';

void main() {
  group('DownloadManager.sanitizeFilename', () {
    test('drops Unix and Windows path components', () {
      expect(
        DownloadManager.sanitizeFilename('../../private/secret.txt'),
        'secret.txt',
      );
      expect(
        DownloadManager.sanitizeFilename(r'..\private\secret.txt'),
        'secret.txt',
      );
    });

    test('decodes escaped separators before dropping path components', () {
      expect(
        DownloadManager.sanitizeFilename('..%2F..%2Fsecret.apk'),
        'secret.apk',
      );
    });

    test('replaces control characters and rejects dot names', () {
      expect(
        DownloadManager.sanitizeFilename('report\u0000.txt'),
        'report_.txt',
      );
      expect(
        DownloadManager.sanitizeFilename('..'),
        startsWith('download_'),
      );
    });
  });
}
