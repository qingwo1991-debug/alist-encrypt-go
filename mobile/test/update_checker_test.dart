import 'package:flutter_test/flutter_test.dart';
import 'package:openlist_mobile/utils/update_checker.dart';

void main() {
  const owner = 'qingwo1991-debug';
  const repo = 'alist-encrypt-go';
  const tag = 'v2026.09.19.330';

  UpdateChecker buildChecker(Map<String, dynamic> release) {
    final checker = UpdateChecker(owner: owner, repo: repo);
    checker.setDataForTesting(release);
    return checker;
  }

  Map<String, dynamic> sampleAssets(List<Map<String, dynamic>> assets) => {
        'tag_name': tag,
        'assets': assets,
        'html_url': 'https://github.com/$owner/$repo/releases/tag/$tag',
        'body': 'test release',
      };

  Map<String, dynamic> asset(String name) => {
        'name': name,
        'browser_download_url':
            'https://github.com/$owner/$repo/releases/download/$tag/$name',
      };

  group('getApkDownloadUrl', () {
    test('picks exact ABI match first', () {
      final checker = buildChecker(sampleAssets([
        asset('alist-encrypt-go-linux-amd64'),
        asset('app-armeabi-v7a-release.apk'),
        asset('app-arm64-v8a-release.apk'),
        asset('app-x86_64-release.apk'),
      ]));
      // 通过环境无法注入 ABI，但 fallback 逻辑与 ABI 匹配一致：
      // arm64-v8a 在 ABI 路径下会命中 app-arm64-v8a-release.apk。
      final url = checker.getApkDownloadUrl();
      expect(
        url,
        'https://github.com/$owner/$repo/releases/download/$tag/app-arm64-v8a-release.apk',
      );
    });

    test('falls back to first apk when ABI missing', () {
      final release = buildChecker(sampleAssets([
        asset('alist-encrypt-go-linux-amd64'),
        asset('app-x86_64-release.apk'),
      ]));
      // 无 arm64 APK -> fallback 为任意 .apk
      expect(release.getApkDownloadUrl(), contains('app-x86_64-release.apk'));
    });

    test('constructable URL used when assets truncated by mirror', () {
      // 镜像截断场景：assets 仅含二进制，无任何 .apk。
      final release = buildChecker(sampleAssets([
        asset('alist-encrypt-go-linux-amd64'),
        asset('alist-encrypt-go-linux-arm64'),
        asset('encrypt-tool-linux-amd64'),
      ]));
      final url = release.getApkDownloadUrl();
      expect(
        url,
        'https://github.com/$owner/$repo/releases/download/$tag/app-arm64-v8a-release.apk',
      );
    });

    test('constructDirectApkDownloadUrl uses stable naming', () {
      expect(
        constructDirectApkDownloadUrl(
            owner: owner, repo: repo, tag: tag, abi: 'arm64-v8a'),
        'https://github.com/$owner/$repo/releases/download/$tag/app-arm64-v8a-release.apk',
      );
    });
  });

  group('compare versions', () {
    test('semver comparison handles prefixes and suffixes', () {
      expect(UpdateChecker.testCompareVersions('v2026.09.19.317', '2026.09.19.330'),
          lessThan(0));
      expect(UpdateChecker.testCompareVersions('2026.09.19.330', 'v2026.09.19.317'),
          greaterThan(0));
      expect(UpdateChecker.testCompareVersions('2026.09.19.330', 'v2026.09.19.330'), 0);
    });
  });
}