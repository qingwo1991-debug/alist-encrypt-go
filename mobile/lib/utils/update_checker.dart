import 'dart:convert';
import 'dart:core';
import 'dart:developer';
import 'dart:io';

import 'package:openlist_mobile/contant/native_bridge.dart';

import 'proxy_speed_test.dart';

/// 根据已知 release 命名规范构造 APK 直链。
///
/// 部分镜像/代理在转发 GitHub API 时可能截断 assets 列表（例如只返回
/// 二进制而漏掉 .apk），此时 assets 中找不到 APK，更新会永远失败。
/// GitHub 上所有历史 release 的 APK 资产命名均为 `app-<abi>-release.apk`，
/// 可据此在 tag 确定的情况下直接构造官方下载 URL 作兜底。
String constructDirectApkDownloadUrl({
  required String owner,
  required String repo,
  required String tag,
  required String abi,
}) {
  return 'https://github.com/$owner/$repo/releases/download/$tag/app-$abi-release.apk';
}

class UpdateChecker {
  String owner;
  String repo;
  final bool includePrerelease;
  final Duration timeout;

  Map<String, dynamic>? _data;

  UpdateChecker({
    required this.owner,
    required this.repo,
    this.includePrerelease = false,
    this.timeout = const Duration(seconds: 10),
  });

  String _versionName = "";
  String _systemABI = "";

  downloadData() async {
    _data = await _getLatestRelease(owner, repo, timeout: timeout);
    if (_data?['prerelease'] == true && !includePrerelease) {
      throw Exception('Latest release is a prerelease');
    }
    _versionName = await NativeBridge.common.getVersionName();
    _systemABI = await NativeBridge.common.getDeviceCPUABI();
  }

  Map<String, dynamic> get data {
    if (_data == null) {
      throw Exception('Data not downloaded');
    }
    return _data!;
  }

  /// 仅供测试注入数据，避免依赖真实网络。线上路径不会调用。
  void setDataForTesting(Map<String, dynamic> data) {
    _data = data;
  }

  static Future<Map<String, dynamic>> _getLatestRelease(
      String owner, String repo, {required Duration timeout}) async {
    final candidateUrls = [
      'https://api.github.com/repos/$owner/$repo/releases/latest',
      'https://gh-proxy.com/https://api.github.com/repos/$owner/$repo/releases/latest',
      'https://ghp.ci/https://api.github.com/repos/$owner/$repo/releases/latest',
      'https://ghproxy.net/https://api.github.com/repos/$owner/$repo/releases/latest',
    ];

    final perRequestTimeout = Duration(
      milliseconds: (timeout.inMilliseconds / candidateUrls.length).clamp(2500, 5000).toInt(),
    );

    Object? lastError;
    for (final url in candidateUrls) {
      HttpClient? client;
      try {
        client = HttpClient()..connectionTimeout = perRequestTimeout;
        final req = await client.getUrl(Uri.parse(url)).timeout(perRequestTimeout);
        req.headers.set('Accept', 'application/vnd.github+json');
        req.headers.set('User-Agent', 'alist-encrypt-go');
        final response = await req.close().timeout(perRequestTimeout);

        if (response.statusCode == HttpStatus.ok) {
          final body = await response.transform(utf8.decoder).join().timeout(perRequestTimeout);
          final decoded = json.decode(body);
          if (decoded is Map<String, dynamic> && decoded.containsKey('tag_name')) {
            return decoded;
          }
        }
      } catch (e) {
        lastError = e;
        log('UpdateChecker: fetch release from $url failed: $e');
      } finally {
        client?.close(force: true);
      }
    }

    throw Exception('Failed to get latest release across all mirrors: $lastError');
  }

  String getTag() {
    return data['tag_name'];
  }

  String getDisplayVersion() {
    return _normalizeVersion(getTag());
  }

  Future<bool> hasNewVersion() async {
    final latestVersion = getTag();
    final currentVersion = _versionName;

    final result = _compareVersions(latestVersion, currentVersion);

    log('UpdateChecker: latestVersion=$latestVersion, currentVersion=$currentVersion');
    log('UpdateChecker: compare result=$result, hasNewVersion=${result > 0}');

    return result > 0;
  }

  String getApkDownloadUrl({String? abi}) {
    final targetABI = (abi == null || abi.isEmpty) ? _systemABI : abi;
    final assets = (data['assets'] as List?) ?? const [];
    final tag = getTag();
    String? fallback;
    for (var asset in assets) {
      final name = asset['name']?.toString() ?? '';
      if (fallback == null && name.endsWith('.apk')) {
        fallback = asset['browser_download_url']?.toString();
      }
      if (targetABI.isNotEmpty && name.contains(targetABI)) {
        return asset['browser_download_url']?.toString() ?? '';
      }
    }
    if (fallback != null) {
      return fallback;
    }
    // 镜像/代理可能截断 assets（如只回 14 个二进制、漏掉全部 .apk）。
    // 此时官方 URL 命名稳定：app-<abi>-release.apk，直接构造兜底，
    // 避免 App 内更新因资产缺失而永远失败。
    final constructed = constructDirectApkDownloadUrl(
        owner: owner, repo: repo, tag: tag, abi: targetABI);
    log('UpdateChecker: no APK asset in release, falling back to constructed URL: $constructed');
    return constructed;
  }

  /// 拿到本设备要下载的那个 APK 的原始 URL，生成代理前缀候选，并行测速，
  /// 返回按速度排序的下载源列表（第一个最快）。
  ///
  /// 语义：测速全失败或异常时返回 [原始URL] 单元素列表，调用方行为与
  /// 现状（直接 `getApkDownloadUrl()`）完全一致。
  Future<List<String>> getPreferredDownloadUrls() async {
    final String originalUrl;
    try {
      originalUrl = getApkDownloadUrl();
    } catch (e) {
      log('UpdateChecker: getApkDownloadUrl failed: $e');
      rethrow;
    }
    try {
      final candidates = ProxySpeedTest.buildCandidateUrls(originalUrl);
      final ranked = await ProxySpeedTest.getRankedWithCache(candidates);
      final sources = ProxySpeedTest.selectDownloadSources(ranked);
      if (sources.isEmpty) {
        return [originalUrl];
      }
      log('UpdateChecker: preferred download sources=${sources.length}: $sources');
      return sources;
    } catch (e) {
      log('UpdateChecker: speed test failed, fallback to original url: $e');
      return [originalUrl];
    }
  }

  String getUpdateContent() {
    return data['body']?.toString().trim() ?? '';
  }

  String getHtmlUrl() {
    return data['html_url']?.toString() ?? '';
  }

  /// Compare two semantic version strings
  /// Returns: positive if v1 > v2, negative if v1 < v2, 0 if equal
  /// Supports versions with 'v' prefix (e.g., "v1.2.3")
  static int _compareVersions(String v1, String v2) {
    final version1 = _normalizeVersion(v1);
    final version2 = _normalizeVersion(v2);

    // Split by dots and convert to integers
    final parts1 = version1.split('.').map((s) => int.tryParse(s) ?? 0).toList();
    final parts2 = version2.split('.').map((s) => int.tryParse(s) ?? 0).toList();

    // Compare each part
    final maxLength = parts1.length > parts2.length ? parts1.length : parts2.length;
    for (int i = 0; i < maxLength; i++) {
      final p1 = i < parts1.length ? parts1[i] : 0;
      final p2 = i < parts2.length ? parts2[i] : 0;
      if (p1 != p2) {
        return p1 - p2;
      }
    }

    return 0;
  }

  /// 版本比较的测试入口（仅测试用），线上走 [_compareVersions]。
  static int testCompareVersions(String v1, String v2) => _compareVersions(v1, v2);

  static String _normalizeVersion(String version) {
    var v = version.trim();
    if (v.toLowerCase().startsWith('v')) {
      v = v.substring(1);
    }
    final dashIndex = v.indexOf('-');
    if (dashIndex != -1) {
      v = v.substring(0, dashIndex);
    }
    final plusIndex = v.indexOf('+');
    if (plusIndex != -1) {
      v = v.substring(0, plusIndex);
    }
    return v;
  }
}
