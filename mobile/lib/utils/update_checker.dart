import 'dart:convert';
import 'dart:core';
import 'dart:developer';
import 'dart:io';

import 'package:openlist_mobile/contant/native_bridge.dart';

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

  static Future<Map<String, dynamic>> _getLatestRelease(
      String owner, String repo, {required Duration timeout}) async {
    final client = HttpClient()..connectionTimeout = timeout;
    final req = await client.getUrl(
        Uri.parse('https://api.github.com/repos/$owner/$repo/releases/latest'));
    req.headers.set('Accept', 'application/vnd.github+json');
    req.headers.set('User-Agent', 'alist-encrypt-go');
    final response = await req.close().timeout(timeout);

    if (response.statusCode == HttpStatus.ok) {
      final body = await response.transform(utf8.decoder).join().timeout(timeout);
      return json.decode(body);
    } else {
      throw Exception(
          'Failed to get latest release, status code: ${response.statusCode}');
    }
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

  String getApkDownloadUrl() {
    final assets = data['assets'];
    String? fallback;
    for (var asset in assets) {
      final name = asset['name']?.toString() ?? '';
      if (fallback == null && name.endsWith('.apk')) {
        fallback = asset['browser_download_url'];
      }
      if (name.contains(_systemABI)) {
        return asset['browser_download_url'];
      }
    }
    if (fallback != null) {
      return fallback;
    }
    throw Exception('Failed to get apk download url for ABI: $_systemABI');
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
