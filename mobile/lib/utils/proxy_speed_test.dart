import 'dart:async';
import 'dart:convert';
import 'dart:developer';
import 'dart:io';

import 'package:shared_preferences/shared_preferences.dart';

/// 代理前缀测速工具。
///
/// 用于应用内更新：GitHub 发布资源的 `browser_download_url` 在国内经常
/// 慢/被墙。这里对候选代理前缀并行测速，选出最快可用源，供下载阶段使用
/// （最快单源 or 多源分段叠加带宽）。
///
/// 反滥用注意：测速只对"真实发布资源"发一次 Range 小请求，不是对 CDN 扫
/// 描，也不做高频重试。结果缓存 10 分钟，避免每次检查更新都重复探测。
class ProxySpeedTest {
  /// 前置型代理：把原始 URL 直接拼到前缀后面。
  static const List<String> _prependPrefixes = [
    'https://gh-proxy.com/',
    'https://ghp.ci/',
    'https://ghproxy.net/',
  ];

  /// 域名替换型代理：github.com -> kkgithub.com（保留路径不变）。
  static const String _domainReplaceFrom = 'github.com/';
  static const String _domainReplaceTo = 'kkgithub.com/';

  static const Duration _cacheTTL = Duration(minutes: 10);
  static const String _cacheKeyPrefix = 'proxy_speed_test_v2_';

  /// 最快源的倍数阈值：在最快源 latency 的该倍以内的源视为"速度接近"，
  /// 可参与多源分段下载（带宽叠加）。
  static const double _multiSourceRatio = 1.5;

  /// 多源分段最多使用的源数（与 DownloadManager 的下载线程数对齐）。
  static const int _maxSources = 4;

  /// 单个源测速超时。
  static const Duration _probeTimeout = Duration(seconds: 3);

  /// 带缓存的测速入口：TTL 内直接返回上次结果，否则并行测速并写缓存。
  /// 返回按耗时升序（最快在前）的可用源列表。
  static Future<List<SpeedResult>> getRankedWithCache(
    List<String> urls, {
    Duration timeout = _probeTimeout,
  }) async {
    if (urls.isEmpty) return [];
    final cacheKey = _cacheKeyPrefix + _hashUrl(urls.first);
    try {
      final prefs = await SharedPreferences.getInstance();
      final cachedRaw = prefs.getString(cacheKey);
      if (cachedRaw != null) {
        final cached = _CachedResult.fromJson(json.decode(cachedRaw));
        if (DateTime.now().difference(cached.timestamp) < _cacheTTL) {
          log('ProxySpeedTest: cache hit for ${urls.first}');
          return cached.results;
        }
      }
    } catch (e) {
      log('ProxySpeedTest: cache read failed: $e');
    }

    final results = await speedTestAndRank(urls, timeout: timeout);
    if (results.isNotEmpty) {
      try {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString(
          cacheKey,
          json.encode(_CachedResult(results, DateTime.now()).toJson()),
        );
      } catch (e) {
        log('ProxySpeedTest: cache write failed: $e');
      }
    }
    return results;
  }

  /// 并行测速，返回按耗时升序（最快在前）的可用源。
  static Future<List<SpeedResult>> speedTestAndRank(
    List<String> urls, {
    Duration timeout = _probeTimeout,
  }) async {
    final all = await Future.wait(
      urls.map((url) => _measureOne(url, timeout)),
    );
    final ok = all.where((r) => r.ok).toList();
    ok.sort((a, b) => a.latencyMs.compareTo(b.latencyMs));
    return ok;
  }

  /// 根据原始 URL 生成候选下载 URL 列表（原始 URL 打头）。
  static List<String> buildCandidateUrls(String originalUrl) {
    final trimmed = originalUrl.trim();
    if (trimmed.isEmpty) return [];
    final candidates = <String>[trimmed];
    for (final prefix in _prependPrefixes) {
      candidates.add('$prefix$trimmed');
    }
    if (trimmed.contains(_domainReplaceFrom)) {
      candidates.add(trimmed.replaceFirst(_domainReplaceFrom, _domainReplaceTo));
    }
    return candidates;
  }

  /// 从测速结果里挑出用于下载的源 URL 列表：
  /// - 全失败 → 空列表，调用方回退原始 URL 单源。
  /// - 仅 1 个可用 → [最快源]。
  /// - ≥2 个可用且都在最快源 _multiSourceRatio 倍内 → 多源分段（最多 _maxSources）。
  static List<String> selectDownloadSources(List<SpeedResult> ranked) {
    if (ranked.isEmpty) return [];
    final fastest = ranked[0].latencyMs;
    final sources = <String>[ranked[0].url];
    for (var i = 1; i < ranked.length && sources.length < _maxSources; i++) {
      if (ranked[i].latencyMs <= fastest * _multiSourceRatio) {
        sources.add(ranked[i].url);
      } else {
        break;
      }
    }
    return sources;
  }

  static Future<SpeedResult> _measureOne(String url, Duration timeout) async {
    final stopwatch = Stopwatch()..start();
    HttpClient? client;
    try {
      client = HttpClient()..connectionTimeout = timeout;
      final req = await client.getUrl(Uri.parse(url)).timeout(timeout);
      req.headers.set('Range', 'bytes=0-1023');
      req.headers.set('User-Agent', 'alist-encrypt-go');
      final response = await req.close().timeout(timeout);
      final statusOk = response.statusCode >= 200 && response.statusCode < 400;
      // 读第一个字节作为 TTFB（确认数据通路真正建立，而不只是 TCP 连上）。
      if (statusOk) {
        await response.first.timeout(timeout);
      } else {
        await response.drain<void>().timeout(timeout);
      }
      stopwatch.stop();
      return SpeedResult(url, stopwatch.elapsedMilliseconds, statusOk);
    } catch (e) {
      stopwatch.stop();
      return SpeedResult(url, stopwatch.elapsedMilliseconds, false);
    } finally {
      client?.close(force: true);
    }
  }

  static String _hashUrl(String url) {
    var hash = 0;
    for (final unit in url.codeUnits) {
      hash = (hash * 31 + unit) & 0x7fffffff;
    }
    return hash.toRadixString(16);
  }
}

/// 单个源的一次测速结果。
class SpeedResult {
  final String url;
  final int latencyMs;
  final bool ok;

  const SpeedResult(this.url, this.latencyMs, this.ok);

  factory SpeedResult.fromJson(Map<String, dynamic> json) {
    return SpeedResult(
      json['url']?.toString() ?? '',
      (json['latency'] as num?)?.toInt() ?? 0,
      (json['ok'] as bool?) ?? false,
    );
  }

  Map<String, dynamic> toJson() => {
        'url': url,
        'latency': latencyMs,
        'ok': ok,
      };
}

class _CachedResult {
  final List<SpeedResult> results;
  final DateTime timestamp;

  _CachedResult(this.results, this.timestamp);

  factory _CachedResult.fromJson(Map<String, dynamic> json) {
    final list = (json['results'] as List?) ?? [];
    final results = list
        .map((e) => SpeedResult.fromJson((e as Map).cast<String, dynamic>()))
        .where((r) => r.ok)
        .toList();
    final ts = DateTime.tryParse(json['ts']?.toString() ?? '') ?? DateTime.now();
    return _CachedResult(results, ts);
  }

  Map<String, dynamic> toJson() => {
        'results': results.map((r) => r.toJson()).toList(),
        'ts': timestamp.toIso8601String(),
      };
}
