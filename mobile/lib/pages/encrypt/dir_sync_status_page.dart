import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'dart:ui';

/// 展示本机代理的 DB_EXPORT 同步状态（本地导入的元数据量、轮次记录）。
///
/// 远端服务器的登录/手动触发扫描已移除：那是冗余入口，扫描由远端
/// Go 服务器自己的计划任务驱动，与其 Web UI 一致，App 无需持有会话。
class DirSyncStatusPage extends StatefulWidget {
  const DirSyncStatusPage({
    super.key,
    required this.proxyPort,
  });

  final int proxyPort;

  @override
  State<DirSyncStatusPage> createState() => _DirSyncStatusPageState();
}

class _DirSyncStatusPageState extends State<DirSyncStatusPage> {
  final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 4),
    receiveTimeout: const Duration(seconds: 8),
    sendTimeout: const Duration(seconds: 8),
  ));

  bool _loading = false;
  String? _error;
  Map<String, dynamic> _localOverview = const {};

  String get _localBaseUrl => 'http://127.0.0.1:${widget.proxyPort}';

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _dio.close(force: true);
    super.dispose();
  }

  Future<void> _load() async {
    if (!mounted || _loading) return;
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final localResp =
          await _dio.get('$_localBaseUrl/api/encrypt/sync/overview');
      final root = localResp.data;
      final data = root is Map ? root['data'] : null;
      if (mounted) {
        setState(() {
          _localOverview = data is Map<String, dynamic>
              ? data
              : const <String, dynamic>{};
        });
      }
    } catch (_) {
      if (mounted) {
        setState(() => _error = '本机同步状态获取失败，请检查代理是否运行');
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Map<String, dynamic> get _localCounts =>
      _localOverview['local_counts'] is Map<String, dynamic>
          ? _localOverview['local_counts'] as Map<String, dynamic>
          : const <String, dynamic>{};

  List<dynamic> get _recentCycles =>
      _localOverview['recent_cycles'] is List<dynamic>
          ? _localOverview['recent_cycles'] as List<dynamic>
          : const <dynamic>[];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('数据同步状态'),
        actions: [
          IconButton(
            tooltip: '刷新',
            onPressed: _loading ? null : _load,
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _load,
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _buildLocalSyncCard(context),
                  const SizedBox(height: 12),
                  _buildErrorCard(context),
                  const SizedBox(height: 24),
                ],
              ),
      ),
    );
  }

  Widget _buildLocalSyncCard(BuildContext context) {
    final theme = Theme.of(context);
    final enabled = _localOverview['enabled'] == true;
    final mode = (_localOverview['sync_mode'] ?? '-').toString();
    final lastSuccess = (_localOverview['last_success_at'] ?? '').toString();
    final lastImported = (_localOverview['last_cycle_imported'] ?? 0).toString();
    final totalImported = (_localOverview['total_imported'] ?? 0).toString();
    final lagSeconds = (_localOverview['lag_seconds'] ?? 0).toString();
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '本机 DB_EXPORT 同步',
              style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            Text(
              enabled ? '已启用' : '未启用',
              style: theme.textTheme.bodyMedium?.copyWith(
                fontWeight: FontWeight.w700,
                color: enabled ? Colors.green : Colors.orange,
              ),
            ),
            const SizedBox(height: 4),
            Text('模式：$mode', style: theme.textTheme.bodyMedium),
            const SizedBox(height: 16),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                _metricCard(context, '最近导入', lastImported),
                _metricCard(context, '累计导入', totalImported),
                _metricCard(context, '同步滞后秒', lagSeconds),
                _metricCard(context, 'size 条目', '${_localCounts['size_entries'] ?? 0}'),
                _metricCard(context, 'strategy 条目', '${_localCounts['strategy_entries'] ?? 0}'),
                _metricCard(context, 'range 条目', '${_localCounts['range_compat_entries'] ?? 0}'),
              ],
            ),
            const SizedBox(height: 16),
            _timeRow('最近成功', lastSuccess),
            const SizedBox(height: 8),
            Text(
              '最近轮次',
              style: theme.textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 8),
            if (_recentCycles.isEmpty)
              const Text('暂无同步轮次记录')
            else
              ..._recentCycles.take(5).map((cycle) {
                final item = cycle is Map<String, dynamic> ? cycle : const <String, dynamic>{};
                final ok = item['ok'] == true;
                return Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          (item['cycle_at'] ?? 0).toString(),
                          style: const TextStyle(fontFeatures: [FontFeature.tabularFigures()]),
                        ),
                      ),
                      Text(ok ? 'OK' : 'FAIL', style: TextStyle(color: ok ? Colors.green : Colors.red)),
                      const SizedBox(width: 12),
                      Text('导入 ${item['imported'] ?? 0}'),
                    ],
                  ),
                );
              }),
          ],
        ),
      ),
    );
  }

  Widget _metricCard(BuildContext context, String label, String value) {
    final theme = Theme.of(context);
    final width = (MediaQuery.of(context).size.width - 52) / 2;
    return SizedBox(
      width: width,
      child: Card(
        elevation: 0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label, style: theme.textTheme.bodySmall),
              const SizedBox(height: 8),
              Text(
                value,
                style: theme.textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w700),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _timeRow(String label, String value) {
    final display = value.trim().isEmpty ? '-' : value;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        children: [
          Expanded(child: Text(label)),
          const SizedBox(width: 12),
          Flexible(
            child: Text(
              display,
              textAlign: TextAlign.right,
              style: const TextStyle(fontFeatures: [FontFeature.tabularFigures()]),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorCard(BuildContext context) {
    final errorText =
        (_error?.trim().isNotEmpty == true) ? _error!.trim() : '';
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('最近错误', style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 12),
            Text(
              errorText.isEmpty ? '无错误' : errorText,
              style: TextStyle(
                color: errorText.isEmpty ? null : Theme.of(context).colorScheme.error,
              ),
            ),
          ],
        ),
      ),
    );
  }
}