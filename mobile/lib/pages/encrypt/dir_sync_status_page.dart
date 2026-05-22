import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'dart:ui';

class DirSyncStatusPage extends StatefulWidget {
  const DirSyncStatusPage({
    super.key,
    required this.baseUrl,
    required this.proxyPort,
  });

  final String baseUrl;
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

  bool _loading = true;
  bool _running = false;
  String? _error;
  Map<String, dynamic> _remoteOverview = const {};
  Map<String, dynamic> _localOverview = const {};

  String get _baseUrl => widget.baseUrl.replaceFirst(RegExp(r'/+$'), '');
  String get _localBaseUrl => 'http://127.0.0.1:${widget.proxyPort}';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final localResp = await _dio.get('$_localBaseUrl/api/encrypt/sync/overview');
      final localRoot = localResp.data is Map<String, dynamic> ? localResp.data as Map<String, dynamic> : const <String, dynamic>{};
      final localData = localRoot['data'] is Map<String, dynamic> ? localRoot['data'] as Map<String, dynamic> : const <String, dynamic>{};
      Map<String, dynamic> remoteData = const <String, dynamic>{};
      if (_baseUrl.isNotEmpty) {
        final remoteResp = await _dio.get('$_baseUrl/api/encrypt/dir-sync/overview');
        final remoteRoot = remoteResp.data is Map<String, dynamic> ? remoteResp.data as Map<String, dynamic> : const <String, dynamic>{};
        remoteData = remoteRoot['data'] is Map<String, dynamic> ? remoteRoot['data'] as Map<String, dynamic> : const <String, dynamic>{};
      }
      setState(() {
        _localOverview = localData;
        _remoteOverview = remoteData;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
      });
    } finally {
      setState(() {
        _loading = false;
      });
    }
  }

  Future<void> _runSync() async {
    if (_baseUrl.isEmpty) {
      return;
    }
    setState(() {
      _running = true;
      _error = null;
    });
    try {
      await _dio.post('$_baseUrl/api/encrypt/dir-sync/run');
      await _load();
    } catch (e) {
      setState(() {
        _error = e.toString();
      });
    } finally {
      if (mounted) {
        setState(() => _running = false);
      }
    }
  }

  Map<String, dynamic> get _job =>
      _remoteOverview['current_job'] is Map<String, dynamic> ? _remoteOverview['current_job'] as Map<String, dynamic> : const <String, dynamic>{};

  Map<String, dynamic> get _snapshots =>
      _remoteOverview['snapshot_stats'] is Map<String, dynamic> ? _remoteOverview['snapshot_stats'] as Map<String, dynamic> : const <String, dynamic>{};

  Map<String, dynamic> get _localCounts =>
      _localOverview['local_counts'] is Map<String, dynamic> ? _localOverview['local_counts'] as Map<String, dynamic> : const <String, dynamic>{};

  List<dynamic> get _recentCycles =>
      _localOverview['recent_cycles'] is List<dynamic> ? _localOverview['recent_cycles'] as List<dynamic> : const <dynamic>[];

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
                  _buildHeaderCard(context),
                  const SizedBox(height: 12),
                  _buildMetricGrid(context),
                  const SizedBox(height: 12),
                  _buildSnapshotGrid(context),
                  const SizedBox(height: 12),
                  _buildTimelineCard(context),
                  const SizedBox(height: 12),
                  _buildErrorCard(context),
                  const SizedBox(height: 12),
                  FilledButton.icon(
                    onPressed: (_running || _baseUrl.isEmpty || !(_remoteOverview['scan_configured'] == true)) ? null : _runSync,
                    icon: _running
                        ? const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.play_arrow),
                    label: Text(_running ? '正在触发同步' : '立即同步'),
                  ),
                  const SizedBox(height: 24),
                ],
              ),
      ),
    );
  }

  Widget _buildHeaderCard(BuildContext context) {
    final theme = Theme.of(context);
    if (_baseUrl.isEmpty) {
      return Card(
        elevation: 0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        child: const Padding(
          padding: EdgeInsets.all(16),
          child: Text('未配置 Go 服务 API 地址，当前仅展示本机 DB_EXPORT 同步状态。'),
        ),
      );
    }
    final status = (_job['status'] ?? 'idle').toString();
    final progress = (_job['progress_percent'] as num?)?.toDouble() ?? 0;
    final scanConfigured = _remoteOverview['scan_configured'] == true;
    Color tone;
    switch (status) {
      case 'running':
        tone = Colors.blue;
        break;
      case 'done':
        tone = Colors.green;
        break;
      case 'failed':
        tone = Colors.red;
        break;
      default:
        tone = Colors.orange;
    }
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: tone.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    status.toUpperCase(),
                    style: theme.textTheme.labelMedium?.copyWith(
                      color: tone,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                const Spacer(),
                Text(
                  scanConfigured ? '已配置扫描账号' : '未配置扫描账号',
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
            const SizedBox(height: 14),
            Text(
              '主动探测 / 目录同步',
              style: theme.textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w700),
            ),
            const SizedBox(height: 6),
            Text(
              '模式：${(_remoteOverview['mode'] ?? '-').toString()}',
              style: theme.textTheme.bodyMedium,
            ),
            const SizedBox(height: 16),
            LinearProgressIndicator(
              value: progress <= 0 ? null : (progress / 100).clamp(0, 1),
              minHeight: 10,
              borderRadius: BorderRadius.circular(999),
            ),
            const SizedBox(height: 8),
            Text(
              '进度 ${progress.toStringAsFixed(0)}%',
              style: theme.textTheme.bodyMedium?.copyWith(fontWeight: FontWeight.w600),
            ),
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

  Widget _buildMetricGrid(BuildContext context) {
    return Wrap(
      spacing: 12,
      runSpacing: 12,
      children: [
        _metricCard(context, '总目录', '${_job['total_dirs_estimate'] ?? 0}'),
        _metricCard(context, '已发现', '${_job['total_dirs_discovered'] ?? 0}'),
        _metricCard(context, '已探测', '${_job['dirs_scanned'] ?? 0}'),
        _metricCard(context, '成功', '${_job['dirs_succeeded'] ?? 0}'),
        _metricCard(context, '失败', '${_job['dirs_failed'] ?? 0}'),
        _metricCard(context, '跳过', '${_job['dirs_skipped'] ?? 0}'),
      ],
    );
  }

  Widget _buildSnapshotGrid(BuildContext context) {
    return Wrap(
      spacing: 12,
      runSpacing: 12,
      children: [
        _metricCard(context, '快照总数', '${_snapshots['total_snapshots'] ?? 0}'),
        _metricCard(context, '新鲜快照', '${_snapshots['fresh_snapshots'] ?? 0}'),
        _metricCard(context, '陈旧快照', '${_snapshots['stale_snapshots'] ?? 0}'),
        _metricCard(context, '同步中', '${_snapshots['syncing_snapshots'] ?? 0}'),
      ],
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

  Widget _buildTimelineCard(BuildContext context) {
    return Card(
      elevation: 0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('时间信息', style: Theme.of(context).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700)),
            const SizedBox(height: 12),
            _timeRow('开始时间', (_job['started_at'] ?? '').toString()),
            _timeRow('最近更新时间', (_job['updated_at'] ?? '').toString()),
            _timeRow('完成时间', (_job['finished_at'] ?? '').toString()),
            _timeRow('上次成功', (_job['last_success_at'] ?? '').toString()),
            _timeRow('下次计划时间', (_job['next_run_at'] ?? '').toString()),
          ],
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
    final errorText = (_error?.trim().isNotEmpty == true)
        ? _error!.trim()
        : (_job['last_error'] ?? '').toString().trim();
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
