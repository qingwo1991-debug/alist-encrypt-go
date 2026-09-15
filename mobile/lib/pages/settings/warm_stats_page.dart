import 'dart:convert';
import 'dart:developer';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:openlist_mobile/contant/native_bridge.dart';

/// 预热统计页：独立统计面板。
///
/// 首帧耗时折线图 + 预热明细 + 播放/删除记录，一次拉取本地代理的
/// `/api/encrypt/exportStats`（独立统计密码鉴权，与加密/管理密码独立）。
class WarmStatsPage extends StatefulWidget {
  const WarmStatsPage({super.key});

  @override
  State<WarmStatsPage> createState() => _WarmStatsPageState();
}

class _WarmStatsPageState extends State<WarmStatsPage> {
  final _passwordController = TextEditingController();
  static const _proxyPort = 5344;

  bool _loading = true;
  bool _exporting = false;
  String? _error;

  List<dynamic> _playbacks = [];
  List<dynamic> _deletions = [];
  List<dynamic> _warmEvents = [];
  Map<String, dynamic> _probeStats = {};

  @override
  void initState() {
    super.initState();
    _loadPassword();
  }

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _loadPassword() async {
    try {
      final configJson =
          await NativeBridge.encryptProxy.getEncryptConfigJson();
      final decoded = json.decode(configJson);
      final config = decoded is Map<String, dynamic>
          ? decoded
          : <String, dynamic>{};
      if (mounted) {
        setState(() {
          _passwordController.text = config['statsPassword']?.toString() ?? '';
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '读取配置失败: $e';
          _loading = false;
        });
      }
    }
  }

  Future<void> _savePassword() async {
    final password = _passwordController.text.trim();
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 3),
        receiveTimeout: const Duration(seconds: 5),
      ));
      await dio.post(
        'http://127.0.0.1:$_proxyPort/api/encrypt/v2/config',
        data: {
          'version': 2,
          'config': {'statsPassword': password},
        },
      );
      if (mounted) {
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(const SnackBar(content: Text('统计密码已保存')));
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(const SnackBar(content: Text('保存失败（代理未运行？）')));
      }
    }
  }

  Future<void> _exportStats() async {
    final password = _passwordController.text.trim();
    if (password.isEmpty) {
      _toast('请先设置统计密码并保存');
      return;
    }
    setState(() {
      _exporting = true;
      _error = null;
    });
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 3),
        receiveTimeout: const Duration(seconds: 15),
      ));
      final resp = await dio.get(
        'http://127.0.0.1:$_proxyPort/api/encrypt/exportStats',
        queryParameters: {'password': password},
      );
      if (resp.statusCode == 401) throw Exception('统计密码错误');
      if (resp.statusCode == 404) throw Exception('统计功能未开启（未设置密码）');
      final root = resp.data is Map<String, dynamic>
          ? resp.data as Map<String, dynamic>
          : <String, dynamic>{};
      if (mounted) {
        setState(() {
          _playbacks = root['playbacks'] as List<dynamic>? ?? [];
          _deletions = root['deletions'] as List<dynamic>? ?? [];
          _warmEvents = root['warm_events'] as List<dynamic>? ?? [];
          _probeStats = root['probe_stats'] as Map<String, dynamic>? ?? {};
          _exporting = false;
        });
        log('预热统计导出：播放 ${_playbacks.length}，预热 ${_warmEvents.length}');
        ScaffoldMessenger.of(context)
          ..hideCurrentSnackBar()
          ..showSnackBar(SnackBar(
              content:
                  Text('已载入：播放 ${_playbacks.length} · 预热 ${_warmEvents.length}')));
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _exporting = false;
          _error = '导出失败: $e';
        });
      }
    }
  }

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(msg)));
  }

  // ── 摘要数据 ─────────────────────────────

  List<Map<String, dynamic>> get _latencySeries {
    final rows = <Map<String, dynamic>>[];
    for (final p in _playbacks) {
      final lat = (p['header_latency_ms'] as num?)?.toDouble() ?? 0;
      if (lat > 0) rows.add({'t': p, 'v': lat});
    }
    rows.sort((a, b) => ((a['t']['played_at'] ?? 0) as num)
        .compareTo(((b['t']['played_at'] ?? 0) as num)));
    return rows.length > 200 ? rows.sublist(rows.length - 200) : rows;
  }

  List<Map<String, dynamic>> get _mbpsSeries {
    final list = <Map<String, dynamic>>[];
    for (final p in _playbacks) {
      final mb = (p['mbps'] as num?)?.toDouble() ?? 0;
      if (mb > 0) list.add({'t': p, 'v': mb});
    }
    list.sort((a, b) => ((a['t']['played_at'] ?? 0) as num)
        .compareTo(((b['t']['played_at'] ?? 0) as num)));
    return list.length > 200 ? list.sublist(list.length - 200) : list;
  }

  double? _percentile(List<double> sorted, double q) {
    if (sorted.isEmpty) return null;
    final idx = (q * (sorted.length - 1)).round().clamp(0, sorted.length - 1);
    return sorted[idx];
  }

  int get _warmOk =>
      _warmEvents.where((e) => (e['status'] ?? '') == 'ok').length;
  int get _warmFail =>
      _warmEvents.where((e) => (e['status'] ?? '') == 'fail').length +
      _warmEvents.where((e) => (e['status'] ?? '') == 'timeout').length;

  double? get _peakMbps {
    final vs = _mbpsSeries.map((e) => e['v'] as double).toList();
    if (vs.isEmpty) return null;
    return vs.reduce((a, b) => a > b ? a : b);
  }

  String _latencySummary() {
    final vs = _latencySeries.map((e) => e['v'] as double).toList()..sort();
    final p50 = _percentile(vs, 0.5);
    final p95 = _percentile(vs, 0.95);
    if (p50 == null) return '暂无首帧数据';
    if (p95 == null) return '${p50.toStringAsFixed(0)}ms';
    return 'p50 ${p50.toStringAsFixed(0)}ms · p95 ${p95.toStringAsFixed(0)}ms';
  }

  String _latencyP50() {
    final vs = _latencySeries.map((e) => e['v'] as double).toList()..sort();
    final p50 = _percentile(vs, 0.5);
    if (p50 == null) return '暂无首帧数据';
    return '${p50.toStringAsFixed(0)}ms';
  }

  String _fmtDuration(num? secs) {
    final s = (secs ?? 0).toDouble();
    if (s < 60) return '${s.toStringAsFixed(0)}s';
    if (s < 3600) return '${(s ~/ 60).toInt()}m ${(s % 60).toInt()}s';
    return '${(s ~/ 3600).toInt()}h ${((s % 3600) ~/ 60).toInt()}m';
  }

  String _fmtBytes(num? bytes) {
    final n = (bytes ?? 0).toDouble();
    if (n < 1024) return '${n.toInt()}B';
    if (n < 1024 * 1024) return '${(n / 1024).toStringAsFixed(1)}KB';
    if (n < 1024 * 1024 * 1024) return '${(n / (1024 * 1024)).toStringAsFixed(1)}MB';
    return '${(n / (1024 * 1024 * 1024)).toStringAsFixed(1)}GB';
  }

  String _fmtTime(num? ts) {
    final t = (ts ?? 0).toInt();
    if (t <= 0) return '-';
    final d = DateTime.fromMillisecondsSinceEpoch(t * 1000);
    String p(int v) => v.toString().padLeft(2, '0');
    return '${p(d.month)}-${p(d.day)} ${p(d.hour)}:${p(d.minute)}';
  }

  String _fmtObs(Map<String, dynamic> p) {
    final lat = (p['header_latency_ms'] as num?)?.toDouble() ?? 0;
    final mb = (p['mbps'] as num?)?.toDouble() ?? 0;
    final buf = StringBuffer();
    if (lat > 0) buf.write('首帧 ${lat.toStringAsFixed(0)}ms ');
    if (mb > 0) buf.write('· ${mb.toStringAsFixed(1)}MiB/s');
    return buf.toString();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('预热统计')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : RefreshIndicator(
              onRefresh: _exportStatsCheck,
              child: ListView(
                padding: const EdgeInsets.all(16),
                children: [
                  _buildCredentialCard(theme),
                  const SizedBox(height: 14),
                  if (_error != null) _buildErrorCard(theme),
                  if (_playbacks.isNotEmpty ||
                      _warmEvents.isNotEmpty ||
                      _deletions.isNotEmpty)
                    _buildSection(theme),
                  if (_playbacks.isNotEmpty ||
                      _warmEvents.isNotEmpty ||
                      _deletions.isNotEmpty) ...[
                    const SizedBox(height: 16),
                    _buildWarmSection(theme),
                    const SizedBox(height: 16),
                    _buildPlaybackSection(theme),
                    const SizedBox(height: 16),
                    _buildDeletionSection(theme),
                  ],
                ],
              ),
            ),
    );
  }

  Future<void> _exportStatsCheck() async {
    await _exportStats();
  }

  Widget _buildCredentialCard(ThemeData theme) {
    return Card(
      elevation: 0,
      color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(Icons.shield_outlined, size: 20, color: theme.colorScheme.primary),
                const SizedBox(width: 8),
                Text('统计密码', style: theme.textTheme.titleSmall),
                Text('（独立于加密/管理密码）',
                    style: theme.textTheme.bodySmall
                        ?.copyWith(color: theme.colorScheme.outline)),
              ],
            ),
            const SizedBox(height: 10),
            TextFormField(
              controller: _passwordController,
              obscureText: true,
              decoration: const InputDecoration(
                isDense: true,
                border: OutlineInputBorder(),
                hintText: '留空 = 统计接口关闭',
              ),
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    icon: const Icon(Icons.lock_outline, size: 18),
                    label: const Text('保存密码'),
                    onPressed: _savePassword,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: FilledButton.icon(
                    icon: const Icon(Icons.refresh, size: 18),
                    label: _exporting ? const Text('载入中...') : const Text('载入数据'),
                    onPressed: _exporting ? null : _exportStats,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildErrorCard(ThemeData theme) {
    return Card(
      elevation: 0,
      color: theme.colorScheme.errorContainer.withValues(alpha: 0.35),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Row(
          children: [
            Icon(Icons.error_outline, color: theme.colorScheme.error),
            const SizedBox(width: 10),
            Expanded(
                child:
                    Text(_error!, style: TextStyle(color: theme.colorScheme.error))),
          ],
        ),
      ),
    );
  }

  // 概览指标卡
  Widget _buildSection(ThemeData theme) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('概览', style: theme.textTheme.titleMedium),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: _metricCard(
                theme,
                label: '播放数',
                value: '${_playbacks.length}',
                icon: Icons.play_circle_outline,
                color: const Color(0xFF409EFF),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _metricCard(
                theme,
                label: '首帧 p50',
                value: _latencySeries.isEmpty ? '-' : _latencyP50(),
                icon: Icons.timeline,
                color: const Color(0xFFF65E5E),
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Expanded(
              child: _metricCard(
                theme,
                label: '预热成功',
                value:
                    '$_warmOk/${_warmEvents.length}',
                icon: Icons.rocket_launch_outlined,
                color: const Color(0xFF67C23A),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _metricCard(
                theme,
                label: '峰值速率',
                value: _peakMbps == null
                    ? '-'
                    : '${_peakMbps!.toStringAsFixed(1)}MiB/s',
                icon: Icons.speed,
                color: const Color(0xFFE6A23C),
              ),
            ),
          ],
        ),
        if (_probeStats.isNotEmpty) ...[
          const SizedBox(height: 10),
          _probeCard(theme),
        ],
        const SizedBox(height: 16),
        // 首帧折线图
        Card(
          elevation: 0,
          color: theme.colorScheme.surfaceContainerLowest,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text('首帧耗时趋势', style: theme.textTheme.titleSmall),
                const SizedBox(height: 4),
                Text(
                  '${_latencySummary()} · 共 ${_latencySeries.length} 次',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.outline),
                ),
                SizedBox(
                  height: 120,
                  child: CustomPaint(
                    painter: _AxisChart(
                      series: _latencySeries,
                      color: const Color(0xFFF65E5E),
                      unit: 'ms',
                    ),
                  ),
                ),
                const Divider(height: 20),
                Text('下行速率趋势', style: theme.textTheme.titleSmall),
                const SizedBox(height: 10),
                SizedBox(
                  height: 120,
                  child: CustomPaint(
                    painter: _AxisChart(
                      series: _mbpsSeries,
                      color: const Color(0xFFF4C90A),
                      unit: 'MiB/s',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  Widget _probeCard(ThemeData theme) {
    final v2Attempts = (_probeStats['v2_attempts'] as num?)?.toInt() ?? 0;
    final v2Success = (_probeStats['v2_success'] as num?)?.toInt() ?? 0;
    final dual = (_probeStats['dual_probe_attempts'] as num?)?.toInt() ?? 0;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        children: [
          Icon(Icons.explore, size: 20, color: theme.colorScheme.primary),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              'V2 头探测 $v2Success/$v2Attempts · 双网络 RTT $dual 次',
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.onSurfaceVariant),
            ),
          ),
        ],
      ),
    );
  }

  Widget _metricCard(ThemeData theme,
      {required String label,
      required String value,
      required IconData icon,
      required Color color}) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [color.withValues(alpha: 0.14), color.withValues(alpha: 0.05)],
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 20, color: color),
          const SizedBox(height: 8),
          Text(value,
              style: theme.textTheme.titleLarge?.copyWith(
                fontWeight: FontWeight.w700,
                color: color,
              )),
          const SizedBox(height: 2),
          Text(label,
              style: theme.textTheme.bodySmall
                  ?.copyWith(color: theme.colorScheme.outline)),
        ],
      ),
    );
  }

  // 预热明细
  Widget _buildWarmSection(ThemeData theme) {
    if (_warmEvents.isEmpty) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text('预热明细 (${_warmEvents.length})',
                style: theme.textTheme.titleMedium),
            _badge('ok $_warmOk · fail $_warmFail'),
          ],
        ),
        const SizedBox(height: 8),
        ..._warmEvents.take(80).map((e) => _warmTile(theme, e)),
      ],
    );
  }

  Widget _warmTile(ThemeData theme, Map<String, dynamic> e) {
    final status = (e['status'] ?? '').toString();
    final detail = (e['detail'] ?? '').toString();
    final dur = (e['duration_ms'] as num?)?.toInt() ?? 0;
    final (Color color, String label) = switch (status) {
      'ok' => (const Color(0xFF67C23A), '成功'),
      'timeout' => (const Color(0xFFE6A23C), '超时'),
      _ => (const Color(0xFFF65A5E), '失败'),
    };
    return Card(
      elevation: 0,
      margin: const EdgeInsets.only(bottom: 8),
      color: theme.colorScheme.surfaceContainerHighest.withValues(alpha: 0.4),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: ListTile(
        dense: true,
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
        leading: Container(
          width: 10,
          height: 10,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
          ),
        ),
        title: Text(
          e['target_path']?.toString() ?? '(unknown)',
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: theme.textTheme.bodyMedium,
        ),
        subtitle: Text(
          [
            _fmtTime(e['finished_at']),
            if (dur > 0) '· ${dur}ms',
            if (detail.isNotEmpty) '· $detail',
          ].join(' '),
          style: theme.textTheme.bodySmall
              ?.copyWith(color: theme.colorScheme.outline),
        ),
        trailing: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(20),
          ),
          child: Text(label,
              style: theme.textTheme.labelSmall?.copyWith(
                color: color,
                fontWeight: FontWeight.w600,
              )),
        ),
      ),
    );
  }

  Widget _badge(String text) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerLowest,
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(text,
          style: Theme.of(context)
              .textTheme
              .labelSmall
              ?.copyWith(color: Theme.of(context).colorScheme.outline)),
    );
  }

  // 播放记录
  Widget _buildPlaybackSection(ThemeData theme) {
    if (_playbacks.isEmpty) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('播放记录 (${_playbacks.length})', style: theme.textTheme.titleMedium),
        const SizedBox(height: 8),
        ..._playbacks.take(60).map((p) => Card(
              elevation: 0,
              margin: const EdgeInsets.only(bottom: 8),
              color: theme.colorScheme.surfaceContainerHighest
                  .withValues(alpha: 0.4),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
              child: ListTile(
                dense: true,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
                title: Text(
                  p['path']?.toString() ?? '(unknown)',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyMedium,
                ),
                subtitle: Text(
                  '${p['provider'] ?? '-'} · ${_fmtDuration(p['duration_secs'])} · '
                  '${_fmtBytes(p['bytes_served'])}  ${_fmtObs(p)}',
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.outline),
                ),
                trailing: Text(
                  _fmtTime(p['played_at']),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.outline),
                ),
              ),
            )),
      ],
    );
  }

  // 删除记录
  Widget _buildDeletionSection(ThemeData theme) {
    if (_deletions.isEmpty) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('删除记录 (${_deletions.length})', style: theme.textTheme.titleMedium),
        const SizedBox(height: 8),
        ..._deletions.take(40).map((d) => Card(
              elevation: 0,
              margin: const EdgeInsets.only(bottom: 8),
              color: theme.colorScheme.surfaceContainerHighest
                  .withValues(alpha: 0.4),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12)),
              child: ListTile(
                dense: true,
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 2),
                title: Text(
                  d['path']?.toString() ?? '(unknown)',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodyMedium,
                ),
                trailing: Text(
                  _fmtTime(d['deleted_at']),
                  style: theme.textTheme.bodySmall
                      ?.copyWith(color: theme.colorScheme.outline),
                ),
              ),
            )),
      ],
    );
  }
}

/// 带坐标轴与数据点的折线图（canvas 自绘，零依赖）。
class _AxisChart extends CustomPainter {
  _AxisChart({
    required this.series,
    required this.color,
    this.unit = '',
  });

  final List<Map<String, dynamic>> series;
  final Color color;
  final String unit;

  @override
  void paint(Canvas canvas, Size size) {
    if (series.isEmpty) {
      final tp = TextPainter(
        text: const TextSpan(
            text: '暂无数据', style: TextStyle(color: Colors.grey)),
        textDirection: TextDirection.ltr,
      )..layout();
      tp.paint(canvas, Offset(size.width / 2 - tp.width / 2, size.height / 2 - tp.height / 2));
      return;
    }

    final values = series.map((e) => e['v'] as double).toList();
    final maxV = values.reduce((a, b) => a > b ? a : b);
    if (maxV <= 0) return;

    const padL = 8.0, padR = 8.0, padT = 26.0, padB = 18.0;
    final plotW = size.width - padL - padR;
    final plotH = size.height - padT - padB;

    // 网格 + Y 轴刻度（5 条）
    final gridPaint = Paint()
      ..color = Colors.grey.withValues(alpha: 0.15)
      ..strokeWidth = 1;
    for (var i = 0; i <= 4; i++) {
      final y = padT + plotH * i / 4;
      canvas.drawLine(Offset(padL, y), Offset(size.width - padR, y), gridPaint);
    }

    // 折线
    final t0 = (series.first['t']['played_at'] as num).toInt();
    final t1 = (series.last['t']['played_at'] as num).toInt();
    final span = (t1 - t0) <= 0 ? 1 : (t1 - t0);
    double fx(num v) => padL + (v - t0) / span * plotW;
    double fy(double v) => padT + plotH * (1 - v / maxV);

    final linePaint = Paint()
      ..color = color
      ..strokeWidth = 1.8
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round;
    final points = <Offset>[];
    for (final e in series) {
      final t = (e['t']['played_at'] as num).toInt();
      final v = e['v'] as double;
      points.add(Offset(fx(t), fy(v).clamp(padT, padT + plotH).toDouble()));
    }
    final path = Path()..moveTo(points.first.dx, points.first.dy);
    for (final p in points.skip(1)) {
      path.lineTo(p.dx, p.dy);
    }
    canvas.drawPath(path, linePaint);

    // 数据点（抽 ≤40 个显示）
    final dotPaint = Paint()..color = color;
    final step = (points.length / 40).ceil();
    for (var i = 0; i < points.length; i += step) {
      canvas.drawCircle(points[i], 2.5, dotPaint);
    }
    if (points.length > 0) {
      canvas.drawCircle(points.last, 3.5, dotPaint);
    }

    // 顶部数值标签（最大）
    final tp = TextPainter(
      text: TextSpan(
        text: '最高 ${maxV.toStringAsFixed(0)}${unit.isEmpty ? '' : ' $unit'}',
        style: const TextStyle(color: Colors.grey, fontSize: 11),
      ),
      textDirection: TextDirection.ltr,
    )..layout();
    tp.paint(canvas, Offset(padL + 2, 2));

    // X 轴时间刻度（两端）
    final tTexts = [t0, t1 == t0 ? t1 + 1 : t1];
    for (final t in tTexts) {
      final d = DateTime.fromMillisecondsSinceEpoch(t * 1000);
      final label = '${d.hour}:${d.minute.toString().padLeft(2, '0')}';
      final lp = TextPainter(
        text: TextSpan(text: label, style: const TextStyle(color: Colors.grey, fontSize: 10)),
        textDirection: TextDirection.ltr,
      )..layout();
      final x = fx(t);
      final dx =
          (x - lp.width / 2).clamp(4.0, size.width - lp.width - 4.0).toDouble();
      lp.paint(canvas, Offset(dx, padT + plotH + 2));
    }
  }

  @override
  bool shouldRepaint(covariant _AxisChart oldDelegate) {
    return oldDelegate.series != series || oldDelegate.color != color;
  }
}