import 'dart:convert';
import 'dart:developer';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:openlist_mobile/contant/native_bridge.dart';

/// 播放统计页：设置统计导出密码 + 导出播放/删除统计。
///
/// 入口在设置页"播放统计"。
/// 统计密码独立于加密/管理密码，存于本地代理配置；导出走本地代理 HTTP
/// `/api/encrypt/exportStats`（独立密码鉴权）。
class PlaybackStatsPage extends StatefulWidget {
  const PlaybackStatsPage({super.key});

  @override
  State<PlaybackStatsPage> createState() => _PlaybackStatsPageState();
}

class _PlaybackStatsPageState extends State<PlaybackStatsPage> {
  final _passwordController = TextEditingController();
  final _proxyPort = 5344; // 本地代理默认端口
  bool _loading = true;
  bool _exporting = false;
  String? _error;
  List<dynamic> _playbacks = [];
  List<dynamic> _deletions = [];

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
      final config = json.decode(configJson) is Map<String, dynamic>
          ? json.decode(configJson) as Map<String, dynamic>
          : <String, dynamic>{};
      final statsPassword = config['statsPassword']?.toString() ?? '';
      if (mounted) {
        setState(() {
          _passwordController.text = statsPassword;
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
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('统计密码已保存')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('保存失败（代理未运行？）: $e')),
        );
      }
    }
  }

  Future<void> _exportStats() async {
    final password = _passwordController.text.trim();
    if (password.isEmpty) {
      _toast('请先设置统计导出密码并保存');
      return;
    }
    setState(() {
      _exporting = true;
      _error = null;
    });
    try {
      final dio = Dio(BaseOptions(
        connectTimeout: const Duration(seconds: 3),
        receiveTimeout: const Duration(seconds: 10),
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
      final plays = root['playbacks'] as List<dynamic>? ?? [];
      final dels = root['deletions'] as List<dynamic>? ?? [];
      if (mounted) {
        setState(() {
          _playbacks = plays;
          _deletions = dels;
          _exporting = false;
        });
        log('播放统计导出：播放 ${plays.length} 条，删除 ${dels.length} 条');
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('已导出：播放 ${plays.length} 条，删除 ${dels.length} 条')),
        );
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
        .showSnackBar(SnackBar(content: Text(msg)));
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
    return '${d.year}-${p(d.month)}-${p(d.day)} ${p(d.hour)}:${p(d.minute)}';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('播放统计')),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                Card(
                  child: Padding(
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        TextFormField(
                          controller: _passwordController,
                          obscureText: true,
                          decoration: const InputDecoration(
                            labelText: '统计导出密码（独立）',
                            hintText: '留空 = 统计接口关闭',
                            helperText: '导出统计时需输入此密码；与加密/管理密码相互独立',
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
                                icon: const Icon(Icons.download, size: 18),
                                label: _exporting
                                    ? const Text('导出中...')
                                    : const Text('导出统计'),
                                onPressed: _exporting ? null : _exportStats,
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 16),
                if (_error != null)
                  Card(
                    color: Colors.red.shade50,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Text(_error!,
                          style: TextStyle(color: Colors.red.shade700)),
                    ),
                  ),
                if (_playbacks.isNotEmpty || _deletions.isNotEmpty) ...[
                  Text('播放记录（${_playbacks.length}）',
                      style: theme.textTheme.titleMedium),
                  const SizedBox(height: 8),
                  ..._playbacks.take(200).map((p) => Card(
                        child: ListTile(
                          dense: true,
                          title: Text(
                            p['path']?.toString() ?? '(unknown)',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          subtitle: Text(
                            '${p['provider'] ?? '-'} · ${_fmtDuration(p['duration_secs'])} · '
                            'seek ${p['seek_count'] ?? 0} · ${_fmtBytes(p['bytes_served'])}',
                          ),
                          trailing: Text(
                            _fmtTime(p['played_at']),
                            style: theme.textTheme.bodySmall,
                          ),
                        ),
                      )),
                  const SizedBox(height: 16),
                  Text('删除记录（${_deletions.length}）',
                      style: theme.textTheme.titleMedium),
                  const SizedBox(height: 8),
                  ..._deletions.take(200).map((d) => Card(
                        child: ListTile(
                          dense: true,
                          title: Text(
                            d['path']?.toString() ?? '(unknown)',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          subtitle: Text(
                            '删除于 ${_fmtTime(d['deleted_at'])}',
                          ),
                        ),
                      )),
                ],
              ],
            ),
    );
  }
}
