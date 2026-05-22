import 'package:dio/dio.dart';
import 'package:flutter/material.dart';

class ProviderRoutingPage extends StatefulWidget {
  const ProviderRoutingPage({super.key, required this.proxyPort});

  final int proxyPort;

  @override
  State<ProviderRoutingPage> createState() => _ProviderRoutingPageState();
}

class _ProviderRoutingPageState extends State<ProviderRoutingPage> {
  final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 3),
    receiveTimeout: const Duration(seconds: 5),
    sendTimeout: const Duration(seconds: 5),
  ));

  static const Map<String, String> _fallbackProviderZhMap = {
    'aliyundriveopen': '阿里云盘',
    'baidunetdisk': '百度网盘',
    'baiduphoto': '百度相册',
    'cloud189': '天翼云盘',
    'cloud189pc': '天翼云盘PC',
    'open123': '123网盘',
    'pan115': '115网盘',
    'quarkoruc': '夸克/UC网盘',
    'weiyun': '微云',
    'wps': 'WPS网盘',
    'mopan': '移动云盘',
    'mobile_cloud': '移动云盘',
    'china_mobile_cloud': '移动云盘',
    'unicom_cloud': '联通云盘',
    'china_unicom_cloud': '联通云盘',
    'wo_cloud': '联通云盘',
    'onedrive': 'OneDrive',
    'onedriveapp': 'OneDrive App',
    'googledrive': 'Google Drive',
    'google_drive': 'Google Drive',
    'googlephoto': 'Google Photos',
    'googlephotoapp': 'Google Photos',
    'mega': 'MEGA',
    'mediafire': 'MediaFire',
    'protondrive': 'Proton Drive',
    'dropbox': 'Dropbox',
    'github': 'GitHub',
  };

  bool _loading = true;
  bool _saving = false;
  bool _enableLocalBypass = true;
  bool _enableRouting = true;
  String _routingUnmatchedDefault = 'proxy';
  String _catalogStatus = '';
  List<String> _providerCandidates = [];
  Map<String, String> _providerLabels = {};
  List<_RoutingRule> _rules = [];

  String get _baseUrl => 'http://127.0.0.1:${widget.proxyPort}';

  @override
  void initState() {
    super.initState();
    _loadAll();
  }

  String _providerLabel(String raw) {
    final key = raw.trim().toLowerCase();
    final zh = _providerLabels[key] ?? _fallbackProviderZhMap[key];
    if (zh == null || zh.isEmpty) {
      return raw;
    }
    return '$raw ($zh)';
  }

  Future<void> _loadAll() async {
    setState(() => _loading = true);
    try {
      await Future.wait([_loadConfig(), _loadCandidates()]);
      _normalizeRuleValues();
    } catch (_) {
      // keep page usable with partial data
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _normalizeRuleValues() {
    for (final rule in _rules) {
      final uniq = <String>{};
      final next = <String>[];
      for (final raw in rule.matchValues) {
        final v = raw.trim().toLowerCase();
        if (v.isEmpty || uniq.contains(v)) continue;
        uniq.add(v);
        next.add(v);
      }
      rule.matchValues = next;
    }
  }

  Future<void> _loadConfig() async {
    final resp = await _dio.get('$_baseUrl/api/encrypt/v2/config');
    final root = resp.data is Map<String, dynamic>
        ? resp.data as Map<String, dynamic>
        : const <String, dynamic>{};
    final data = root['data'] as Map<String, dynamic>?;
    final config = data?['config'] as Map<String, dynamic>?;
    if (config == null) return;

    final rawRules = (config['providerRoutingRules'] as List<dynamic>? ?? []);
    final rules = rawRules.whereType<Map>().map((item) {
      final m = item.map((k, v) => MapEntry(k.toString(), v));
      final values = <String>[];
      final rawValues = m['matchValues'];
      if (rawValues is List) {
        for (final raw in rawValues) {
          final v = raw.toString().trim().toLowerCase();
          if (v.isNotEmpty) values.add(v);
        }
      }
      if (values.isEmpty) {
        final single = (m['matchValue'] ?? '').toString().trim().toLowerCase();
        if (single.isNotEmpty) values.add(single);
      }
      return _RoutingRule(
        id: (m['id'] ?? '').toString(),
        action: (m['action'] ?? 'direct').toString(),
        enabled: m['enabled'] is bool ? m['enabled'] as bool : true,
        priority: int.tryParse((m['priority'] ?? 100).toString()) ?? 100,
        matchValues: values,
      );
    }).toList();

    setState(() {
      _enableLocalBypass = config['enableLocalBypass'] is bool
          ? config['enableLocalBypass'] as bool
          : true;
      _enableRouting = (config['routingMode'] ?? 'by_provider').toString() != 'off';
      _routingUnmatchedDefault =
          (config['routingUnmatchedDefault'] ?? 'proxy').toString().toLowerCase() == 'direct'
          ? 'direct'
          : 'proxy';
      _rules = rules;
    });
  }

  Future<void> _loadCandidates() async {
    final resp = await _dio.get('$_baseUrl/api/encrypt/provider-routing-candidates');
    final root = resp.data is Map<String, dynamic>
        ? resp.data as Map<String, dynamic>
        : const <String, dynamic>{};
    final data = root['data'] as Map<String, dynamic>?;

    final providers = (data?['providers'] as List<dynamic>? ?? [])
        .map((e) => e.toString().trim().toLowerCase())
        .where((e) => e.isNotEmpty)
        .toSet()
        .toList()
      ..sort();

    final labels = <String, String>{};
    final rawLabels = data?['provider_labels'];
    if (rawLabels is Map) {
      for (final entry in rawLabels.entries) {
        final key = entry.key.toString().trim().toLowerCase();
        final value = entry.value.toString().trim();
        if (key.isNotEmpty && value.isNotEmpty) {
          labels[key] = value;
        }
      }
    }

    setState(() {
      _providerCandidates = providers;
      _providerLabels = labels;
      final meta = data?['meta'] as Map<String, dynamic>?;
      if (meta != null) {
        final total = (meta['catalog_total'] ?? providers.length).toString();
        final stale = meta['catalog_stale'] == true ? '过期' : '正常';
        final refreshing = meta['catalog_refreshing'] == true ? '（刷新中）' : '';
        _catalogStatus = '目录$total 项，状态:$stale$refreshing';
      } else {
        _catalogStatus = '目录${providers.length} 项';
      }
    });
  }

  Future<void> _refreshCatalogNow() async {
    try {
      await _dio.post('$_baseUrl/api/encrypt/provider-routing-candidates/refresh');
      await Future.delayed(const Duration(milliseconds: 400));
      await _loadCandidates();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('已触发后台刷新，列表已更新')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('刷新失败: $e')));
      }
    }
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    try {
      _normalizeRuleValues();
      final filteredRules = _rules
          .where((e) => e.matchValues.isNotEmpty)
          .map((e) => e.toJson())
          .toList();

      await _dio.post(
        '$_baseUrl/api/encrypt/v2/config',
        data: {
          'version': 2,
          'config': {
            'routingMode': _enableRouting ? 'by_provider' : 'off',
            'routingUnmatchedDefault': _routingUnmatchedDefault,
            'providerRuleSource': 'builtin+custom',
            'providerRoutingRules': filteredRules,
          }
        },
        options: Options(contentType: 'application/json'),
      );
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('网盘分流规则已保存')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('保存失败: $e')));
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  void _addRule() {
    setState(() {
      _rules.add(_RoutingRule(
        id: DateTime.now().millisecondsSinceEpoch.toString(),
        action: 'direct',
        enabled: true,
        priority: _rules.length + 1,
        matchValues: const [],
      ));
    });
  }

  Future<void> _pickProviders(_RoutingRule rule) async {
    final selected = Set<String>.from(rule.matchValues);
    var keyword = '';
    final customController = TextEditingController();

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      builder: (ctx) {
        return StatefulBuilder(
          builder: (ctx, setSheetState) {
            List<String> filtered = _providerCandidates;
            final q = keyword.trim().toLowerCase();
            if (q.isNotEmpty) {
              filtered = _providerCandidates.where((p) {
                final label = (_providerLabels[p] ?? _fallbackProviderZhMap[p] ?? '').toLowerCase();
                return p.contains(q) || label.contains(q);
              }).toList();
            }

            return Padding(
              padding: EdgeInsets.only(
                left: 16,
                right: 16,
                top: 16,
                bottom: MediaQuery.of(ctx).viewInsets.bottom + 16,
              ),
              child: SizedBox(
                height: MediaQuery.of(ctx).size.height * 0.72,
                child: Column(
                  children: [
                    const Text('选择 Provider（可多选）', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
                    const SizedBox(height: 12),
                    TextField(
                      decoration: const InputDecoration(
                        labelText: '搜索 Provider/中文名',
                        prefixIcon: Icon(Icons.search),
                      ),
                      onChanged: (v) => setSheetState(() => keyword = v),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: TextField(
                            controller: customController,
                            decoration: const InputDecoration(
                              labelText: '手动添加 provider',
                              hintText: '例如: china_mobile_cloud',
                            ),
                          ),
                        ),
                        const SizedBox(width: 8),
                        FilledButton.tonal(
                          onPressed: () {
                            final custom = customController.text.trim().toLowerCase();
                            if (custom.isNotEmpty) {
                              setSheetState(() {
                                selected.add(custom);
                                if (!_providerCandidates.contains(custom)) {
                                  _providerCandidates = [..._providerCandidates, custom]..sort();
                                }
                                customController.clear();
                              });
                            }
                          },
                          child: const Text('添加'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Expanded(
                      child: filtered.isEmpty
                          ? const Center(child: Text('没有匹配项'))
                          : ListView.builder(
                              itemCount: filtered.length,
                              itemBuilder: (_, i) {
                                final p = filtered[i];
                                final checked = selected.contains(p);
                                return CheckboxListTile(
                                  value: checked,
                                  onChanged: (v) {
                                    setSheetState(() {
                                      if (v == true) {
                                        selected.add(p);
                                      } else {
                                        selected.remove(p);
                                      }
                                    });
                                  },
                                  title: Text(
                                    p,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                  subtitle: Text(
                                    _providerLabels[p] ?? _fallbackProviderZhMap[p] ?? '-',
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                  controlAffinity: ListTileControlAffinity.leading,
                                );
                              },
                            ),
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: OutlinedButton(
                            onPressed: () => Navigator.pop(ctx),
                            child: const Text('取消'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: FilledButton(
                            onPressed: () {
                              setState(() {
                                rule.matchValues = selected.toList()..sort();
                              });
                              Navigator.pop(ctx);
                            },
                            child: const Text('确定'),
                          ),
                        ),
                      ],
                    )
                  ],
                ),
              ),
            );
          },
        );
      },
    );

    customController.dispose();
  }

  Widget _buildProviderChip(String provider, _RoutingRule rule) {
    final label = _providerLabel(provider);
    return InputChip(
      label: SizedBox(
        width: 180,
        child: Text(
          label,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
      ),
      onDeleted: () {
        setState(() {
          rule.matchValues.removeWhere((e) => e == provider);
        });
      },
    );
  }

  Widget _buildRuleCard(int index) {
    final rule = _rules[index];
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: DropdownButtonFormField<String>(
                    value: rule.action,
                    decoration: const InputDecoration(labelText: '动作'),
                    items: const [
                      DropdownMenuItem(value: 'direct', child: Text('直连')),
                      DropdownMenuItem(value: 'proxy', child: Text('代理')),
                    ],
                    onChanged: (v) {
                      if (v == null) return;
                      setState(() => rule.action = v);
                    },
                  ),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: TextFormField(
                    initialValue: rule.priority.toString(),
                    decoration: const InputDecoration(labelText: '优先级（小优先）'),
                    keyboardType: TextInputType.number,
                    onChanged: (v) => rule.priority = int.tryParse(v) ?? 100,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: FilledButton.tonalIcon(
                    onPressed: () => _pickProviders(rule),
                    icon: const Icon(Icons.playlist_add_check),
                    label: Text('选择 Provider（已选 ${rule.matchValues.length}）'),
                  ),
                ),
                const SizedBox(width: 8),
                Switch(
                  value: rule.enabled,
                  onChanged: (v) => setState(() => rule.enabled = v),
                ),
                IconButton(
                  icon: const Icon(Icons.delete_outline),
                  tooltip: '删除规则',
                  onPressed: () => setState(() => _rules.removeAt(index)),
                ),
              ],
            ),
            const SizedBox(height: 8),
            if (rule.matchValues.isEmpty)
              const Text('未选择 Provider', style: TextStyle(color: Colors.grey))
            else
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: rule.matchValues
                    .map((provider) => _buildProviderChip(provider, rule))
                    .toList(),
              ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('网盘分流规则'),
        actions: [
          IconButton(
            onPressed: _loadAll,
            icon: const Icon(Icons.refresh),
            tooltip: '刷新',
          ),
          IconButton(
            onPressed: _saving ? null : _save,
            icon: const Icon(Icons.save),
            tooltip: '保存',
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addRule,
        child: const Icon(Icons.add),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : ListView(
              padding: const EdgeInsets.all(16),
              children: [
                SwitchListTile(
                  title: const Text('启用按网盘分流'),
                  subtitle: const Text('关闭后按原网络行为处理（仅私网直连 + 系统代理）'),
                  value: _enableRouting,
                  onChanged: (v) => setState(() => _enableRouting = v),
                ),
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('本地/私网直连（全局）'),
                  subtitle: const Text('该开关已统一到【加密页面 > 网络策略】配置；本页仅展示当前状态'),
                  trailing: Text(
                    _enableLocalBypass ? '已开启' : '已关闭',
                  ),
                ),
                ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: const Text('未匹配 Provider 默认动作'),
                  subtitle: const Text('当未命中任何规则和内置网盘分类时使用'),
                  trailing: DropdownButton<String>(
                    value: _routingUnmatchedDefault,
                    items: const [
                      DropdownMenuItem(value: 'proxy', child: Text('走代理')),
                      DropdownMenuItem(value: 'direct', child: Text('直连')),
                    ],
                    onChanged: (v) {
                      if (v == null) return;
                      setState(() => _routingUnmatchedDefault = v);
                    },
                  ),
                ),
                const Card(
                  child: Padding(
                    padding: EdgeInsets.all(12),
                    child: Text(
                      '说明: 一条规则可选择多个 Provider，命中其中任意一个即应用该规则。',
                    ),
                  ),
                ),
                if (_catalogStatus.isNotEmpty)
                  Card(
                    child: ListTile(
                      title: Text(_catalogStatus),
                      trailing: FilledButton.tonal(
                        onPressed: _refreshCatalogNow,
                        child: const Text('刷新目录'),
                      ),
                    ),
                  ),
                const SizedBox(height: 8),
                if (_rules.isEmpty)
                  const Card(
                    child: Padding(
                      padding: EdgeInsets.all(12),
                      child: Text('暂无规则，可点击右下角 + 添加。'),
                    ),
                  ),
                ...List.generate(_rules.length, _buildRuleCard),
              ],
            ),
    );
  }
}

class _RoutingRule {
  _RoutingRule({
    required this.id,
    required this.action,
    required this.enabled,
    required this.priority,
    required this.matchValues,
  });

  String id;
  String action;
  bool enabled;
  int priority;
  List<String> matchValues;

  Map<String, dynamic> toJson() {
    final values = matchValues
        .map((e) => e.trim().toLowerCase())
        .where((e) => e.isNotEmpty)
        .toSet()
        .toList()
      ..sort();
    return {
      'id': id,
      'matchType': 'provider',
      'matchValues': values,
      'matchValue': values.isNotEmpty ? values.first : '',
      'action': action,
      'enabled': enabled,
      'priority': priority,
    };
  }
}
