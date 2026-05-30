import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import '../../generated/l10n.dart';
import '../../contant/native_bridge.dart';
import 'provider_routing_page.dart';
import 'dir_sync_status_page.dart';
import '../local_mount/local_mount_page.dart';
import '../sync/sync_task_list_page.dart';

/// 加密配置页面
class EncryptConfigPage extends StatefulWidget {
  const EncryptConfigPage({super.key});

  @override
  State<EncryptConfigPage> createState() => _EncryptConfigPageState();
}

class _EncryptConfigPageState extends State<EncryptConfigPage> {
  final _formKey = GlobalKey<FormState>();
  
  // Alist 服务器配置
  final _alistHostController = TextEditingController(text: '127.0.0.1');
  final _alistPortController = TextEditingController(text: '5244');
  bool _alistHttps = false;
  
  // 代理端口
  final _proxyPortController = TextEditingController(text: '5344');

  // 网络策略
  final _upstreamTimeoutController = TextEditingController(text: '60');
  final _probeTimeoutController = TextEditingController(text: '5');
  final _probeBudgetController = TextEditingController(text: '5');
  final _upstreamBackoffController = TextEditingController(text: '20');
  bool _enableLocalBypass = true;
  bool _playFirstFallback = true;
  bool _enableRangeCompatCache = true;
  final _rangeCompatTtlController = TextEditingController(text: '43200');
  final _rangeCompatMinFailuresController = TextEditingController(text: '2');
  final _rangeSkipMaxBytesController = TextEditingController(text: '${256 * 1024 * 1024}');
  bool _enableParallelDecrypt = true;
  final _parallelDecryptConcurrencyController = TextEditingController(text: '4');
  final _streamBufferKbController = TextEditingController(text: '512');
  final _webdavNegativeCacheTtlController = TextEditingController(text: '10');
  
  // H2C 开关（HTTP/2 Cleartext）
  bool _enableH2C = false;

  // DB_EXPORT 元数据同步配置
  bool _enableDbExportSync = false;
  final _dbExportBaseUrlController = TextEditingController(text: '');
  final _dbExportSyncIntervalController = TextEditingController(text: '300');
  bool _dbExportAuthEnabled = false;
  final _dbExportUsernameController = TextEditingController(text: 'admin');
  final _dbExportPasswordController = TextEditingController();
  
  // 加密路径列表
  List<EncryptPathConfig> _encryptPaths = [];
  
  bool _isLoading = true;
  bool _proxyRunning = false;
  bool _isInitialized = false;
  List<Map<String, dynamic>> _configDocs = [];

  @override
  void initState() {
    super.initState();
    _initAndLoadConfig();
  }

  Future<void> _initAndLoadConfig() async {
    setState(() => _isLoading = true);
    try {
      // 初始化加密代理
      if (!_isInitialized) {
        final dataDir = await NativeBridge.appConfig.getDataDir();
        await NativeBridge.encryptProxy.initEncryptProxy('$dataDir/encrypt_config.json');
        _isInitialized = true;
      }
      
      await _checkProxyStatus();
      await _loadConfig();
      if (_proxyRunning) {
        await _loadConfigViaV2Api();
        await _loadConfigDocsViaV2Api();
      }
    } catch (e) {
      debugPrint('Failed to init encrypt proxy: $e');
      // 如果初始化失败，使用默认值
      setState(() {
        _encryptPaths = [];
      });
    } finally {
      setState(() => _isLoading = false);
    }
  }

  Future<void> _loadConfig() async {
    try {
      final configJson = await NativeBridge.encryptProxy.getEncryptConfigJson();
      debugPrint('Loaded config: $configJson');
      
      if (configJson.isNotEmpty && configJson != '{}') {
        final config = json.decode(configJson);
        
        setState(() {
          _alistHostController.text = config['alistHost'] ?? '127.0.0.1';
          _alistPortController.text = (config['alistPort'] ?? 5244).toString();
          _alistHttps = config['alistHttps'] ?? false;
          _proxyPortController.text = (config['proxyPort'] ?? 5344).toString();
          _upstreamTimeoutController.text =
              (config['upstreamTimeoutSeconds'] ?? 60).toString();
          _probeTimeoutController.text =
              (config['probeTimeoutSeconds'] ?? 5).toString();
          _probeBudgetController.text =
              (config['probeBudgetSeconds'] ?? 5).toString();
          _upstreamBackoffController.text =
              (config['upstreamBackoffSeconds'] ?? 20).toString();
          _enableLocalBypass = config['enableLocalBypass'] ?? true;
          _playFirstFallback = config['playFirstFallback'] ?? true;
          _enableRangeCompatCache = config['enableRangeCompatCache'] ?? true;
          _rangeCompatTtlController.text =
              (config['rangeCompatTtlMinutes'] ?? 43200).toString();
          _rangeCompatMinFailuresController.text =
              (config['rangeCompatMinFailures'] ?? 2).toString();
          _rangeSkipMaxBytesController.text =
              (config['rangeSkipMaxBytes'] ?? (256 * 1024 * 1024)).toString();
          _enableParallelDecrypt = config['enableParallelDecrypt'] ?? true;
          _parallelDecryptConcurrencyController.text =
              (config['parallelDecryptConcurrency'] ?? 4).toString();
          _streamBufferKbController.text =
              (config['streamBufferKb'] ?? 512).toString();
          _webdavNegativeCacheTtlController.text =
              (config['webdavNegativeCacheTtlMinutes'] ?? 10).toString();
          _enableH2C = config['enableH2C'] ?? false;
          _enableDbExportSync = config['enableDbExportSync'] ?? false;
          _dbExportBaseUrlController.text = config['dbExportBaseUrl'] ?? '';
          _dbExportSyncIntervalController.text =
              (config['dbExportSyncIntervalSeconds'] ?? 300).toString();
          _dbExportAuthEnabled = config['dbExportAuthEnabled'] ?? false;
          _dbExportUsernameController.text = config['dbExportUsername'] ?? 'admin';
          _dbExportPasswordController.text = config['dbExportPassword'] ?? '';
          
          // 解析加密路径列表
          final paths = config['encryptPaths'] as List<dynamic>?;
          if (paths != null) {
            _encryptPaths = paths.map((p) => EncryptPathConfig(
              path: p['path'] ?? '',
              password: '', // 密码不会返回
              encType: p['encType'] ?? 'aes-ctr',
              encName: p['encName'] ?? false,
              encSuffix: p['encSuffix'] ?? '',
              enable: p['enable'] ?? true,
            )).toList();
          }
        });
      }
    } catch (e) {
      debugPrint('Failed to load encrypt config: $e');
    }
  }

  Future<void> _loadConfigViaV2Api() async {
    final proxyPort = int.tryParse(_proxyPortController.text) ?? 5344;
    final dio = Dio(BaseOptions(
      connectTimeout: const Duration(seconds: 3),
      receiveTimeout: const Duration(seconds: 5),
      sendTimeout: const Duration(seconds: 5),
    ));
    try {
      final resp = await dio.get('http://127.0.0.1:$proxyPort/api/encrypt/v2/config');
      final data = resp.data is Map<String, dynamic> ? resp.data as Map<String, dynamic> : null;
      final payload = data?['data'] as Map<String, dynamic>?;
      final config = payload?['config'] as Map<String, dynamic>?;
      if (config == null) return;
      setState(() {
        _rangeCompatTtlController.text = (config['rangeCompatTtlMinutes'] ?? _rangeCompatTtlController.text).toString();
        _rangeCompatMinFailuresController.text = (config['rangeCompatMinFailures'] ?? _rangeCompatMinFailuresController.text).toString();
        _rangeSkipMaxBytesController.text = (config['rangeSkipMaxBytes'] ?? _rangeSkipMaxBytesController.text).toString();
        _parallelDecryptConcurrencyController.text = (config['parallelDecryptConcurrency'] ?? _parallelDecryptConcurrencyController.text).toString();
        _streamBufferKbController.text = (config['streamBufferKb'] ?? _streamBufferKbController.text).toString();
        _webdavNegativeCacheTtlController.text = (config['webdavNegativeCacheTtlMinutes'] ?? _webdavNegativeCacheTtlController.text).toString();
        _playFirstFallback = config['playFirstFallback'] ?? _playFirstFallback;
        _enableRangeCompatCache = config['enableRangeCompatCache'] ?? _enableRangeCompatCache;
        _enableParallelDecrypt = config['enableParallelDecrypt'] ?? _enableParallelDecrypt;
      });
    } catch (e) {
      debugPrint('Failed to load v2 config: $e');
    }
  }

  Future<void> _loadConfigDocsViaV2Api() async {
    final proxyPort = int.tryParse(_proxyPortController.text) ?? 5344;
    final dio = Dio(BaseOptions(
      connectTimeout: const Duration(seconds: 3),
      receiveTimeout: const Duration(seconds: 5),
      sendTimeout: const Duration(seconds: 5),
    ));
    try {
      final resp = await dio.get('http://127.0.0.1:$proxyPort/api/encrypt/v2/config/schema');
      final data = resp.data is Map<String, dynamic> ? resp.data as Map<String, dynamic> : null;
      final payload = data?['data'] as Map<String, dynamic>?;
      final docs = (payload?['docs'] as List<dynamic>? ?? [])
          .whereType<Map>()
          .map((e) => e.map((key, value) => MapEntry(key.toString(), value)))
          .toList();
      setState(() {
        _configDocs = docs;
      });
    } catch (e) {
      debugPrint('Failed to load v2 config schema: $e');
    }
  }

  Future<void> _checkProxyStatus() async {
    try {
      final running = await NativeBridge.encryptProxy.isEncryptProxyRunning();
      final proxyPort = int.tryParse(_proxyPortController.text) ?? 5344;
      var ready = false;
      if (running) {
        final dio = Dio(BaseOptions(
          connectTimeout: const Duration(seconds: 2),
          receiveTimeout: const Duration(seconds: 2),
          sendTimeout: const Duration(seconds: 2),
        ));
        try {
          final resp = await dio.get('http://127.0.0.1:$proxyPort/ping');
          ready = resp.statusCode != null && resp.statusCode! >= 200 && resp.statusCode! < 500;
        } catch (_) {
          ready = false;
        }
      }
      setState(() => _proxyRunning = running && ready);
    } catch (e) {
      debugPrint('Failed to check proxy status: $e');
    }
  }

  Future<void> _saveConfig() async {
    if (!_formKey.currentState!.validate()) return;

    if (_enableDbExportSync && _dbExportBaseUrlController.text.trim().isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('请填写 DB_EXPORT API 地址')),
        );
      }
      return;
    }
    if (_enableDbExportSync &&
        _dbExportAuthEnabled &&
        _dbExportUsernameController.text.trim().isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('请填写鉴权账号')),
        );
      }
      return;
    }

    int syncInterval = 300;
    final parsedSyncInterval = int.tryParse(_dbExportSyncIntervalController.text.trim());
    if (parsedSyncInterval != null && parsedSyncInterval > 0) {
      syncInterval = parsedSyncInterval;
    }
    
    try {
      // 保存 Alist 主机配置
      await NativeBridge.encryptProxy.setEncryptAlistHost(
        _alistHostController.text,
        int.parse(_alistPortController.text),
        _alistHttps,
      );
      
      // 保存代理端口
      await NativeBridge.encryptProxy.setEncryptProxyPort(
        int.parse(_proxyPortController.text),
      );

      // 保存 DB_EXPORT 同步配置
      await NativeBridge.encryptProxy.setEncryptDbExportSyncConfig(
        _enableDbExportSync,
        _dbExportBaseUrlController.text.trim(),
        syncInterval,
        _dbExportAuthEnabled,
        _dbExportUsernameController.text.trim(),
        _dbExportPasswordController.text,
      );

      // 保存网络策略
      await NativeBridge.encryptProxy.setEncryptNetworkPolicy(
        int.tryParse(_upstreamTimeoutController.text) ?? 60,
        int.tryParse(_probeTimeoutController.text) ?? 5,
        int.tryParse(_probeBudgetController.text) ?? 5,
        int.tryParse(_upstreamBackoffController.text) ?? 20,
        _enableLocalBypass,
      );
      
      // 保存解密和缓存高级配置 (通过 HTTP API 保存)
      await _saveAdvancedConfigViaApi();
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(S.current.saved)),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('保存失败: $e')),
        );
      }
    }
  }

  Future<void> _saveAdvancedConfigViaApi() async {
    if (!_proxyRunning) {
      // 如果代理没运行，先启动一下以便保存配置
      try {
        await NativeBridge.encryptProxy.startEncryptProxy();
        await Future.delayed(const Duration(milliseconds: 500));
        await _checkProxyStatus();
        if (!_proxyRunning) throw Exception('启动代理失败，无法保存高级配置');
      } catch (e) {
        throw Exception('代理未运行，无法保存高级配置');
      }
    }

    final proxyPort = int.tryParse(_proxyPortController.text) ?? 5344;
    final dio = Dio(BaseOptions(
      connectTimeout: const Duration(seconds: 3),
      receiveTimeout: const Duration(seconds: 5),
      sendTimeout: const Duration(seconds: 5),
    ));
    final resp = await dio.post(
      'http://127.0.0.1:$proxyPort/api/encrypt/v2/config',
      data: {
        'version': 2,
        'config': {
          'playFirstFallback': _playFirstFallback,
          'enableRangeCompatCache': _enableRangeCompatCache,
          'rangeCompatTtlMinutes':
              int.tryParse(_rangeCompatTtlController.text) ?? 43200,
          'rangeCompatMinFailures':
              int.tryParse(_rangeCompatMinFailuresController.text) ?? 2,
          'rangeSkipMaxBytes':
              int.tryParse(_rangeSkipMaxBytesController.text) ?? (256 * 1024 * 1024),
          'enableParallelDecrypt': _enableParallelDecrypt,
          'parallelDecryptConcurrency':
              int.tryParse(_parallelDecryptConcurrencyController.text) ?? 4,
          'streamBufferKb': int.tryParse(_streamBufferKbController.text) ?? 512,
          'webdavNegativeCacheTtlMinutes':
              int.tryParse(_webdavNegativeCacheTtlController.text) ?? 10,
        }
      },
      options: Options(contentType: 'application/json'),
    );
    if (resp.statusCode == null || resp.statusCode! < 200 || resp.statusCode! >= 300) {
      throw Exception('advanced config save failed: ${resp.statusCode}');
    }
  }

  Future<void> _toggleProxy() async {
    try {
      if (_proxyRunning) {
        await NativeBridge.encryptProxy.stopEncryptProxy();
      } else {
        await NativeBridge.encryptProxy.startEncryptProxy();
      }
      
      // 延迟检查状态
      await Future.delayed(const Duration(milliseconds: 500));
      await _checkProxyStatus();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('操作失败: $e')),
        );
      }
    }
  }

  void _showAddPathDialog() {
    final pathController = TextEditingController();
    final passwordController = TextEditingController();
    final encSuffixController = TextEditingController();
    String encType = 'aes-ctr';
    bool encName = false;
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('添加加密路径'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: pathController,
                decoration: const InputDecoration(
                  labelText: '路径',
                  hintText: '例: /encrypt/* 或 /movies/*',
                ),
              ),
              const SizedBox(height: 16),
              _PasswordInput(
                controller: passwordController,
                labelText: '密码',
              ),
              const SizedBox(height: 16),
              StatefulBuilder(
                builder: (context, setDialogState) => Column(
                  children: [
                    DropdownButtonFormField<String>(
                      value: encType,
                      decoration: const InputDecoration(
                        labelText: '加密算法',
                      ),
                      items: const [
                        DropdownMenuItem(value: 'aes-ctr', child: Text('AES-CTR (推荐)')),
                        DropdownMenuItem(value: 'rc4md5', child: Text('RC4-MD5')),
                        DropdownMenuItem(value: 'mix', child: Text('Mix 混淆')),
                      ],
                      onChanged: (value) {
                        setDialogState(() => encType = value!);
                      },
                    ),
                    const SizedBox(height: 16),
                    SwitchListTile(
                      title: const Text('加密文件名'),
                      value: encName,
                      onChanged: (value) {
                        setDialogState(() => encName = value);
                      },
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: encSuffixController,
                      decoration: const InputDecoration(
                        labelText: '加密后缀',
                        hintText: '.bin（留空则使用原始后缀）',
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(S.current.cancel),
          ),
          FilledButton(
            onPressed: () async {
              if (pathController.text.isEmpty || passwordController.text.isEmpty) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('请填写完整')),
                );
                return;
              }
              
              try {
                await NativeBridge.encryptProxy.addEncryptPath(
                  pathController.text,
                  passwordController.text,
                  encType,
                  encName,
                  encSuffixController.text,
                );
                
                // 重新加载配置
                await _loadConfig();
                
                if (mounted) Navigator.pop(context);
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('添加失败: $e')),
                  );
                }
              }
            },
            child: Text(S.current.confirm),
          ),
        ],
      ),
    );
  }

  void _editPath(int index) {
    final config = _encryptPaths[index];
    final pathController = TextEditingController(text: config.path);
    final passwordController = TextEditingController();
    final encSuffixController = TextEditingController(text: config.encSuffix);
    String encType = config.encType;
    bool encName = config.encName;
    bool enable = config.enable;
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('编辑加密路径'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: pathController,
                decoration: const InputDecoration(
                  labelText: '路径',
                ),
              ),
              const SizedBox(height: 16),
              _PasswordInput(
                controller: passwordController,
                labelText: '密码（留空保持不变）',
              ),
              const SizedBox(height: 16),
              StatefulBuilder(
                builder: (context, setDialogState) => Column(
                  children: [
                    DropdownButtonFormField<String>(
                      value: encType,
                      decoration: const InputDecoration(
                        labelText: '加密算法',
                      ),
                      items: const [
                        DropdownMenuItem(value: 'aes-ctr', child: Text('AES-CTR (推荐)')),
                        DropdownMenuItem(value: 'rc4md5', child: Text('RC4-MD5')),
                        DropdownMenuItem(value: 'mix', child: Text('Mix 混淆')),
                      ],
                      onChanged: (value) {
                        setDialogState(() => encType = value!);
                      },
                    ),
                    const SizedBox(height: 16),
                    SwitchListTile(
                      title: const Text('加密文件名'),
                      value: encName,
                      onChanged: (value) {
                        setDialogState(() => encName = value);
                      },
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: encSuffixController,
                      decoration: const InputDecoration(
                        labelText: '加密后缀',
                        hintText: '.bin（留空则使用原始后缀）',
                      ),
                    ),
                    SwitchListTile(
                      title: const Text('启用'),
                      value: enable,
                      onChanged: (value) {
                        setDialogState(() => enable = value);
                      },
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () async {
              try {
                await NativeBridge.encryptProxy.removeEncryptPath(index);
                await _loadConfig();
                if (mounted) Navigator.pop(context);
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('删除失败: $e')),
                  );
                }
              }
            },
            style: TextButton.styleFrom(foregroundColor: Colors.red),
            child: const Text('删除'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(S.current.cancel),
          ),
          FilledButton(
            onPressed: () async {
              try {
                // 如果密码为空，使用原密码（这里需要后端支持）
                await NativeBridge.encryptProxy.updateEncryptPath(
                  index,
                  pathController.text,
                  passwordController.text,
                  encType,
                  encName,
                  encSuffixController.text,
                  enable,
                );
                
                await _loadConfig();
                if (mounted) Navigator.pop(context);
              } catch (e) {
                if (mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(content: Text('更新失败: $e')),
                  );
                }
              }
            },
            child: Text(S.current.confirm),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _alistHostController.dispose();
    _alistPortController.dispose();
    _proxyPortController.dispose();
    _upstreamTimeoutController.dispose();
    _probeTimeoutController.dispose();
    _probeBudgetController.dispose();
    _upstreamBackoffController.dispose();
    _rangeCompatTtlController.dispose();
    _rangeCompatMinFailuresController.dispose();
    _rangeSkipMaxBytesController.dispose();
    _parallelDecryptConcurrencyController.dispose();
    _streamBufferKbController.dispose();
    _webdavNegativeCacheTtlController.dispose();
    _dbExportBaseUrlController.dispose();
    _dbExportSyncIntervalController.dispose();
    _dbExportUsernameController.dispose();
    _dbExportPasswordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('加密代理配置'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _initAndLoadConfig,
            tooltip: '刷新',
          ),
          IconButton(
            icon: const Icon(Icons.save),
            onPressed: _saveConfig,
            tooltip: '保存',
          ),
        ],
      ),
      body: _isLoading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // 代理状态卡片
                    Card(
                      child: Padding(
                        padding: const EdgeInsets.all(16),
                        child: Row(
                          children: [
                            Icon(
                              _proxyRunning ? Icons.check_circle : Icons.cancel,
                              color: _proxyRunning ? Colors.green : Colors.grey,
                              size: 48,
                            ),
                            const SizedBox(width: 16),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    _proxyRunning ? '代理运行中' : '代理已停止',
                                    style: Theme.of(context).textTheme.titleLarge,
                                  ),
                                  if (_proxyRunning)
                                    Text(
                                      '访问地址: http://127.0.0.1:${_proxyPortController.text}',
                                      style: Theme.of(context).textTheme.bodySmall,
                                    ),
                                ],
                              ),
                            ),
                            FilledButton.tonal(
                              onPressed: _toggleProxy,
                              child: Text(_proxyRunning ? '停止' : '启动'),
                            ),
                          ],
                        ),
                      ),
                    ),
                    
                    const SizedBox(height: 24),
                    
                    // Alist 服务器配置
                    Text(
                      'Alist 服务器',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          flex: 3,
                          child: TextFormField(
                            controller: _alistHostController,
                            decoration: const InputDecoration(
                              labelText: '主机地址',
                              hintText: '127.0.0.1',
                            ),
                            validator: (value) {
                              if (value == null || value.isEmpty) {
                                return '请输入主机地址';
                              }
                              return null;
                            },
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          flex: 1,
                          child: TextFormField(
                            controller: _alistPortController,
                            decoration: const InputDecoration(
                              labelText: '端口',
                            ),
                            keyboardType: TextInputType.number,
                            validator: (value) {
                              if (value == null || value.isEmpty) {
                                return '请输入端口';
                              }
                              final port = int.tryParse(value);
                              if (port == null || port < 1 || port > 65535) {
                                return '端口无效';
                              }
                              return null;
                            },
                          ),
                        ),
                      ],
                    ),
                    SwitchListTile(
                      title: const Text('本地/私网直连（全局，绕过系统代理）'),
                      value: _enableLocalBypass,
                      onChanged: (value) => setState(() => _enableLocalBypass = value),
                    ),
                    SwitchListTile(
                      title: const Text('播放优先兜底（解密失败时透传）'),
                      value: _playFirstFallback,
                      onChanged: (value) => setState(() => _playFirstFallback = value),
                    ),
                    SwitchListTile(
                      title: const Text('启用 Range 兼容缓存'),
                      value: _enableRangeCompatCache,
                      onChanged: (value) => setState(() => _enableRangeCompatCache = value),
                    ),
                    Row(
                      children: [
                        Expanded(
                          child: TextFormField(
                            controller: _rangeCompatTtlController,
                            decoration: const InputDecoration(
                              labelText: 'Range 兼容缓存 TTL（分钟）',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: TextFormField(
                            controller: _rangeCompatMinFailuresController,
                            decoration: const InputDecoration(
                              labelText: 'Range 失败阈值',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    TextFormField(
                      controller: _rangeSkipMaxBytesController,
                      decoration: const InputDecoration(
                        labelText: 'Range 跳过上限（字节）',
                      ),
                      keyboardType: TextInputType.number,
                    ),
                    SwitchListTile(
                      title: const Text('启用并行解密'),
                      value: _enableParallelDecrypt,
                      onChanged: (value) => setState(() => _enableParallelDecrypt = value),
                    ),
                    Row(
                      children: [
                        Expanded(
                          child: TextFormField(
                            controller: _parallelDecryptConcurrencyController,
                            decoration: const InputDecoration(
                              labelText: '并行解密并发',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: TextFormField(
                            controller: _streamBufferKbController,
                            decoration: const InputDecoration(
                              labelText: '流缓冲 KB',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    TextFormField(
                      controller: _webdavNegativeCacheTtlController,
                      decoration: const InputDecoration(
                        labelText: 'WebDAV 负缓存 TTL（分钟）',
                      ),
                      keyboardType: TextInputType.number,
                    ),
                    SwitchListTile(
                      title: const Text('使用 HTTPS'),
                      value: _alistHttps,
                      onChanged: (value) => setState(() => _alistHttps = value),
                    ),
                    SwitchListTile(
                      title: const Text('启用 H2C (HTTP/2 明文)'),
                      subtitle: const Text('需要后端 OpenList 也开启 enable_h2c'),
                      value: _enableH2C,
                      onChanged: (value) async {
                        setState(() => _enableH2C = value);
                        try {
                          await NativeBridge.encryptProxy.setEncryptEnableH2C(value);
                        } catch (e) {
                          debugPrint('Failed to set H2C: $e');
                        }
                      },
                    ),

                    const SizedBox(height: 24),

                    // DB_EXPORT API 同步配置
                    Text(
                      'DB_EXPORT 同步',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    SwitchListTile(
                      title: const Text('启用 DB_EXPORT 元数据同步'),
                      subtitle: const Text('从远端 exportFileMeta 增量拉取元数据到本地数据库'),
                      value: _enableDbExportSync,
                      onChanged: (value) => setState(() => _enableDbExportSync = value),
                    ),
                    if (_enableDbExportSync) ...[
                      TextFormField(
                        controller: _dbExportBaseUrlController,
                        decoration: const InputDecoration(
                          labelText: 'API 地址',
                          hintText: 'http://127.0.0.1:5344',
                        ),
                        validator: (value) {
                          if (!_enableDbExportSync) return null;
                          if (value == null || value.trim().isEmpty) {
                            return '请输入 API 地址';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 8),
                      TextFormField(
                        controller: _dbExportSyncIntervalController,
                        decoration: const InputDecoration(
                          labelText: '同步间隔（秒）',
                          hintText: '300',
                        ),
                        keyboardType: TextInputType.number,
                        validator: (value) {
                          if (!_enableDbExportSync) return null;
                          final interval = int.tryParse(value ?? '');
                          if (interval == null || interval <= 0) {
                            return '请输入有效同步间隔';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 8),
                      SwitchListTile(
                        title: const Text('启用鉴权'),
                        subtitle: const Text('开启后使用 /enc-api/login 获取 token'),
                        value: _dbExportAuthEnabled,
                        onChanged: (value) => setState(() => _dbExportAuthEnabled = value),
                      ),
                    ],
                    if (_enableDbExportSync && _dbExportAuthEnabled) ...[
                      TextFormField(
                        controller: _dbExportUsernameController,
                        decoration: const InputDecoration(
                          labelText: '账号',
                          hintText: 'admin',
                        ),
                        validator: (value) {
                          if (!_enableDbExportSync || !_dbExportAuthEnabled) return null;
                          if (value == null || value.trim().isEmpty) {
                            return '请输入账号';
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 8),
                      _PasswordInput(
                        controller: _dbExportPasswordController,
                        labelText: '密码（留空保持不变）',
                      ),
                    ],
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('主动探测 / 数据同步状态'),
                      subtitle: Text(
                        _dbExportBaseUrlController.text.trim().isEmpty
                            ? '先配置 Go 服务 API 地址后查看'
                            : '查看总量、进度、最近更新时间和下次计划时间',
                      ),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: _dbExportBaseUrlController.text.trim().isEmpty
                          ? null
                          : () {
                              Navigator.of(context).push(
                                MaterialPageRoute(
                                  builder: (_) => DirSyncStatusPage(
                                    baseUrl: _dbExportBaseUrlController.text.trim(),
                                    proxyPort: int.tryParse(_proxyPortController.text) ?? 5344,
                                  ),
                                ),
                              );
                            },
                    ),
                    
                    const SizedBox(height: 24),

                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      title: const Text('网盘分流规则'),
                      subtitle: const Text('按 provider/driver 配置直连或代理（白名单逻辑已收敛到网盘规则）'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () async {
                        final proxyPort = int.tryParse(_proxyPortController.text) ?? 5344;
                        await Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) => ProviderRoutingPage(proxyPort: proxyPort),
                          ),
                        );
                        await _loadConfigViaV2Api();
                      },
                    ),
                    const SizedBox(height: 8),

                    // 本地目录挂载入口
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.folder),
                      title: const Text('高级：本地目录挂载'),
                      subtitle: const Text('把手机目录作为 OpenList Local 存储浏览；媒体备份不需要配置这里'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) => const LocalMountPage(),
                          ),
                        );
                      },
                    ),
                    const SizedBox(height: 8),

                    // 同步任务入口
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.sync),
                      title: const Text('媒体加密备份'),
                      subtitle: const Text('照片/视频定时上传到已启用加密路径，可选择成功后删除本地'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () {
                        Navigator.of(context).push(
                          MaterialPageRoute(
                            builder: (_) => const SyncTaskListPage(),
                          ),
                        );
                      },
                    ),
                    const SizedBox(height: 8),

                    // 代理端口配置
                    Text(
                      '代理端口',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    TextFormField(
                      controller: _proxyPortController,
                      decoration: const InputDecoration(
                        labelText: '代理端口',
                        hintText: '5344',
                      ),
                      keyboardType: TextInputType.number,
                      validator: (value) {
                        if (value == null || value.isEmpty) {
                          return '请输入代理端口';
                        }
                        final port = int.tryParse(value);
                        if (port == null || port < 1 || port > 65535) {
                          return '端口无效';
                        }
                        return null;
                      },
                    ),

                    const SizedBox(height: 24),

                    Text(
                      '网络策略',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: TextFormField(
                            controller: _upstreamTimeoutController,
                            decoration: const InputDecoration(
                              labelText: '上游超时（秒）',
                              hintText: '8',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: TextFormField(
                            controller: _probeTimeoutController,
                            decoration: const InputDecoration(
                              labelText: '单次探测超时（秒）',
                              hintText: '3',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Expanded(
                          child: TextFormField(
                            controller: _probeBudgetController,
                            decoration: const InputDecoration(
                              labelText: '探测总预算（秒）',
                              hintText: '5',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: TextFormField(
                            controller: _upstreamBackoffController,
                            decoration: const InputDecoration(
                              labelText: '失败退避（秒）',
                              hintText: '20',
                            ),
                            keyboardType: TextInputType.number,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 24),

                    Text(
                      '参数边界说明（V2）',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    if (_configDocs.isEmpty)
                      const Text(
                        '未获取到说明（请先启动代理后刷新）',
                        style: TextStyle(color: Colors.grey),
                      )
                    else
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: Column(
                            children: _configDocs.take(8).map((item) {
                              final label = item['label']?.toString() ?? item['key']?.toString() ?? '-';
                              final desc = item['description']?.toString() ?? '';
                              final min = item['min']?.toString() ?? '-';
                              final max = item['max']?.toString() ?? '-';
                              final def = item['default']?.toString() ?? '-';
                              final unit = item['unit']?.toString() ?? '';
                              return Padding(
                                padding: const EdgeInsets.symmetric(vertical: 4),
                                child: Align(
                                  alignment: Alignment.centerLeft,
                                  child: Text(
                                    '$label: $desc (范围 $min-$max$unit, 默认 $def$unit)',
                                    style: Theme.of(context).textTheme.bodySmall,
                                  ),
                                ),
                              );
                            }).toList(),
                          ),
                        ),
                      ),

                    const SizedBox(height: 24),
                    
                    // 加密路径配置
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          '加密路径',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        IconButton(
                          icon: const Icon(Icons.add),
                          onPressed: _showAddPathDialog,
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    if (_encryptPaths.isEmpty)
                      Card(
                        child: Padding(
                          padding: const EdgeInsets.all(24),
                          child: Center(
                            child: Column(
                              children: [
                                Icon(
                                  Icons.folder_off,
                                  size: 48,
                                  color: Theme.of(context).hintColor,
                                ),
                                const SizedBox(height: 8),
                                Text(
                                  '暂无加密路径',
                                  style: TextStyle(
                                    color: Theme.of(context).hintColor,
                                  ),
                                ),
                                const SizedBox(height: 8),
                                TextButton.icon(
                                  onPressed: _showAddPathDialog,
                                  icon: const Icon(Icons.add),
                                  label: const Text('添加'),
                                ),
                              ],
                            ),
                          ),
                        ),
                      )
                    else
                      ListView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        itemCount: _encryptPaths.length,
                        itemBuilder: (context, index) {
                          final config = _encryptPaths[index];
                          return Card(
                            child: ListTile(
                              leading: Icon(
                                config.enable
                                    ? Icons.lock
                                    : Icons.lock_open,
                                color: config.enable
                                    ? Colors.green
                                    : Colors.grey,
                              ),
                              title: Text(config.path),
                              subtitle: Text(
                                '${config.encType.toUpperCase()} | '
                                '${config.encName ? "加密文件名" : "不加密文件名"}'
                                '${config.encSuffix.isEmpty ? "" : " | 后缀 ${config.encSuffix}"}',
                              ),
                              trailing: Switch(
                                value: config.enable,
                                onChanged: (value) async {
                                  try {
                                    await NativeBridge.encryptProxy.updateEncryptPath(
                                      index,
                                      config.path,
                                      '', // 密码保持不变
                                      config.encType,
                                      config.encName,
                                      config.encSuffix,
                                      value,
                                    );
                                    await _loadConfig();
                                  } catch (e) {
                                    if (mounted) {
                                      ScaffoldMessenger.of(context).showSnackBar(
                                        SnackBar(content: Text('更新失败: $e')),
                                      );
                                    }
                                  }
                                },
                              ),
                              onTap: () => _editPath(index),
                            ),
                          );
                        },
                      ),
                    
                    const SizedBox(height: 24),
                    
                    // 使用说明
                    ExpansionTile(
                      title: const Text('使用说明'),
                      children: [
                        Padding(
                          padding: const EdgeInsets.all(16),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: const [
                              Text('1. 配置 Alist 服务器地址和端口'),
                              SizedBox(height: 8),
                              Text('2. 添加需要加密的路径，支持通配符 *'),
                              SizedBox(height: 8),
                              Text('3. 设置每个路径的加密密码'),
                              SizedBox(height: 8),
                              Text('4. 启动代理服务'),
                              SizedBox(height: 8),
                              Text('5. 通过代理地址访问 Alist，加密路径下的文件会自动加解密'),
                              SizedBox(height: 16),
                              Text(
                                '提示：AES-CTR 算法性能更好，推荐使用',
                                style: TextStyle(color: Colors.grey),
                              ),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
    );
  }
}

/// 加密路径配置
class EncryptPathConfig {
  final String path;
  final String password;
  final String encType;
  final bool encName;
  final String encSuffix;
  final bool enable;

  EncryptPathConfig({
    required this.path,
    required this.password,
    required this.encType,
    required this.encName,
    required this.encSuffix,
    required this.enable,
  });
}

class _PasswordInput extends StatefulWidget {
  final TextEditingController controller;
  final String labelText;

  const _PasswordInput({
    required this.controller,
    required this.labelText,
  });

  @override
  State<_PasswordInput> createState() => _PasswordInputState();
}

class _PasswordInputState extends State<_PasswordInput> {
  bool _obscureText = true;

  @override
  Widget build(BuildContext context) {
    return TextField(
      controller: widget.controller,
      obscureText: _obscureText,
      decoration: InputDecoration(
        labelText: widget.labelText,
        suffixIcon: IconButton(
          icon: Icon(
            _obscureText ? Icons.visibility : Icons.visibility_off,
          ),
          onPressed: () {
            setState(() {
              _obscureText = !_obscureText;
            });
          },
        ),
      ),
    );
  }
}
