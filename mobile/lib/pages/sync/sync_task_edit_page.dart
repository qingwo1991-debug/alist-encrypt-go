import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';

import '../../contant/native_bridge.dart';
import '../../models/sync_task.dart';
import '../../utils/sync_task_manager.dart';
import '../../utils/storage_permission_helper.dart';

class SyncTaskEditPage extends StatefulWidget {
  final SyncTask? existingTask;

  const SyncTaskEditPage({super.key, this.existingTask});

  @override
  State<SyncTaskEditPage> createState() => _SyncTaskEditPageState();
}

class _SyncTaskEditPageState extends State<SyncTaskEditPage> {
  final _formKey = GlobalKey<FormState>();
  final _nameController = TextEditingController();
  final _sourcePathController = TextEditingController();
  final _targetPathController = TextEditingController();
  final _excludeFoldersController = TextEditingController();

  int _intervalHours = 1;
  bool _wifiOnly = true;
  bool _enabled = true;
  bool _deleteAfterSync = false;
  bool _preserveFolderStructure = true;
  List<String> _selectedExtensions = [];
  final Set<String> _selectedPresets = {};
  List<String> _enabledEncryptPaths = [];

  bool get isEditing => widget.existingTask != null;

  @override
  void initState() {
    super.initState();
    final task = widget.existingTask;
    if (task != null) {
      _nameController.text = task.name;
      _sourcePathController.text = task.sourcePath;
      _targetPathController.text = task.targetPath;
      _excludeFoldersController.text = task.excludeFolders.join(', ');
      _intervalHours = task.intervalHours;
      _wifiOnly = task.wifiOnly;
      _enabled = task.enabled;
      _deleteAfterSync = task.deleteAfterSync;
      _preserveFolderStructure = task.preserveFolderStructure;
      _selectedExtensions = List.from(task.fileExtensions);

      // 反推预设选中状态
      for (final entry in SyncTask.presetExtensions.entries) {
        if (entry.value.every((ext) => _selectedExtensions.contains(ext))) {
          _selectedPresets.add(entry.key);
        }
      }
    } else {
      _selectedPresets
        ..add('照片')
        ..add('视频');
      _selectedExtensions = [
        ...SyncTask.presetExtensions['照片']!,
        ...SyncTask.presetExtensions['视频']!,
      ];
    }
    _loadEncryptPaths();
  }

  @override
  void dispose() {
    _nameController.dispose();
    _sourcePathController.dispose();
    _targetPathController.dispose();
    _excludeFoldersController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(isEditing ? '编辑媒体备份' : '新建媒体备份'),
        actions: [
          if (isEditing)
            const Padding(
              padding: EdgeInsets.only(right: 16),
              child: Center(
                child: Text('编辑模式', style: TextStyle(fontSize: 13)),
              ),
            ),
        ],
      ),
      body: Form(
        key: _formKey,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            TextFormField(
              controller: _nameController,
              decoration: const InputDecoration(
                labelText: '任务名称',
                hintText: '例: 相册加密备份',
              ),
              validator: (v) => v == null || v.isEmpty ? '请输入任务名称' : null,
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _sourcePathController,
              decoration: InputDecoration(
                labelText: '源目录路径',
                hintText: '/storage/emulated/0/DCIM',
                suffixIcon: IconButton(
                  icon: const Icon(Icons.folder_open),
                  onPressed: _pickSourceDir,
                ),
              ),
              validator: (v) => v == null || v.isEmpty ? '请输入源目录路径' : null,
            ),
            const SizedBox(height: 16),
            TextFormField(
              controller: _targetPathController,
              decoration: InputDecoration(
                labelText: '云端加密目标路径',
                hintText: _enabledEncryptPaths.isEmpty
                    ? '/encrypt/photos'
                    : '${_enabledEncryptPaths.first}/photos',
                suffixIcon: IconButton(
                  icon: const Icon(Icons.lock),
                  tooltip: '选择已启用加密路径',
                  onPressed: _enabledEncryptPaths.isEmpty
                      ? null
                      : _showEncryptPathPicker,
                ),
              ),
              validator: (v) {
                if (v == null || v.trim().isEmpty) return '请输入目标路径';
                if (!_isCoveredByEnabledEncryptPath(v.trim())) {
                  return '目标路径必须位于已启用的加密路径内';
                }
                return null;
              },
            ),
            if (_enabledEncryptPaths.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 4,
                children: _enabledEncryptPaths.map((path) {
                  return ActionChip(
                    avatar: const Icon(Icons.lock, size: 16),
                    label: Text(path),
                    onPressed: () => _applyEncryptPath(path),
                  );
                }).toList(),
              ),
            ] else ...[
              const SizedBox(height: 8),
              Text(
                '请先在加密路径中添加并启用目标路径，否则不会创建备份任务。',
                style: TextStyle(
                  color: Theme.of(context).colorScheme.error,
                  fontSize: 13,
                ),
              ),
            ],
            const SizedBox(height: 16),

            // 文件类型预设
            Text('备份文件类型', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 4,
              children: [
                _buildPresetChip(SyncTask.allFilesLabel),
                ...SyncTask.presetExtensions.keys.map(_buildPresetChip),
              ],
            ),
            if (_selectedExtensions.isNotEmpty) ...[
              const SizedBox(height: 8),
              Text(
                '已选扩展名: ${_selectedExtensions.join(', ')}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
            const SizedBox(height: 16),

            // 排除目录
            TextFormField(
              controller: _excludeFoldersController,
              decoration: const InputDecoration(
                labelText: '排除目录',
                hintText: '多个目录用逗号分隔, 例: temp, cache',
              ),
            ),
            const SizedBox(height: 16),

            // 同步间隔
            DropdownButtonFormField<int>(
              value: _intervalHours,
              decoration: const InputDecoration(labelText: '同步间隔'),
              items: const [
                DropdownMenuItem(value: 1, child: Text('1 小时')),
                DropdownMenuItem(value: 2, child: Text('2 小时')),
                DropdownMenuItem(value: 4, child: Text('4 小时')),
                DropdownMenuItem(value: 6, child: Text('6 小时')),
                DropdownMenuItem(value: 12, child: Text('12 小时')),
                DropdownMenuItem(value: 24, child: Text('24 小时')),
              ],
              onChanged: (v) => setState(() => _intervalHours = v ?? 1),
            ),
            const SizedBox(height: 8),

            // 开关项
            SwitchListTile(
              title: const Text('仅 WiFi 下同步'),
              value: _wifiOnly,
              onChanged: (v) => setState(() => _wifiOnly = v),
              contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text('启用任务'),
              value: _enabled,
              onChanged: (v) => setState(() => _enabled = v),
              contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text('保留目录结构'),
              subtitle: const Text('目标路径会保留源目录中的相对路径'),
              value: _preserveFolderStructure,
              onChanged: (v) => setState(() => _preserveFolderStructure = v),
              contentPadding: EdgeInsets.zero,
            ),
            SwitchListTile(
              title: const Text('同步后删除源文件 ⚠️'),
              subtitle: const Text('只删除已成功上传到加密目标路径的文件'),
              value: _deleteAfterSync,
              onChanged: (v) => setState(() => _deleteAfterSync = v),
              contentPadding: EdgeInsets.zero,
            ),
            if (_deleteAfterSync)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Card(
                  color: Colors.red.shade50,
                  child: const Padding(
                    padding: EdgeInsets.all(12),
                    child: Row(
                      children: [
                        Icon(Icons.warning_amber, color: Colors.red),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            '启用后，只有确认上传成功的文件会从本地删除。目标路径未命中加密配置时任务会直接失败，不会删除本地文件。',
                            style: TextStyle(color: Colors.red, fontSize: 13),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),

            const SizedBox(height: 24),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('取消'),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: FilledButton(
                    onPressed: _save,
                    child: Text(isEditing ? '更新' : '创建'),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPresetChip(String name) {
    final isSelected = name == SyncTask.allFilesLabel
        ? _selectedExtensions.isEmpty
        : _selectedPresets.contains(name);

    return FilterChip(
      label: Text(name),
      selected: isSelected,
      onSelected: (selected) {
        setState(() {
          if (name == SyncTask.allFilesLabel) {
            _selectedExtensions = [];
            _selectedPresets.clear();
            return;
          }

          if (selected) {
            _selectedPresets.add(name);
            final temp = SyncTask(id: '', name: '', sourcePath: '', targetPath: '');
            temp.fileExtensions = List.from(_selectedExtensions);
            temp.mergePreset(name);
            _selectedExtensions = temp.fileExtensions;
          } else {
            _selectedPresets.remove(name);
            _selectedExtensions = [];
            for (final preset in _selectedPresets) {
              final temp = SyncTask(id: '', name: '', sourcePath: '', targetPath: '');
              temp.fileExtensions = List.from(_selectedExtensions);
              temp.mergePreset(preset);
              _selectedExtensions = temp.fileExtensions;
            }
          }
        });
      },
    );
  }

  Future<void> _pickSourceDir() async {
    final granted = await StoragePermissionHelper.requestWithRationale(context);
    if (!granted) return;

    final result = await FilePicker.platform.getDirectoryPath(
      dialogTitle: '选择源目录',
    );
    if (result != null) {
      _sourcePathController.text = result;
    }
  }

  Future<void> _loadEncryptPaths() async {
    try {
      final configJson = await NativeBridge.encryptProxy.getEncryptConfigJson();
      if (!mounted || configJson.isEmpty || configJson == '{}') return;
      final config = json.decode(configJson) as Map<String, dynamic>;
      final paths = config['encryptPaths'] as List<dynamic>? ?? [];
      final enabled = paths
          .whereType<Map>()
          .where((p) => p['enable'] as bool? ?? true)
          .map((p) => _normalizeOpenListPath(p['path']?.toString() ?? ''))
          .where((p) => p.isNotEmpty)
          .toSet()
          .toList()
        ..sort();
      setState(() {
        _enabledEncryptPaths = enabled;
      });
    } catch (_) {
      if (mounted) {
        setState(() {
          _enabledEncryptPaths = [];
        });
      }
    }
  }

  void _showEncryptPathPicker() {
    showModalBottomSheet<void>(
      context: context,
      builder: (ctx) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            for (final path in _enabledEncryptPaths)
              ListTile(
                leading: const Icon(Icons.lock),
                title: Text(path),
                onTap: () {
                  Navigator.pop(ctx);
                  _applyEncryptPath(path);
                },
              ),
          ],
        ),
      ),
    );
  }

  void _applyEncryptPath(String path) {
    _targetPathController.text = path;
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;

    final manager = SyncTaskManager();
    await manager.loadTasks();

    final excludeFolders = _excludeFoldersController.text
        .split(',')
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();

    final taskId = isEditing
        ? widget.existingTask!.id
        : 'sync_${DateTime.now().millisecondsSinceEpoch}';

    final task = SyncTask(
      id: taskId,
      name: _nameController.text.trim(),
      sourcePath: _sourcePathController.text.trim(),
      targetPath: _normalizeOpenListPath(_targetPathController.text),
      fileExtensions: _selectedExtensions,
      excludeFolders: excludeFolders,
      intervalHours: _intervalHours,
      wifiOnly: _wifiOnly,
      enabled: _enabled,
      deleteAfterSync: _deleteAfterSync,
      preserveFolderStructure: _preserveFolderStructure,
      lastSyncTime: widget.existingTask?.lastSyncTime,
      lastSyncFileCount: widget.existingTask?.lastSyncFileCount,
      lastError: widget.existingTask?.lastError,
    );

    if (isEditing) {
      await manager.updateTask(task);
    } else {
      await manager.addTask(task);
    }

    if (mounted) Navigator.pop(context);
  }

  bool _isCoveredByEnabledEncryptPath(String path) {
    final target = _normalizeOpenListPath(path);
    if (target.isEmpty || _enabledEncryptPaths.isEmpty) return false;
    return _enabledEncryptPaths.any((encryptPath) {
      return encryptPath == '/' ||
          target == encryptPath ||
          target.startsWith('$encryptPath/');
    });
  }

  String _normalizeOpenListPath(String path) {
    final trimmed = path.trim().replaceAll('\\', '/');
    if (trimmed == '/') return '/';
    final wildcardNormalized = trimmed.endsWith('/*')
        ? trimmed.substring(0, trimmed.length - 2)
        : trimmed;
    final normalized = wildcardNormalized.replaceAll(RegExp(r'/+$'), '');
    if (normalized.isEmpty) return '';
    return normalized.startsWith('/') ? normalized : '/$normalized';
  }
}
