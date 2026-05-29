import 'dart:async';

import 'package:flutter/material.dart';

import '../../models/sync_task.dart';
import '../../utils/sync_task_manager.dart';
import 'sync_task_edit_page.dart';
import 'sync_history_page.dart';

class SyncTaskListPage extends StatefulWidget {
  const SyncTaskListPage({super.key});

  @override
  State<SyncTaskListPage> createState() => _SyncTaskListPageState();
}

class _SyncTaskListPageState extends State<SyncTaskListPage> {
  final SyncTaskManager _manager = SyncTaskManager();
  final Map<String, Map<String, dynamic>> _statusByTaskId = {};
  Timer? _statusTimer;

  @override
  void initState() {
    super.initState();
    _manager.addListener(_onChanged);
    _reloadTasks();
    _statusTimer = Timer.periodic(const Duration(seconds: 2), (_) {
      _refreshStatuses();
    });
  }

  @override
  void dispose() {
    _statusTimer?.cancel();
    _manager.removeListener(_onChanged);
    super.dispose();
  }

  void _onChanged() {
    if (mounted) setState(() {});
  }

  Future<void> _reloadTasks() async {
    await _manager.loadTasks();
    await _refreshStatuses();
  }

  Future<void> _refreshStatuses() async {
    if (!mounted || !_manager.isLoaded || _manager.tasks.isEmpty) return;
    final next = <String, Map<String, dynamic>>{};
    for (final task in _manager.tasks) {
      final status = await _manager.getTaskStatus(task.id);
      if (status != null) {
        next[task.id] = status;
      }
    }
    if (!mounted) return;
    setState(() {
      _statusByTaskId
        ..clear()
        ..addAll(next);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('媒体加密备份'),
        actions: [
          IconButton(
            icon: const Icon(Icons.add),
            onPressed: () => _openEditPage(null),
            tooltip: '新建媒体备份',
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (!_manager.isLoaded) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_manager.tasks.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.cloud_upload_outlined,
              size: 64,
              color: Theme.of(context).hintColor,
            ),
            const SizedBox(height: 16),
            Text(
              '暂无媒体备份任务',
              style: TextStyle(color: Theme.of(context).hintColor, fontSize: 16),
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              icon: const Icon(Icons.add),
              label: const Text('新建媒体备份'),
              onPressed: () => _openEditPage(null),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _manager.tasks.length,
      itemBuilder: (context, index) {
        final task = _manager.tasks[index];
        return _buildTaskCard(task);
      },
    );
  }

  Widget _buildTaskCard(SyncTask task) {
    final status = _statusByTaskId[task.id];
    return Card(
      child: ExpansionTile(
        leading: Icon(
          task.enabled ? Icons.sync : Icons.sync_disabled,
          color: task.enabled ? Colors.green : Colors.grey,
        ),
        title: Text(task.name),
        subtitle: Text(
          '${task.sourcePath} → ${task.targetPath}',
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
        ),
        children: [
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildInfoRow('手机目录', task.sourcePath),
                _buildInfoRow('加密目标路径', task.targetPath),
                _buildInfoRow(
                  '文件类型',
                  task.fileExtensions.isEmpty
                      ? '全部文件'
                      : task.fileExtensions.join(', '),
                ),
                _buildInfoRow('排除目录', task.excludeFolders.isEmpty ? '无' : task.excludeFolders.join(', ')),
                _buildInfoRow('同步间隔', '${task.intervalHours}小时'),
                _buildInfoRow('仅在WiFi下', task.wifiOnly ? '是' : '否'),
                _buildInfoRow('保留目录结构', task.preserveFolderStructure ? '是' : '否'),
                _buildInfoRow('备份后删除本地', task.deleteAfterSync ? '是 ⚠️' : '否'),
                if (status != null)
                  _buildInfoRow(
                    '运行状态',
                    _describeStatus(status),
                    isError: _isFailedStatus(status),
                  ),
                if (status != null && _hasRuntimeProgress(status))
                  _buildRuntimeProgress(status),
                if (status != null && status['lastHistoryEntry'] is Map)
                  ..._buildHistorySummaryRows(
                    status['lastHistoryEntry'] as Map<String, dynamic>,
                  ),
                if (task.lastSyncTime != null)
                  _buildInfoRow(
                    '上次同步',
                    DateTime.fromMillisecondsSinceEpoch(task.lastSyncTime!)
                        .toString()
                        .substring(0, 19),
                  ),
                if (task.lastSyncFileCount != null)
                  _buildInfoRow('上次扫描文件数', '${task.lastSyncFileCount}'),
                if (task.lastError != null && task.lastError!.isNotEmpty)
                  _buildInfoRow('最后错误', task.lastError!, isError: true),
                const SizedBox(height: 8),
                Row(
                  mainAxisAlignment: MainAxisAlignment.end,
                  children: [
                    TextButton.icon(
                      icon: const Icon(Icons.history),
                      label: const Text('历史'),
                      onPressed: () => _openHistory(task),
                    ),
                    TextButton.icon(
                      icon: const Icon(Icons.play_arrow),
                      label: const Text('立即执行'),
                      onPressed: () => _runNow(task),
                    ),
                    TextButton.icon(
                      icon: const Icon(Icons.restart_alt),
                      label: const Text('重传'),
                      onPressed: () => _confirmRerunFromScratch(task),
                    ),
                    TextButton.icon(
                      icon: const Icon(Icons.edit),
                      label: const Text('编辑'),
                      onPressed: () => _openEditPage(task),
                    ),
                    TextButton.icon(
                      icon: const Icon(Icons.delete, color: Colors.red),
                      label: const Text('删除'),
                      onPressed: () => _confirmDelete(task),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoRow(String label, String value, {bool isError = false}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              label,
              style: TextStyle(
                color: Theme.of(context).hintColor,
                fontSize: 13,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontSize: 13,
                color: isError ? Colors.red : null,
              ),
            ),
          ),
        ],
      ),
    );
  }

  List<Widget> _buildHistorySummaryRows(Map<String, dynamic> history) {
    final totalFiles = history['totalFiles'] as int? ?? 0;
    final pendingFiles = history['pendingFiles'] as int? ?? totalFiles;
    final skippedFiles = history['skippedFiles'] as int? ?? 0;
    final successCount = history['successCount'] as int? ?? 0;
    final failureCount = history['failureCount'] as int? ?? 0;
    return [
      _buildInfoRow('本次扫描', '$totalFiles'),
      _buildInfoRow('待上传', '$pendingFiles'),
      _buildInfoRow('已跳过', '$skippedFiles'),
      _buildInfoRow('成功/失败', '$successCount / $failureCount',
          isError: failureCount > 0),
    ];
  }

  bool _hasRuntimeProgress(Map<String, dynamic> status) {
    return status['scannedFiles'] != null ||
        status['pendingFiles'] != null ||
        status['uploadedFiles'] != null ||
        status['failedFiles'] != null ||
        status['currentFile'] != null;
  }

  Widget _buildRuntimeProgress(Map<String, dynamic> status) {
    final scannedFiles = status['scannedFiles'] as int?;
    final pendingFiles = status['pendingFiles'] as int?;
    final skippedFiles = status['skippedFiles'] as int?;
    final uploadedFiles = status['uploadedFiles'] as int? ?? 0;
    final failedFiles = status['failedFiles'] as int? ?? 0;
    final currentFile = status['currentFile']?.toString();
    final phase = _describePhase(status['currentPhase']?.toString());
    final denominator = pendingFiles ?? scannedFiles ?? 0;
    final completed = uploadedFiles + failedFiles;
    final progress = denominator > 0 ? (completed / denominator).clamp(0.0, 1.0) : null;

    return Padding(
      padding: const EdgeInsets.only(top: 6, bottom: 4),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildInfoRow('当前阶段', phase),
          if (currentFile != null && currentFile.isNotEmpty)
            _buildInfoRow('当前文件', currentFile),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _buildMetricChip('扫描', '${scannedFiles ?? 0}', Colors.blue),
              _buildMetricChip('待传', '${pendingFiles ?? 0}', Colors.deepPurple),
              _buildMetricChip('跳过', '${skippedFiles ?? 0}', Colors.teal),
              _buildMetricChip('成功', '$uploadedFiles', Colors.green),
              _buildMetricChip('失败', '$failedFiles',
                  failedFiles > 0 ? Colors.red : Colors.grey),
            ],
          ),
          const SizedBox(height: 8),
          LinearProgressIndicator(value: progress),
        ],
      ),
    );
  }

  Widget _buildMetricChip(String label, String value, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Text(
        '$label $value',
        style: TextStyle(
          color: color,
          fontSize: 12,
          fontWeight: FontWeight.w500,
        ),
      ),
    );
  }

  Future<void> _openEditPage(SyncTask? task) async {
    await Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SyncTaskEditPage(existingTask: task),
      ),
    );
    await _reloadTasks();
  }

  Future<void> _openHistory(SyncTask task) async {
    await Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => SyncHistoryPage(taskId: task.id, taskName: task.name),
      ),
    );
  }

  Future<void> _runNow(SyncTask task) async {
    try {
      await _manager.runTaskNow(task.id);
      await _refreshStatuses();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('任务 "${task.name}" 已开始执行')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('执行失败: $e')),
        );
      }
    }
  }

  Future<void> _confirmRerunFromScratch(SyncTask task) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清空记录并重传'),
        content: Text(
          '这会清空任务 "${task.name}" 的本地增量记录，并重新上传当前扫描到的文件。云端已有同名文件可能被覆盖，是否继续？',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('继续'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      await _manager.rerunTaskFromScratch(task.id);
      await _refreshStatuses();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('任务 "${task.name}" 已清空记录并重新执行')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('重传失败: $e')),
        );
      }
    }
  }

  bool _isFailedStatus(Map<String, dynamic> status) {
    final oneTimeState = status['oneTimeState']?.toString() ?? '';
    final periodicState = status['periodicState']?.toString() ?? '';
    return oneTimeState == 'FAILED' || periodicState == 'FAILED';
  }

  String _describeStatus(Map<String, dynamic> status) {
    final oneTimeState = status['oneTimeState']?.toString() ?? 'NONE';
    final periodicState = status['periodicState']?.toString() ?? 'UNKNOWN';
    if (oneTimeState != 'NONE') {
      return '立即任务: $oneTimeState';
    }
    return '周期任务: $periodicState';
  }

  String _describePhase(String? phase) {
    switch (phase) {
      case 'PREPARING':
        return '准备中';
      case 'SCANNING':
        return '扫描本地文件';
      case 'READY':
        return '等待上传';
      case 'UPLOADING':
        return '上传中';
      case 'COMPLETED':
        return '已完成';
      default:
        return '未知';
    }
  }

  void _confirmDelete(SyncTask task) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('删除备份任务'),
        content: Text('确定要删除媒体备份任务 "${task.name}" 吗？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () {
              _manager.deleteTask(task.id);
              Navigator.pop(ctx);
            },
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('删除'),
          ),
        ],
      ),
    );
  }
}
