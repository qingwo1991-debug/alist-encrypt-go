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
  String? _togglingTaskId;

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

  Future<void> _refreshTasks() async {
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
          PopupMenuButton<String>(
            onSelected: (value) {
              if (value == 'clear_all_history') {
                _confirmClearAllHistory();
              }
            },
            itemBuilder: (context) => const [
              PopupMenuItem<String>(
                value: 'clear_all_history',
                child: Text('清空全部历史'),
              ),
            ],
          ),
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

    return RefreshIndicator(
      onRefresh: _refreshTasks,
      child: ListView.builder(
        padding: const EdgeInsets.all(16),
        itemCount: _manager.tasks.length,
        itemBuilder: (context, index) {
          final task = _manager.tasks[index];
          return _buildTaskCard(task);
        },
      ),
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
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              '${task.sourcePath} → ${task.targetPath}',
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            Row(
              children: [
                Text(task.enabled ? '已启用' : '已停用',
                    style: TextStyle(fontSize: 12, color: task.enabled ? Colors.green : Colors.grey)),
                const Spacer(),
                if (_togglingTaskId == task.id)
                  const SizedBox(
                    width: 20, height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                else
                  Switch(
                    value: task.enabled,
                    onChanged: (v) => _toggleTaskEnabled(task, v),
                  ),
              ],
            ),
            Padding(
              padding: const EdgeInsets.only(bottom: 4),
              child: Text(
                [
                  if (task.lastSyncTime != null)
                    '上次: ${DateTime.fromMillisecondsSinceEpoch(task.lastSyncTime!).toString().substring(5, 16)}',
                  if (status != null) _describeStatus(status),
                  if (task.lastSyncFileCount != null)
                    '${task.lastSyncFileCount} 文件',
                ].join(' · '),
                style: TextStyle(fontSize: 11, color: Theme.of(context).hintColor),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
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
                if (status != null && (status['currentUploadTaskId']?.toString().isNotEmpty ?? false))
                  _buildInfoRow('上传任务ID', status['currentUploadTaskId'].toString()),
                if (status != null && status['currentUploadTaskProgress'] != null)
                  _buildInfoRow('上传任务进度', '${status['currentUploadTaskProgress']}%'),
                if (status != null && (status['currentUploadTaskStatus']?.toString().isNotEmpty ?? false))
                  _buildInfoRow('上传任务状态', status['currentUploadTaskStatus'].toString()),
                if (status != null && (status['currentUploadTaskError']?.toString().isNotEmpty ?? false))
                  _buildInfoRow('上传任务错误', status['currentUploadTaskError'].toString(), isError: true),
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
                    FilledButton.tonalIcon(
                      icon: const Icon(Icons.play_arrow),
                      label: const Text('执行'),
                      onPressed: () => _runNow(task),
                    ),
                    const SizedBox(width: 8),
                    OutlinedButton.icon(
                      icon: const Icon(Icons.edit),
                      label: const Text('编辑'),
                      onPressed: () => _openEditPage(task),
                    ),
                    const SizedBox(width: 4),
                    IconButton(
                      icon: const Icon(Icons.delete_outline, color: Colors.red),
                      onPressed: () => _confirmDelete(task),
                      tooltip: '删除',
                    ),
                    PopupMenuButton<String>(
                      tooltip: '更多操作',
                      onSelected: (value) {
                        switch (value) {
                          case 'history': _openHistory(task); break;
                          case 'details': _showStatusDetails(task, status); break;
                          case 'clear_history': _confirmClearTaskHistory(task); break;
                          case 'clean': _confirmCleanUploadedSourceFiles(task); break;
                          case 'rerun': _confirmRerunFromScratch(task); break;
                        }
                      },
                      itemBuilder: (context) => const [
                        PopupMenuItem(value: 'history', child: Text('查看历史')),
                        PopupMenuItem(value: 'details', child: Text('运行详情')),
                        PopupMenuItem(value: 'clear_history', child: Text('清空历史')),
                        PopupMenuItem(value: 'clean', child: Text('清理已备份源文件')),
                        PopupMenuItem(value: 'rerun', child: Text('清空记录并重传')),
                      ],
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
        status['currentUploadTaskId'] != null ||
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
          if (status['currentUploadTaskId'] != null)
            _buildInfoRow('OpenList任务', status['currentUploadTaskId'].toString()),
          if (status['currentUploadTaskProgress'] != null)
            _buildInfoRow('任务进度', '${status['currentUploadTaskProgress']}%'),
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

  Future<void> _toggleTaskEnabled(SyncTask task, bool enabled) async {
    if (_togglingTaskId != null) return;
    setState(() => _togglingTaskId = task.id);
    try {
      final updated = SyncTask(
        id: task.id,
        name: task.name,
        sourcePath: task.sourcePath,
        targetPath: task.targetPath,
        fileExtensions: List.from(task.fileExtensions),
        excludeFolders: List.from(task.excludeFolders),
        intervalHours: task.intervalHours,
        wifiOnly: task.wifiOnly,
        enabled: enabled,
        deleteAfterSync: task.deleteAfterSync,
        preserveFolderStructure: task.preserveFolderStructure,
        uploadSpeedLimitKbps: task.uploadSpeedLimitKbps,
        lastSyncTime: task.lastSyncTime,
        lastSyncFileCount: task.lastSyncFileCount,
        lastError: task.lastError,
      );
      await _manager.updateTask(updated);
      if (mounted) await _reloadTasks();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('切换失败: $e')),
        );
      }
    } finally {
      if (mounted) setState(() => _togglingTaskId = null);
    }
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

  Future<void> _confirmCleanUploadedSourceFiles(SyncTask task) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清理已备份源文件'),
        content: Text(
          '将重新扫描任务“${task.name}”的本地文件，并删除那些在云端已存在且尺寸一致的源文件，用于释放手机空间。此操作不会删除云端文件，是否继续？',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('开始清理'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      final result = await _manager.cleanUploadedSourceFiles(task.id);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(result)),
      );
      await _refreshStatuses();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('清理失败: $e')),
      );
    }
  }

  bool _isFailedStatus(Map<String, dynamic> status) {
    final cleanupState = status['cleanupState']?.toString() ?? '';
    final oneTimeState = status['oneTimeState']?.toString() ?? '';
    final periodicState = status['periodicState']?.toString() ?? '';
    return cleanupState == 'FAILED' ||
        oneTimeState == 'FAILED' ||
        periodicState == 'FAILED';
  }

  String _describeStatus(Map<String, dynamic> status) {
    final cleanupState = status['cleanupState']?.toString() ?? 'NONE';
    final oneTimeState = status['oneTimeState']?.toString() ?? 'NONE';
    final periodicState = status['periodicState']?.toString() ?? 'UNKNOWN';
    if (cleanupState != 'NONE' &&
        cleanupState != 'SUCCEEDED' &&
        cleanupState != 'CANCELLED') {
      return '清理任务: $cleanupState';
    }
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
      case 'UPLOADING_TASK':
        return '等待 OpenList 上传任务完成';
      case 'UPLOAD_TASK_FAILED':
        return 'OpenList 上传任务失败';
      case 'COMPLETED':
        return '已完成';
      case 'CLEANUP_PREPARING':
        return '准备清理';
      case 'CLEANUP_SCANNING':
        return '扫描可清理文件';
      case 'CLEANUP_DELETING':
        return '清理本地源文件';
      case 'CLEANUP_COMPLETED':
        return '清理完成';
      case 'CLEANUP_FAILED':
        return '清理失败';
      default:
        return '未知';
    }
  }

  Future<void> _showStatusDetails(SyncTask task, Map<String, dynamic>? status) async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('${task.name} - 运行详情'),
        content: SizedBox(
          width: 520,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildDialogRow('任务ID', task.id),
                _buildDialogRow('当前阶段', _describePhase(status?['currentPhase']?.toString())),
                _buildDialogRow('清理任务状态', status?['cleanupState']?.toString() ?? '-'),
                _buildDialogRow('当前文件', status?['currentFile']?.toString() ?? '-'),
                _buildDialogRow('OpenList上传任务ID', status?['currentUploadTaskId']?.toString() ?? '-'),
                _buildDialogRow(
                  'OpenList上传任务进度',
                  status?['currentUploadTaskProgress'] != null
                      ? '${status!['currentUploadTaskProgress']}%'
                      : '-',
                ),
                _buildDialogRow('OpenList上传任务状态', status?['currentUploadTaskStatus']?.toString() ?? '-'),
                _buildDialogRow('OpenList上传任务错误', status?['currentUploadTaskError']?.toString() ?? '-'),
                _buildDialogRow('扫描数', '${status?['scannedFiles'] ?? '-'}'),
                _buildDialogRow('待传数', '${status?['pendingFiles'] ?? '-'}'),
                _buildDialogRow('跳过数', '${status?['skippedFiles'] ?? '-'}'),
                _buildDialogRow('成功数', '${status?['uploadedFiles'] ?? '-'}'),
                _buildDialogRow('失败数', '${status?['failedFiles'] ?? '-'}'),
                _buildDialogRow('最后错误', task.lastError?.isNotEmpty == true ? task.lastError! : '-'),
              ],
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }

  Widget _buildDialogRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 132,
            child: Text(
              label,
              style: TextStyle(
                color: Theme.of(context).hintColor,
                fontSize: 13,
              ),
            ),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: const TextStyle(fontSize: 13),
            ),
          ),
        ],
      ),
    );
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
            onPressed: () async {
              await _manager.deleteTask(task.id);
              if (mounted) {
                setState(() {
                  _statusByTaskId.remove(task.id);
                });
              }
              if (ctx.mounted) {
                Navigator.pop(ctx);
              }
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('已删除任务 "${task.name}"')),
                );
              }
            },
            style: FilledButton.styleFrom(backgroundColor: Colors.red),
            child: const Text('删除'),
          ),
        ],
      ),
    );
  }

  Future<void> _confirmClearTaskHistory(SyncTask task) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清空历史记录'),
        content: Text('确定要清空任务 "${task.name}" 的全部历史记录吗？这不会删除任务配置。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('清空'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      await _manager.clearTaskHistory(task.id);
      await _refreshStatuses();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('已清空任务 "${task.name}" 的历史记录')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('清空历史失败: $e')),
        );
      }
    }
  }

  Future<void> _confirmClearAllHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清空全部历史'),
        content: const Text('确定要清空所有媒体备份任务的历史记录吗？这不会删除任务配置。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('清空全部'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;

    try {
      await _manager.clearAllHistory();
      await _refreshStatuses();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('已清空全部历史记录')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('清空全部历史失败: $e')),
        );
      }
    }
  }
}
