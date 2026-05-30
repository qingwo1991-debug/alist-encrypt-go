import 'package:flutter/material.dart';

import '../../utils/sync_task_manager.dart';

class SyncHistoryPage extends StatefulWidget {
  final String taskId;
  final String taskName;

  const SyncHistoryPage({
    super.key,
    required this.taskId,
    required this.taskName,
  });

  @override
  State<SyncHistoryPage> createState() => _SyncHistoryPageState();
}

class _SyncHistoryPageState extends State<SyncHistoryPage> {
  final SyncTaskManager _manager = SyncTaskManager();
  List<Map<String, dynamic>> _history = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  Future<void> _loadHistory() async {
    setState(() => _isLoading = true);
    final history = await _manager.getTaskHistory(widget.taskId);
    // Sort by most recent first
    history.sort((a, b) {
      final aTime = a['runAt'] as int? ?? 0;
      final bTime = b['runAt'] as int? ?? 0;
      return bTime.compareTo(aTime);
    });
    setState(() {
      _history = history;
      _isLoading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('${widget.taskName} - 同步历史'),
        actions: [
          IconButton(
            icon: const Icon(Icons.delete_sweep_outlined),
            tooltip: '清空当前任务历史',
            onPressed: _confirmClearHistory,
          ),
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadHistory,
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (_history.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.history, size: 64, color: Theme.of(context).hintColor),
            const SizedBox(height: 16),
            Text(
              '暂无同步历史',
              style: TextStyle(color: Theme.of(context).hintColor, fontSize: 16),
            ),
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _history.length,
      itemBuilder: (context, index) {
        final entry = _history[index];
        return _buildHistoryCard(entry);
      },
    );
  }

  Widget _buildHistoryCard(Map<String, dynamic> entry) {
    final runAt = entry['runAt'] as int? ?? 0;
    final totalFiles = entry['totalFiles'] as int? ?? 0;
    final pendingFiles = entry['pendingFiles'] as int? ?? totalFiles;
    final skippedFiles = entry['skippedFiles'] as int? ?? 0;
    final successCount = entry['successCount'] as int? ?? 0;
    final failureCount = entry['failureCount'] as int? ?? 0;
    final errors = (entry['errors'] as List<dynamic>?)
            ?.map((e) => e.toString())
            .toList() ??
        [];

    final runTime = DateTime.fromMillisecondsSinceEpoch(runAt);
    final hasErrors = failureCount > 0;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  hasErrors ? Icons.warning_amber : Icons.check_circle,
                  color: hasErrors ? Colors.orange : Colors.green,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '${runTime.year}-${runTime.month.toString().padLeft(2, '0')}-${runTime.day.toString().padLeft(2, '0')} '
                    '${runTime.hour.toString().padLeft(2, '0')}:${runTime.minute.toString().padLeft(2, '0')}:${runTime.second.toString().padLeft(2, '0')}',
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                _buildStatChip('总扫描', totalFiles, Colors.blue),
                _buildStatChip('待上传', pendingFiles, Colors.deepPurple),
                _buildStatChip('已跳过', skippedFiles, Colors.teal),
                _buildStatChip('成功', successCount, Colors.green),
                _buildStatChip(
                  '失败',
                  failureCount,
                  failureCount > 0 ? Colors.red : Colors.grey,
                ),
              ],
            ),
            if (errors.isNotEmpty) ...[
              const SizedBox(height: 12),
              if (errors.length <= 3)
                ...errors.map((error) => Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        error,
                        style: const TextStyle(color: Colors.red, fontSize: 12),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ))
              else ...[
                ...errors.take(3).map((error) => Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(
                        error,
                        style: const TextStyle(color: Colors.red, fontSize: 12),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    )),
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: Text(
                    '... 还有 ${errors.length - 3} 个错误',
                    style: TextStyle(
                      color: Theme.of(context).hintColor,
                      fontSize: 12,
                    ),
                  ),
                ),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildStatChip(String label, int count, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Text(
        '$label: $count',
        style: TextStyle(color: color, fontSize: 13, fontWeight: FontWeight.w500),
      ),
    );
  }

  Future<void> _confirmClearHistory() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('清空历史记录'),
        content: Text('确定要清空任务 "${widget.taskName}" 的全部历史记录吗？'),
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
      await _manager.clearTaskHistory(widget.taskId);
      await _loadHistory();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('历史记录已清空')),
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('清空历史失败: $e')),
      );
    }
  }
}
