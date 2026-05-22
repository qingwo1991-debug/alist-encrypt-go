import 'package:flutter/material.dart';
import 'package:open_filex/open_filex.dart';
import 'package:dio/dio.dart';

import '../generated/l10n.dart';
import '../utils/download_manager.dart';

/// 应用更新下载进度弹窗
class AppUpdateProgressDialog extends StatefulWidget {
  final String apkUrl;
  final String version;

  const AppUpdateProgressDialog({
    super.key,
    required this.apkUrl,
    required this.version,
  });

  @override
  State<AppUpdateProgressDialog> createState() => _AppUpdateProgressDialogState();
}

class _AppUpdateProgressDialogState extends State<AppUpdateProgressDialog> {
  double _progress = 0.0;
  int _receivedBytes = 0;
  int _totalBytes = 0;
  String? _filePath;
  String? _errorMessage;
  bool _isDownloading = true;
  bool _isCompleted = false;
  bool _isCancelled = false;
  CancelToken? _cancelToken;
  DateTime? _startTime;

  @override
  void initState() {
    super.initState();
    _startDownload();
  }

  Future<void> _startDownload() async {
    _startTime = DateTime.now();
    _cancelToken = CancelToken();

    final result = await DownloadManager.downloadWithProgressCallback(
      url: widget.apkUrl,
      filename: 'OpenList_${widget.version}.apk',
      cancelToken: _cancelToken,
      onProgress: (progress, received, total) {
        if (mounted && !_isCancelled) {
          setState(() {
            _progress = progress;
            _receivedBytes = received;
            _totalBytes = total;
          });
        }
      },
      onComplete: (filePath) {
        if (mounted && !_isCancelled) {
          setState(() {
            _isDownloading = false;
            _isCompleted = true;
            _filePath = filePath;
          });
        }
      },
      onError: (error) {
        if (mounted && !_isCancelled) {
          setState(() {
            _isDownloading = false;
            _errorMessage = error;
          });
        }
      },
    );

    if (result == null && mounted && !_isCancelled && _errorMessage == null) {
      setState(() {
        _isDownloading = false;
        _errorMessage = S.of(context).downloadFailed;
      });
    }
  }

  void _cancelDownload() {
    _isCancelled = true;
    _cancelToken?.cancel(S.of(context).userCancelledDownloadError);
    Navigator.pop(context);
  }

  Future<void> _installApk() async {
    if (_filePath != null) {
      final result = await OpenFilex.open(_filePath!);
      if (result.type == ResultType.done) {
        if (mounted) {
          Navigator.pop(context);
        }
      }
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)}GB';
  }

  String _getDownloadSpeed() {
    if (_startTime == null || _receivedBytes == 0) return '';
    final elapsed = DateTime.now().difference(_startTime!).inSeconds;
    if (elapsed == 0) return '';
    final speed = _receivedBytes / elapsed;
    return '${_formatBytes(speed.toInt())}/s';
  }

  String _getRemainingTime() {
    if (_startTime == null || _receivedBytes == 0 || _totalBytes == 0) return '';
    final elapsed = DateTime.now().difference(_startTime!).inSeconds;
    if (elapsed == 0) return '';
    final speed = _receivedBytes / elapsed;
    if (speed == 0) return '';
    final remaining = (_totalBytes - _receivedBytes) / speed;
    if (remaining < 60) {
      return '${remaining.toInt()}s';
    } else if (remaining < 3600) {
      return '${(remaining / 60).toInt()}m ${(remaining % 60).toInt()}s';
    }
    return '${(remaining / 3600).toInt()}h ${((remaining % 3600) / 60).toInt()}m';
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return AlertDialog(
      title: Row(
        children: [
          Icon(
            _isCompleted
                ? Icons.check_circle
                : _errorMessage != null
                    ? Icons.error
                    : Icons.system_update,
            color: _isCompleted
                ? Colors.green
                : _errorMessage != null
                    ? Colors.red
                    : theme.colorScheme.primary,
            size: 28,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              _isCompleted
                  ? S.of(context).downloadCompleteTitle
                  : _errorMessage != null
                      ? S.of(context).downloadFailed
                      : S.of(context).downloading,
            ),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 版本标签
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: theme.colorScheme.primaryContainer,
              borderRadius: BorderRadius.circular(20),
            ),
            child: Text(
              widget.version,
              style: TextStyle(
                fontWeight: FontWeight.bold,
                color: theme.colorScheme.onPrimaryContainer,
              ),
            ),
          ),
          const SizedBox(height: 20),

          if (_errorMessage != null) ...[
            // 错误状态
            Card(
              color: Colors.red.shade50,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    const Icon(Icons.error_outline, color: Colors.red),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        _errorMessage!,
                        style: const TextStyle(color: Colors.red),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ] else if (_isCompleted) ...[
            // 完成状态
            Card(
              color: Colors.green.shade50,
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Row(
                  children: [
                    const Icon(Icons.check_circle, color: Colors.green),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        S.of(context).apkDownloadCompleteMessage,
                        style: const TextStyle(color: Colors.green),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ] else ...[
            // 下载进度
            LinearProgressIndicator(
              value: _progress,
              backgroundColor: theme.colorScheme.surfaceContainerHighest,
              valueColor: AlwaysStoppedAnimation<Color>(theme.colorScheme.primary),
              minHeight: 8,
              borderRadius: BorderRadius.circular(4),
            ),
            const SizedBox(height: 12),

            // 进度百分比
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '${(_progress * 100).toStringAsFixed(1)}%',
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.bold,
                    color: theme.colorScheme.primary,
                  ),
                ),
                Text(
                  '${_formatBytes(_receivedBytes)} / ${_totalBytes > 0 ? _formatBytes(_totalBytes) : "..."}',
                  style: theme.textTheme.bodySmall,
                ),
              ],
            ),
            const SizedBox(height: 8),

            // 下载速度和剩余时间
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Row(
                  children: [
                    Icon(Icons.speed, size: 16, color: theme.colorScheme.secondary),
                    const SizedBox(width: 4),
                    Text(
                      _getDownloadSpeed(),
                      style: theme.textTheme.bodySmall,
                    ),
                  ],
                ),
                if (_getRemainingTime().isNotEmpty)
                  Row(
                    children: [
                      Icon(Icons.timer, size: 16, color: theme.colorScheme.secondary),
                      const SizedBox(width: 4),
                      Text(
                        _getRemainingTime(),
                        style: theme.textTheme.bodySmall,
                      ),
                    ],
                  ),
              ],
            ),
          ],
        ],
      ),
      actions: <Widget>[
        if (_errorMessage != null) ...[
          // 错误状态：重试和关闭
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(S.of(context).cancel),
          ),
          FilledButton.icon(
            onPressed: () {
              setState(() {
                _errorMessage = null;
                _isDownloading = true;
                _progress = 0.0;
                _receivedBytes = 0;
                _totalBytes = 0;
              });
              _startDownload();
            },
            icon: const Icon(Icons.refresh),
            label: Text(S.of(context).refresh),
          ),
        ] else if (_isCompleted) ...[
          // 完成状态：稍后安装和立即安装
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(S.of(context).laterInstall),
          ),
          FilledButton.icon(
            onPressed: _installApk,
            icon: const Icon(Icons.install_mobile),
            label: Text(S.of(context).installNow),
          ),
        ] else ...[
          // 下载中：取消
          TextButton(
            onPressed: _cancelDownload,
            child: Text(S.of(context).cancelDownload),
          ),
        ],
      ],
    );
  }
}
