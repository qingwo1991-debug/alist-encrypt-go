import 'dart:async';
import 'dart:io';
import 'dart:developer';

import 'package:dio/dio.dart';
import 'package:path_provider/path_provider.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:get/get.dart' as getx;
import 'package:flutter/material.dart';
import 'package:open_filex/open_filex.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'notification_manager.dart';
import 'positional_file_writer.dart';
import 'app_shell.dart';
import '../generated/l10n.dart';

/// 下载任务状态
enum DownloadStatus {
  pending,    // 等待中
  downloading, // 下载中
  completed,   // 已完成
  failed,      // 失败
  cancelled,   // 已取消
}

class _DownloadChunk {
  final int index;
  final int start;
  final int end;

  const _DownloadChunk({
    required this.index,
    required this.start,
    required this.end,
  });

  int get length => end - start + 1;
}

class _ContentRange {
  final int start;
  final int end;
  final int total;

  const _ContentRange({
    required this.start,
    required this.end,
    required this.total,
  });
}

/// 下载任务
class DownloadTask {
  final String id;
  final String url;
  final String filename;
  final String filePath;
  DownloadStatus status;
  double progress;
  int receivedBytes;
  int totalBytes;
  String? errorMessage;
  DateTime startTime;
  DateTime? endTime;
  CancelToken? cancelToken;

  DownloadTask({
    required this.id,
    required this.url,
    required this.filename,
    required this.filePath,
    this.status = DownloadStatus.pending,
    this.progress = 0.0,
    this.receivedBytes = 0,
    this.totalBytes = 0,
    this.errorMessage,
    DateTime? startTime,
    this.endTime,
    this.cancelToken,
  }) : startTime = startTime ?? DateTime.now();

  String get statusText {
    switch (status) {
      case DownloadStatus.pending:
        return S.current.pending;
      case DownloadStatus.downloading:
        return S.current.downloading;
      case DownloadStatus.completed:
        return S.current.completed;
      case DownloadStatus.failed:
        return S.current.failed;
      case DownloadStatus.cancelled:
        return S.current.cancelled;
    }
  }

  String get progressText {
    if (totalBytes > 0) {
      return '${_formatBytes(receivedBytes)} / ${_formatBytes(totalBytes)}';
    }
    return _formatBytes(receivedBytes);
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)}GB';
  }
}

class DownloadManager {
  static const String _downloadDirPrefKey = 'download_directory_path';
  static final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 10),
    receiveTimeout: const Duration(seconds: 20),
    sendTimeout: const Duration(seconds: 20),
  ));
  @visibleForTesting
  static Duration headerBudget = const Duration(seconds: 20);
  @visibleForTesting
  static Duration idleBudget = const Duration(seconds: 20);
  // At most two transfers (eight range requests) across all entry points.
  static int _runningTransfers = 0;
  // Bound pending work as well as sockets: bursts must not accumulate an
  // unlimited number of suspended transfers and their callbacks/tokens.
  static const int _maxQueuedDownloads = 32;
  static final List<Completer<void>> _transferQueue = [];

  @visibleForTesting
  static int cancellationSubscriptions = 0;
  static final Expando<StreamSubscription<DioException>> _bodyCancellation =
      Expando<StreamSubscription<DioException>>();
  static final Expando<CancelToken> _bodyAttempts = Expando<CancelToken>();

  static StreamSubscription<DioException>? _listenForCancellation(
    CancelToken? token, void Function(DioException) onCancel,
  ) {
    if (token == null) return null;
    cancellationSubscriptions++;
    return token.whenCancel.asStream().listen(onCancel);
  }

  static Future<void> _detachCancellation(
    StreamSubscription<DioException>? subscription,
  ) async {
    if (subscription == null) return;
    await subscription.cancel();
    cancellationSubscriptions--;
  }

  static Future<void> _detachBodyCancellation(ResponseBody body) async {
    final subscription = _bodyCancellation[body];
    _bodyCancellation[body] = null;
    _bodyAttempts[body] = null;
    await _detachCancellation(subscription);
  }

  static Future<void> _acquireTransfer(CancelToken? token) async {
    _throwIfCancelled(token);
    if (_runningTransfers < 2) {
      _runningTransfers++;
      return;
    }
    if (_transferQueue.length >= _maxQueuedDownloads) {
      throw StateError('Download queue is full (32 pending transfers)');
    }
    final waiter = Completer<void>();
    _transferQueue.add(waiter);
    final cancelled = Completer<bool>();
    final subscription = _listenForCancellation(token, (_) {
      if (!cancelled.isCompleted) cancelled.complete(false);
    });
    try {
      final admitted = await Future.any<bool>([
        waiter.future.then((_) => true),
        if (token != null) cancelled.future,
      ]);
      if (!admitted || token?.isCancelled == true) {
        // An admitted waiter owns a slot, even if cancellation won the race.
        if (!_transferQueue.remove(waiter)) _releaseTransfer();
        _throwIfCancelled(token);
      }
    } finally {
      await _detachCancellation(subscription);
    }
  }

  static void _releaseTransfer() {
    if (_transferQueue.isNotEmpty) {
      _transferQueue.removeAt(0).complete();
    } else {
      _runningTransfers--;
    }
  }

  // A separate attempt token bounds time to headers without cancelling the
  // caller's token: mirror fallback must remain usable after a timeout.
  static Future<Response<T>> _requestHeaders<T>(
    String url, {
    required bool head,
    required CancelToken? cancelToken,
    required Options options,
  }) async {
    _throwIfCancelled(cancelToken);
    final attempt = CancelToken();
    final subscription = _listenForCancellation(
      cancelToken, (error) => attempt.cancel(error),
    );
    var handedToBody = false;
    var timedOut = false;
    final timer = Timer(headerBudget, () {
      timedOut = true;
      attempt.cancel('download header budget exceeded');
    });
    try {
      final response = await _dio.request<T>(
        url,
        cancelToken: attempt,
        options: options.copyWith(method: head ? 'HEAD' : 'GET'),
      );
      final data = response.data;
      if (data is ResponseBody) {
        // Stream responses outlive their headers. Transfer ownership until
        // body EOF/error/cancel/discard, not merely until this request returns.
        _bodyAttempts[data] = attempt;
        if (subscription != null) {
          _bodyCancellation[data] = subscription;
          handedToBody = true;
        }
      }
      return response;
    } catch (error) {
      _throwIfCancelled(cancelToken);
      if (timedOut) throw TimeoutException('download header budget exceeded');
      rethrow;
    } finally {
      timer.cancel();
      if (!handedToBody) await _detachCancellation(subscription);
    }
  }

  @visibleForTesting
  static Dio get networkClientForTesting => _dio;

  /// Runs the same bounded transfer pipeline without UI/platform directory IO.
  @visibleForTesting
  static Future<void> downloadToPathForTesting({
    required String url,
    List<String>? urls,
    required String filePath,
    CancelToken? cancelToken,
    required void Function(int received, int total) onProgress,
  }) =>
      _downloadToPath(
        url: url,
        urls: urls,
        filePath: filePath,
        cancelToken: cancelToken,
        onProgress: onProgress,
      );

  static Future<void> _downloadToPath({
    required String url,
    List<String>? urls,
    required String filePath,
    CancelToken? cancelToken,
    required void Function(int received, int total) onProgress,
  }) async {
    await _acquireTransfer(cancelToken);
    try {
      _throwIfCancelled(cancelToken);
      final candidates = (urls != null && urls.isNotEmpty) ? urls : [url];
      final multiOk = await _downloadMultiThread(
        url: candidates.first,
        chunkUrls: candidates,
        filePath: filePath,
        cancelToken: cancelToken,
        onProgress: onProgress,
      );
      if (multiOk) return;
      Object? lastError;
      for (final candidate in candidates) {
        _throwIfCancelled(cancelToken);
        try {
          await _downloadSingle(
            candidate,
            filePath,
            cancelToken,
            onProgress,
          );
          _throwIfCancelled(cancelToken);
          return;
        } catch (error) {
          _throwIfCancelled(cancelToken);
          lastError = error;
        }
      }
      throw lastError ?? StateError('All fallback download URLs failed');
    } finally {
      _releaseTransfer();
    }
  }

  static Future<void> _downloadSingle(
    String url,
    String filePath,
    CancelToken? token,
    void Function(int received, int total) onProgress,
  ) async {
    final response = await _requestHeaders<ResponseBody>(
      url,
      head: false,
      cancelToken: token,
      options: Options(
        responseType: ResponseType.stream,
        headers: {'Accept-Encoding': 'identity'},
      ),
    );
    final body = response.data!;
    final total = int.tryParse(
      response.headers.value(Headers.contentLengthHeader) ?? '',
    ) ?? -1;
    RandomAccessFile? file;
    var reading = false;
    try {
      await File(filePath).parent.create(recursive: true);
      file = await File(filePath).open(mode: FileMode.write);
      var received = 0;
      reading = true;
      await for (final bytes in _readBody(body, token)) {
        _throwIfCancelled(token);
        await file.writeFrom(bytes);
        _throwIfCancelled(token);
        received += bytes.length;
        onProgress(received, total);
      }
      _throwIfCancelled(token);
      if (total >= 0 && received != total) {
        throw StateError('incomplete download: $received/$total');
      }
    } catch (_) {
      await file?.close();
      file = null;
      try {
        await File(filePath).delete();
      } catch (_) {}
      rethrow;
    } finally {
      if (!reading) await _discardResponseBody(body);
      await file?.close();
    }
  }

  static final Map<String, DownloadTask> _activeTasks = {};
  static final List<DownloadTask> _completedTasks = [];
  static const int _downloadThreads = 4;
  static const int _minMultiThreadSize = 10 * 1024 * 1024;

  @visibleForTesting
  static String sanitizeFilename(String? candidate) {
    var filename = (candidate ?? '').trim();
    try {
      filename = Uri.decodeComponent(filename);
    } on FormatException {
      // Keep malformed percent escapes as literal filename characters.
    }

    filename = filename.replaceAll('\\', '/');
    filename = filename.split('/').last.trim();
    filename = filename.replaceAll(RegExp(r'[\x00-\x1f\x7f]'), '_');
    if (filename.isEmpty || filename == '.' || filename == '..') {
      return 'download_${DateTime.now().millisecondsSinceEpoch}';
    }
    return filename;
  }

  /// 多源分段：从 index 开始轮转取源，让相邻段落到不同源（带宽叠加）。
  static List<String> _rotatedChunkUrls(List<String> chunkUrls, int index) {
    final result = <String>[];
    for (var i = 0; i < chunkUrls.length; i++) {
      result.add(chunkUrls[(index + i) % chunkUrls.length]);
    }
    return result;
  }

  static List<_DownloadChunk> _buildDownloadChunks(int totalBytes) {
    return List.generate(_downloadThreads, (index) {
      final start = index * (totalBytes ~/ _downloadThreads);
      final end = index == _downloadThreads - 1
          ? totalBytes - 1
          : (index + 1) * (totalBytes ~/ _downloadThreads) - 1;
      return _DownloadChunk(index: index, start: start, end: end);
    });
  }

  static _ContentRange? _parseContentRange(String? value) {
    if (value == null) return null;
    final match = RegExp(
      r'^bytes\s+(\d+)-(\d+)/(\d+)$',
      caseSensitive: false,
    ).firstMatch(value.trim());
    if (match == null) return null;
    return _ContentRange(
      start: int.parse(match.group(1)!),
      end: int.parse(match.group(2)!),
      total: int.parse(match.group(3)!),
    );
  }

  static void _throwIfCancelled(CancelToken? cancelToken) {
    final cancellation = cancelToken?.cancelError;
    if (cancellation != null) {
      throw cancellation;
    }
  }

  static Stream<List<int>> _readBody(
    ResponseBody body, CancelToken? token,
  ) async* {
    final iterator = StreamIterator(body.stream);
    Completer<bool>? pending;
    final subscription = _listenForCancellation(token, (error) {
      final waiter = pending;
      if (waiter != null && !waiter.isCompleted) waiter.completeError(error);
    });
    try {
      while (true) {
        _throwIfCancelled(token);
        final waiter = Completer<bool>();
        pending = waiter;
        iterator.moveNext().then((hasNext) {
          if (!waiter.isCompleted) waiter.complete(hasNext);
        }, onError: (Object error, StackTrace stack) {
          if (!waiter.isCompleted) waiter.completeError(error, stack);
        });
        final hasNext = await waiter.future.timeout(idleBudget);
        pending = null;
        if (!hasNext) break;
        _throwIfCancelled(token);
        yield iterator.current;
      }
    } catch (error) {
      // Dio wraps ResponseBody streams. Cancelling only the outer iterator
      // need not abort the adapter's underlying response; cancel its private
      // attempt too, while keeping the caller token usable for mirror retry.
      _bodyAttempts[body]?.cancel(error);
      rethrow;
    } finally {
      pending = null;
      _bodyAttempts[body]?.cancel('download body reader finished');
      try {
        await iterator.cancel();
      } finally {
        await _detachCancellation(subscription);
        await _detachBodyCancellation(body);
      }
    }
  }

  static Future<void> _discardResponseBody(ResponseBody? body) async {
    if (body == null) return;
    _bodyAttempts[body]?.cancel('discard download response');
    final subscription = body.stream.listen((_) {}, onError: (Object _) {});
    try {
      await subscription.cancel();
    } finally {
      await _detachBodyCancellation(body);
    }
  }

  static Future<void> _downloadChunk({
    required String url,
    List<String>? chunkUrls,
    required PositionalFileWriter writer,
    required _DownloadChunk chunk,
    required int totalBytes,
    required String? ifRange,
    required CancelToken? cancelToken,
    required void Function(int received) onReceived,
  }) async {
    _throwIfCancelled(cancelToken);
    final headers = <String, dynamic>{
      'Accept-Encoding': 'identity',
      'Range': 'bytes=${chunk.start}-${chunk.end}',
    };
    if (ifRange != null && ifRange.isNotEmpty) {
      headers['If-Range'] = ifRange;
    }

    // 多源分段：本段首选第 index%len 个源；失败时依次换下一个源重试。
    // 仅当提供多源列表时才轮换，否则始终用主 url（现状行为）。
    final candidates = (chunkUrls != null && chunkUrls.isNotEmpty)
        ? _rotatedChunkUrls(chunkUrls, chunk.index)
        : <String>[url];
    ResponseBody? responseBody;
    dynamic lastError;
    for (var i = 0; i < candidates.length; i++) {
      _throwIfCancelled(cancelToken);
      final candidate = candidates[i];
      try {
        final response = await _requestHeaders<ResponseBody>(
          candidate,
          head: false,
          cancelToken: cancelToken,
          options: Options(
            headers: headers,
            responseType: ResponseType.stream,
            followRedirects: true,
            validateStatus: (status) => status != null,
          ),
        );
        final contentRange = _parseContentRange(
          response.headers.value('content-range'),
        );
        final validRange = response.statusCode == HttpStatus.partialContent &&
            contentRange != null &&
            contentRange.start == chunk.start &&
            contentRange.end == chunk.end &&
            contentRange.total == totalBytes;
        if (validRange) {
          final declaredLength = int.tryParse(
            response.headers.value(Headers.contentLengthHeader) ?? '',
          );
          if (declaredLength != null && declaredLength != chunk.length) {
            await _discardResponseBody(response.data);
            throw StateError(
              'invalid range length for bytes=${chunk.start}-${chunk.end}',
            );
          }
          if (response.data == null) {
            await _discardResponseBody(response.data);
            throw StateError(
              'missing range body for bytes=${chunk.start}-${chunk.end}',
            );
          }
          responseBody = response.data;
          break;
        }
        // 无效范围：丢弃并试下一个源
        await _discardResponseBody(response.data);
        lastError = StateError(
          'invalid range response for bytes=${chunk.start}-${chunk.end}: '
          'status=${response.statusCode} '
          'content-range=${response.headers.value('content-range')}',
        );
      } catch (e) {
        _throwIfCancelled(cancelToken);
        lastError = e;
        log('分片 ${chunk.index} 源 $candidate 失败，重试下一个源: $e');
      }
    }
    if (responseBody == null) {
      throw lastError ??
          StateError(
            'missing range body for bytes=${chunk.start}-${chunk.end}',
          );
    }

    // The writer owns the shared cursor across the entire asynchronous
    // seek/write transaction. Awaiting each batch bounds outstanding buffers
    // to one per worker and keeps native disk IO off the UI isolate.
    var received = 0;
    await for (final bytes in _readBody(responseBody, cancelToken)) {
      _throwIfCancelled(cancelToken);
      if (received + bytes.length > chunk.length) {
        throw StateError(
          'range body exceeded expected length for '
          'bytes=${chunk.start}-${chunk.end}',
        );
      }
      await writer.writeAt(chunk.start + received, bytes);
      _throwIfCancelled(cancelToken);
      received += bytes.length;
      onReceived(received);
    }

    _throwIfCancelled(cancelToken);
    if (received != chunk.length) {
      throw StateError(
        'incomplete range body for bytes=${chunk.start}-${chunk.end}: '
        'received=$received expected=${chunk.length}',
      );
    }
  }

  /// 获取所有活跃的下载任务
  static List<DownloadTask> get activeTasks => _activeTasks.values.toList();
  
  /// 获取所有已完成的下载任务
  static List<DownloadTask> get completedTasks => _completedTasks;
  
  /// 获取所有下载任务
  static List<DownloadTask> get allTasks => [..._activeTasks.values, ..._completedTasks];

  /// 带进度条的下载（后台下载，不阻塞UI）
  static Future<bool> downloadFileWithProgress({
    required String url,
    String? filename,
  }) async {
    // 初始化通知管理器
    await NotificationManager.initialize();
    
    // 生成任务ID
    String taskId = DateTime.now().microsecondsSinceEpoch.toString();
    
    // 获取下载目录
    Directory? downloadDir = await _getOpenListDownloadDirectory();
    if (downloadDir == null) {
      showGlobalSnackBar(SnackBar(
        content: Text(S.current.cannotGetDownloadDirectory),
        duration: const Duration(seconds: 3),
      ));
      return false;
    }

    // 确定文件名和路径
    String finalFilename = sanitizeFilename(filename ?? _getFilenameFromUrl(url));
    String filePath = '${downloadDir.path}/$finalFilename';
    filePath = _reserveDownloadPath(filePath);
    finalFilename = filePath.split('/').last;

    // 创建下载任务
    CancelToken cancelToken = CancelToken();
    DownloadTask task = DownloadTask(
      id: taskId,
      url: url,
      filename: finalFilename,
      filePath: filePath,
      status: DownloadStatus.pending,
      cancelToken: cancelToken,
    );

    // 添加到活跃任务列表
    _activeTasks[taskId] = task;

    try {
      // Reservation also covers notification work before the file is opened.
      showGlobalSnackBar(SnackBar(
        content: Text(S.current.startDownloadFile(finalFilename)),
        duration: const Duration(seconds: 2),
        backgroundColor: Colors.green,
      ));
      // 更新任务状态
      task.status = DownloadStatus.downloading;
      
      // 显示初始通知
      await NotificationManager.showDownloadProgressNotification();
      
      // The common pipeline bounds tasks, headers and idle body reads.
      await _downloadToPath(
        url: url,
        filePath: filePath,
        cancelToken: cancelToken,
        onProgress: (received, total) {
          if (task.status == DownloadStatus.cancelled) return;
          task.receivedBytes = received;
          task.totalBytes = total;
          if (total > 0) {
            task.progress = received / total;
          }
          NotificationManager.showDownloadProgressNotification();
          log('下载进度(多线程): ${(task.progress * 100).toStringAsFixed(1)}%');
        },
      );

      // 下载完成
      task.status = DownloadStatus.completed;
      task.endTime = DateTime.now();
      task.progress = 1.0;

      // 移动到已完成列表
      _activeTasks.remove(taskId);
      _completedTasks.insert(0, task); // 插入到开头，最新的在前面

      // 显示单个文件完成通知
      await NotificationManager.showSingleFileCompleteNotification(task);

      // 显示完成提示
      showGlobalSnackBar(SnackBar(
        content: Text(S.current.downloadCompleteFile(finalFilename)),
        duration: const Duration(seconds: 3),
        backgroundColor: Colors.blue,
        action: SnackBarAction(label: S.current.open, onPressed: () {
            _openFile(filePath);
        }),
      ));

      log('文件下载完成: $filePath');
      return true;

    } catch (e) {
      if (e is DioException && e.type == DioExceptionType.cancel) {
        // 用户取消下载
        task.status = DownloadStatus.cancelled;
        task.endTime = DateTime.now();
        log('下载已取消: $finalFilename');
      } else {
        // 下载失败
        task.status = DownloadStatus.failed;
        task.errorMessage = e.toString();
        task.endTime = DateTime.now();
        log('下载失败: $e');
        
        showGlobalSnackBar(SnackBar(
          content: Text(S.current.downloadFailedFile(finalFilename)),
          duration: const Duration(seconds: 3),
          backgroundColor: Colors.red,
        ));
      }

      // 移动到已完成列表
      _activeTasks.remove(taskId);
      _completedTasks.insert(0, task);
      
      // 更新通知状态
      if (_activeTasks.isEmpty) {
        await NotificationManager.cancelDownloadNotification();
      } else {
        await NotificationManager.showDownloadProgressNotification();
      }
      
      return false;
    } finally {
      // The pipeline has joined disk writes before relinquishing this path.
      _reservedDownloadPaths.remove(filePath);
    }
  }

  /// 简单的后台下载（推荐使用）
  static Future<bool> downloadFileInBackground({
    required String url,
    String? filename,
  }) async {
    return await downloadFileWithProgress(
      url: url,
      filename: filename,
    );
  }

  /// 带进度回调的下载方法（用于更新弹窗等需要实时进度的场景）
  ///
  /// [urls] 可选：多源分段列表（测速后排好的最快源们）。提供时多线程分段的
  /// 不同段轮转到不同源叠加带宽；某个源失败会在段级换下一个源重试。
  /// 不提供则行为与现状一致（单源）。
  static Future<String?> downloadWithProgressCallback({
    required String url,
    List<String>? urls,
    String? filename,
    CancelToken? cancelToken,
    required Function(double progress, int received, int total) onProgress,
    required Function(String filePath) onComplete,
    required Function(String error) onError,
  }) async {
    // 获取下载目录
    Directory? downloadDir = await _getOpenListDownloadDirectory();
    if (downloadDir == null) {
      onError(S.current.cannotGetDownloadDirectory);
      return null;
    }

    // 确定文件名和路径
    String finalFilename = sanitizeFilename(filename ?? _getFilenameFromUrl(url));
    String filePath = '${downloadDir.path}/$finalFilename';
    filePath = _reserveDownloadPath(filePath);

    // 多源列表非空时以它为准（首个即首选 URL）。
    final primaryUrl =
        (urls != null && urls.isNotEmpty) ? urls.first : url;

    try {
      // 执行下载：优先多线程，失败回退单线程
      await _downloadToPath(
        url: primaryUrl,
        urls: urls,
        filePath: filePath,
        cancelToken: cancelToken,
        onProgress: (received, total) {
          double progress = 0.0;
          if (total > 0) {
            progress = received / total;
          }
          onProgress(progress, received, total);
        },
      );

      // 下载完成
      onComplete(filePath);
      log('文件下载完成: $filePath');
      return filePath;

    } catch (e) {
      if (e is DioException && e.type == DioExceptionType.cancel) {
        // 用户取消下载
        log('下载已取消: $finalFilename');
        return null;
      } else {
        // 下载失败
        log('下载失败: $e');
        onError(e.toString());
        return null;
      }
    } finally {
      _reservedDownloadPaths.remove(filePath);
    }
  }

  /// 多线程分片下载，失败返回 false 供调用方回退到单线程
  static Future<bool> _downloadMultiThread({
    required String url,
    List<String>? chunkUrls,
    required String filePath,
    CancelToken? cancelToken,
    required void Function(int received, int total) onProgress,
  }) async {
    PositionalFileWriter? writer;
    final siblings = CancelToken();
    final subscription = _listenForCancellation(
      cancelToken, (error) => siblings.cancel(error),
    );
    try {
      // HEAD 始终用首选 URL（最快源），确定 content-length/accept-ranges/etag。
      final headUrl = (chunkUrls != null && chunkUrls.isNotEmpty)
          ? chunkUrls.first
          : url;
      final headResp = await _requestHeaders<dynamic>(
        headUrl,
        head: true,
        cancelToken: cancelToken,
        options: Options(
          headers: {'Accept-Encoding': 'identity'},
          followRedirects: true,
          validateStatus: (s) => s != null && s < 400,
        ),
      );

      _throwIfCancelled(cancelToken);
      if (headResp.statusCode != HttpStatus.ok) {
        return false;
      }

      final contentLength =
          int.tryParse(headResp.headers.value('content-length') ?? '') ?? 0;
      final acceptRanges = headResp.headers.value('accept-ranges') ?? '';

      if (contentLength < _minMultiThreadSize ||
          acceptRanges.trim().toLowerCase() != 'bytes') {
        _throwIfCancelled(cancelToken);
        return false;
      }

      final chunks = _buildDownloadChunks(contentLength);
      // 直写目标文件：只打开一次写句柄（FileMode.write 会截断存量），
      // 各分片复用一个句柄、按字节偏移直接写入，不再生成本地 .parts-*。
      final targetFile = File(filePath);
      await targetFile.parent.create(recursive: true);
      writer = await PositionalFileWriter.open(
        targetFile,
        maxPendingWrites: _downloadThreads,
        checkCancelled: () => _throwIfCancelled(siblings),
      );

      String? ifRange = headResp.headers.value('etag')?.trim();
      if (ifRange == null || ifRange.isEmpty || ifRange.startsWith('W/')) {
        ifRange = null;
      }
      ifRange ??= headResp.headers.value('last-modified')?.trim();

      final receivedPerChunk = List.filled(chunks.length, 0);
      await Future.wait(chunks.map((chunk) {
        return _downloadChunk(
          url: url,
          chunkUrls: chunkUrls,
          writer: writer!,
          chunk: chunk,
          totalBytes: contentLength,
          ifRange: ifRange,
          cancelToken: siblings,
          onReceived: (received) {
            receivedPerChunk[chunk.index] = received;
            final totalReceived = receivedPerChunk.fold<int>(
              0,
              (sum, value) => sum + value,
            );
            onProgress(totalReceived, contentLength);
          },
        ).catchError((Object error, StackTrace stack) {
          // Cancel siblings immediately, but still join them before closing
          // the shared handle. Never cancel the user's fallback token.
          siblings.cancel(error);
          Error.throwWithStackTrace(error, stack);
        });
      }));

      // Future.wait 默认（eagerError=false）等所有分片完成后再抛错，
      // 因此这里关闭句柄时不会再有人写入。成功时关闭以释放资源。
      await writer.close();
      _throwIfCancelled(cancelToken);
      final writtenLength = await targetFile.length();
      if (writtenLength != contentLength) {
        throw StateError(
          'direct-write download length mismatch: '
          'file=$writtenLength expected=$contentLength',
        );
      }
      onProgress(contentLength, contentLength);
      return true;
    } catch (e) {
      // 失败或取消：先关闭句柄再清理残留的部分下载文件，避免 Windows
      // 上句柄占用导致删除失败；成功时不落盘任何临时分片。
      try {
        await writer?.close();
      } catch (_) {}
      try {
        if (await File(filePath).exists()) {
          await File(filePath).delete();
        }
      } catch (_) {}
      final cancellation = cancelToken?.cancelError;
      if (cancellation != null) {
        throw cancellation;
      }
      log('多线程下载失败，将回退到单线程: $e');
      return false;
    } finally {
      await _detachCancellation(subscription);
    }
  }

  /// 取消下载任务
  static void cancelDownload(String taskId) {
    DownloadTask? task = _activeTasks[taskId];
    if (task != null && task.cancelToken != null) {
      task.cancelToken!.cancel(S.current.userCancelledDownloadError);
    }
  }

  /// 清除已完成的下载记录
  static void clearCompletedTasks() {
    _completedTasks.clear();
  }

  /// 删除下载任务记录
  static void removeTask(String taskId) {
    _activeTasks.remove(taskId);
    _completedTasks.removeWhere((task) => task.id == taskId);
  }

  /// 获取OpenList专用下载目录
  static Future<Directory?> _getOpenListDownloadDirectory() async {
    try {
      final configuredPath = await getConfiguredDownloadDirectoryPath();
      if (configuredPath != null && configuredPath.isNotEmpty) {
        final configuredDir = Directory(configuredPath);
        if (await configuredDir.exists()) {
          return configuredDir;
        }
      }

      Directory? baseDir;
      
      if (Platform.isAndroid) {
        // Android: use app-scoped external files directory to avoid legacy
        // broad storage permissions and keep behavior compatible on Android 11+.
        baseDir = await getExternalStorageDirectory();
        if (baseDir != null) {
          baseDir = Directory('${baseDir.path}/OpenListDownloads');
        }
      } else {
        // 其他平台（如Windows、macOS、Linux）
        baseDir = await getDownloadsDirectory();
      }

      if (baseDir == null) {
        log('无法获取基础下载目录');
        return null;
      }

      // 创建OpenList专用文件夹
      Directory openListDir = Directory('${baseDir.path}/OpenList');
      
      if (!await openListDir.exists()) {
        try {
          await openListDir.create(recursive: true);
          log('创建OpenList下载目录: ${openListDir.path}');
        } catch (e) {
          log('创建OpenList目录失败: $e');
          // 如果创建失败，返回基础目录
          return baseDir;
        }
      }

      log('OpenList下载目录: ${openListDir.path}');
      return openListDir;
      
    } catch (e) {
      log('获取下载目录失败: $e');
      return null;
    }
  }

  static Future<String?> getConfiguredDownloadDirectoryPath() async {
    final prefs = await SharedPreferences.getInstance();
    final path = prefs.getString(_downloadDirPrefKey);
    if (path == null || path.trim().isEmpty) {
      return null;
    }
    return path;
  }

  static Future<void> setConfiguredDownloadDirectoryPath(String path) async {
    final prefs = await SharedPreferences.getInstance();
    final normalized = path.trim();
    if (normalized.isEmpty) {
      await prefs.remove(_downloadDirPrefKey);
      return;
    }
    await prefs.setString(_downloadDirPrefKey, normalized);
  }

  /// 从URL中提取文件名
  static String _getFilenameFromUrl(String url) {
    try {
      Uri uri = Uri.parse(url);
      String path = uri.path;
      if (path.isNotEmpty && path.contains('/')) {
        String filename = path.split('/').last;
        if (filename.isNotEmpty) {
          return sanitizeFilename(filename);
        }
      }
    } catch (e) {
      log('解析文件名失败: $e');
    }
    
    // 如果无法从URL提取文件名，使用时间戳
    return 'download_${DateTime.now().millisecondsSinceEpoch}';
  }

  static final Set<String> _reservedDownloadPaths = <String>{};

  static bool _downloadPathInUse(String path) =>
      _reservedDownloadPaths.contains(path) ||
      _activeTasks.values.any((task) => task.filePath == path) ||
      File(path).existsSync();

  // Selection and reservation contain no await: callback and notification
  // downloads cannot both claim a path before either has created its file.
  static String _reserveDownloadPath(String originalPath) {
    final path = _getUniqueFilePath(originalPath);
    _reservedDownloadPaths.add(path);
    return path;
  }

  @visibleForTesting
  static String reserveDownloadPathForTesting(String originalPath) =>
      _reserveDownloadPath(originalPath);

  @visibleForTesting
  static void releaseDownloadPathForTesting(String path) {
    _reservedDownloadPaths.remove(path);
  }

  /// 获取唯一的文件路径（避免重名）
  static String _getUniqueFilePath(String originalPath) {
    File file = File(originalPath);
    if (!_downloadPathInUse(originalPath)) {
      return originalPath;
    }

    String directory = file.parent.path;
    String nameWithoutExtension = file.path.split('/').last.split('.').first;
    String extension = file.path.contains('.') 
        ? '.${file.path.split('.').last}' 
        : '';

    int counter = 1;
    String newPath;
    do {
      newPath = '$directory/${nameWithoutExtension}_$counter$extension';
      counter++;
    } while (_downloadPathInUse(newPath));

    return newPath;
  }

  /// 检查是否为 APK 文件
  static bool _isApkFile(String filePath) {
    return filePath.toLowerCase().endsWith('.apk');
  }

  /// 检查和请求安装权限
  static Future<bool> _checkInstallPermission() async {
    if (!Platform.isAndroid) return true;
    
    try {
      // 检查是否有安装权限
      bool hasPermission = await Permission.requestInstallPackages.isGranted;
      
      if (!hasPermission) {
        // 请求安装权限
        PermissionStatus status = await Permission.requestInstallPackages.request();
        
        if (status.isGranted) {
          return true;
        } else if (status.isPermanentlyDenied) {
          // 权限被永久拒绝，引导用户到设置页面
          getx.Get.dialog(
            AlertDialog(
              title: Text(S.current.needInstallPermission),
              content: Text(S.current.needInstallPermissionDesc),
              actions: [
                TextButton(
                  onPressed: () => getx.Get.back(),
                  child: Text(S.current.cancel),
                ),
                TextButton(
                  onPressed: () {
                    getx.Get.back();
                    openAppSettings();
                  },
                  child: Text(S.current.goToSettings),
                ),
              ],
            ),
          );
          return false;
        } else {
          showGlobalSnackBar(SnackBar(
            content: Text(S.current.needInstallPermissionToInstallApk),
            duration: const Duration(seconds: 3),
          ));
          return false;
        }
      }
      
      return true;
    } catch (e) {
      log('检查安装权限失败: $e');
      return true; // 如果检查失败，继续尝试打开
    }
  }

  /// 尝试打开文件
  static Future<void> _openFile(String filePath) async {
    try {
      log('尝试打开文件: $filePath');
      
      // 如果是 APK 文件，先检查安装权限
      if (_isApkFile(filePath)) {
        bool hasPermission = await _checkInstallPermission();
        if (!hasPermission) {
          return; // 没有权限，不继续打开
        }
      }
      
      // 使用 open_filex 插件打开文件
      final result = await OpenFilex.open(filePath);
      
      log('打开文件结果: ${result.type} - ${result.message}');
      
      // 根据结果显示相应的提示
      switch (result.type) {
        case ResultType.done:
          // 文件成功打开，不需要额外提示
          break;
        case ResultType.noAppToOpen:
          if (_isApkFile(filePath)) {
            showGlobalSnackBar(SnackBar(
              content: Text(S.current.cannotInstallApkNeedPermission),
              duration: const Duration(seconds: 5),
              action: SnackBarAction(label: S.current.goToSettings, onPressed: () {
                  openAppSettings();
              }),
            ));
          } else {
            showGlobalSnackBar(SnackBar(
              content: Text(S.current.noAppToOpenFile),
              duration: const Duration(seconds: 3),
              action: SnackBarAction(label: S.current.viewLocation, onPressed: () {
                  _showFileLocation(filePath);
              }),
            ));
          }
          break;
        case ResultType.fileNotFound:
          showGlobalSnackBar(SnackBar(
            content: Text(S.current.fileNotFound),
            duration: const Duration(seconds: 3),
          ));
          break;
        case ResultType.permissionDenied:
          if (_isApkFile(filePath)) {
            showGlobalSnackBar(SnackBar(
              content: Text(S.current.noPermissionToInstallApkFile),
              duration: const Duration(seconds: 5),
              action: SnackBarAction(label: S.current.goToSettings, onPressed: () {
                  openAppSettings();
              }),
            ));
          } else {
            showGlobalSnackBar(SnackBar(
              content: Text(S.current.noPermissionToOpenFile),
              duration: const Duration(seconds: 3),
            ));
          }
          break;
        case ResultType.error:
          showGlobalSnackBar(SnackBar(
            content: Text(S.current.openFileFailed(result.message)),
            duration: const Duration(seconds: 3),
            action: SnackBarAction(label: S.current.viewLocation, onPressed: () {
                _showFileLocation(filePath);
            }),
          ));
          break;
      }
    } catch (e) {
      log('打开文件异常: $e');
      showGlobalSnackBar(SnackBar(
        content: Text(S.current.openFileException(e.toString())),
        duration: const Duration(seconds: 3),
        action: SnackBarAction(label: S.current.viewLocation, onPressed: () {
            _showFileLocation(filePath);
        }),
      ));
    }
  }

  /// 显示文件位置信息
  static void _showFileLocation(String filePath) {
    getx.Get.dialog(
      AlertDialog(
        title: Text(S.current.fileLocation),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(S.current.fileSavedTo),
            const SizedBox(height: 8),
            SelectableText(
              filePath,
              style: const TextStyle(fontSize: 12),
            ),
            const SizedBox(height: 16),
            Text(
              S.current.fileLocationTip,
              style: const TextStyle(fontSize: 14, color: Colors.grey),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => getx.Get.back(),
            child: Text(S.current.ok),
          ),
        ],
      ),
    );
  }

  /// 获取OpenList下载目录路径（公共方法）
  static Future<String?> getDownloadDirectoryPath() async {
    Directory? dir = await _getOpenListDownloadDirectory();
    return dir?.path;
  }

  /// 列出已下载的文件
  static Future<List<FileSystemEntity>> getDownloadedFiles() async {
    try {
      Directory? downloadDir = await _getOpenListDownloadDirectory();
      if (downloadDir != null && await downloadDir.exists()) {
        return downloadDir.listSync();
      }
    } catch (e) {
      log('获取下载文件列表失败: $e');
    }
    return [];
  }

  /// 清理下载目录
  static Future<bool> clearDownloadDirectory() async {
    try {
      Directory? downloadDir = await _getOpenListDownloadDirectory();
      if (downloadDir != null && await downloadDir.exists()) {
        for (final entity in downloadDir.listSync()) {
          await entity.delete(recursive: true);
        }
        log('已清理下载目录');
        return true;
      }
    } catch (e) {
      log('清理下载目录失败: $e');
    }
    return false;
  }

  /// 删除指定文件
  static Future<bool> deleteFile(String filename) async {
    try {
      final safeFilename = sanitizeFilename(filename);
      if (safeFilename != filename) {
        log('拒绝删除下载目录外的文件名');
        return false;
      }
      Directory? downloadDir = await _getOpenListDownloadDirectory();
      if (downloadDir != null) {
        File file = File('${downloadDir.path}/$safeFilename');
        if (await file.exists()) {
          await file.delete();
          log('已删除文件: $filename');
          return true;
        }
      }
    } catch (e) {
      log('删除文件失败: $e');
    }
    return false;
  }
}

/// 下载控制器（保持向后兼容）
class DownloadController extends getx.GetxController {
  double _progress = 0.0;
  String _statusText = S.current.preparingDownloadStatus;
  bool _isCancelled = false;

  double get progress => _progress;
  String get statusText => _statusText;
  bool get isCancelled => _isCancelled;

  void updateProgress(double progress, int received, int total) {
    if (_isCancelled) return;
    
    _progress = progress;
    _statusText = '${_formatBytes(received)} / ${_formatBytes(total)}';
    update();
  }

  void cancelDownload() {
    _isCancelled = true;
    _statusText = S.current.downloadCancelledText;
    update();
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)}GB';
  }
}
