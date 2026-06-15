package com.openlist.mobile.sync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.media.MediaScannerConnection
import android.os.Build
import android.os.Environment
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.*
import com.openlist.mobile.constant.LogLevel
import com.openlist.mobile.R
import com.openlist.mobile.config.AppConfig
import com.openlist.mobile.model.openlist.Logger
import com.openlist.mobile.model.openlist.OpenList
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import openlistlib.Openlistlib
import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.text.SimpleDateFormat
import java.util.Locale

/**
 * WorkManager Worker：执行单个同步任务
 *
 * 流程：
 * 1. 读取任务配置
 * 2. 校验存储权限
 * 3. 校验加密代理服务存活（使用当前配置端口，默认 5344）
 * 4. 扫描源目录（递归）
 * 5. 过滤扩展名 + 排除目录
 * 6. 对比本地同步记录（增量判断：filePath + fileSize + lastModified）
 * 7. 逐个上传至本机加密代理
 * 8. 成功则写入同步记录
 * 9. 汇总成功/失败数并写入历史
 * 10. 如启用 deleteAfterSync，删除已成功上传的源文件
 */
class SyncWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    private var foregroundTitle: String = "媒体加密备份"

    companion object {
        const val TAG = "SyncWorker"
        const val KEY_TASK_ID = "task_id"
        const val KEY_TASK_JSON = "task_json"
        const val DEFAULT_ALIST_BASE_URL = "http://127.0.0.1:5244"
        const val DEFAULT_PROXY_PORT = 5344L
        private val logDateFormatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())
        private const val TASK_POLL_INTERVAL_MS = 3000L
        private const val V2_HEADER_SIZE = 32L
        private const val FOREGROUND_CHANNEL_ID = "media_backup_sync"
        private const val FOREGROUND_NOTIFICATION_ID = 53440
    }

    private data class UploadTaskSubmission(
        val taskId: String,
        val progress: Double,
        val status: String,
    )

    private data class UploadTaskSnapshot(
        val id: String,
        val state: Int,
        val progress: Double,
        val status: String,
        val error: String,
    )

    private data class RemoteFileProbe(
        val exists: Boolean,
        val size: Long?,
        val isDir: Boolean,
        val message: String,
    )

    private data class ScanProgressState(
        var visitedDirectories: Int = 0,
        var matchedFiles: Int = 0,
        var lastPublishedFiles: Int = -1,
        var lastDetail: String = "",
    ) {
        fun heuristicProgress(): Int {
            val ticks = visitedDirectories + matchedFiles
            if (ticks <= 0) return 0
            return ((ticks.toDouble() / (ticks.toDouble() + 24.0)) * 95.0)
                .toInt()
                .coerceIn(1, 95)
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val taskId = inputData.getString(KEY_TASK_ID) ?: return@withContext Result.failure()
        val taskJson = inputData.getString(KEY_TASK_JSON) ?: return@withContext Result.failure()
        val context = applicationContext
        val traceId = buildTraceId(taskId)

        val taskConfig: SyncTaskConfig
        try {
            taskConfig = SyncTaskConfig.fromJsonString(taskJson)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse task config for $taskId", e)
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("任务配置解析失败: ${e.message ?: "unknown error"}"))
            return@withContext Result.failure()
        }

        SyncRecordStore.clearLogs(context, taskId)
        foregroundTitle = taskConfig.name
        updateForegroundNotification(
            title = taskConfig.name,
            detail = "准备执行媒体加密备份",
            progress = 0,
            indeterminate = true,
        )
        publishProgress(phase = "PREPARING")
        logSync(traceId, taskId, "prepare", "任务开始 name=${taskConfig.name}")

        // 1. 校验存储权限
        if (!hasStorageAccess()) {
            Log.w(TAG, "No storage access for task $taskId")
            logSync(traceId, taskId, "prepare", "缺少本地存储访问权限", LogLevel.ERROR)
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("缺少本地存储访问权限"))
            return@withContext Result.failure()
        }

        // 2. 校验本地 OpenList / 加密代理服务存活
        ensureRuntimeReady()
        if (!isProxyAlive()) {
            Log.w(TAG, "Encrypt proxy not alive for task $taskId")
            logSync(traceId, taskId, "prepare", "加密代理服务不可用", LogLevel.ERROR)
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("加密代理服务不可用"))
            return@withContext Result.failure()
        }
        if (!isAlistAlive()) {
            Log.w(TAG, "OpenList not alive for task $taskId")
            logSync(traceId, taskId, "prepare", "OpenList 服务(${currentOpenListPort()})不可用", LogLevel.ERROR)
            recordHistory(
                context,
                taskId,
                0,
                0,
                0,
                0,
                1,
                listOf("OpenList 服务(${currentOpenListPort()})不可用")
            )
            return@withContext Result.failure()
        }

        // 2.1. 强制要求目标路径在已启用加密路径内，避免明文上传后误删本地文件
        if (!isEncryptedTargetPath(taskConfig.targetPath)) {
            Log.w(TAG, "Target path is not covered by enabled encrypt paths: ${taskConfig.targetPath}")
            logSync(traceId, taskId, "prepare", "目标路径未配置为加密路径: ${taskConfig.targetPath}", LogLevel.ERROR)
            recordHistory(
                context,
                taskId,
                0,
                0,
                0,
                0,
                1,
                listOf("目标路径未配置为加密路径，已阻止上传：${taskConfig.targetPath}")
            )
            return@withContext Result.failure()
        }

        // 2.5. 获取认证 token。媒体加密备份依赖 OpenList 管理认证，不再回退匿名上传。
        val authToken = SyncScheduler.acquireAuthToken()
        if (authToken.isNullOrEmpty()) {
            logSync(traceId, taskId, "auth", "未获取到管理认证 token，任务终止", LogLevel.ERROR)
            return@withContext Result.failure(
                workDataOf(
                    "taskId" to taskId,
                    "error" to "未取得管理认证 token，请先在 OpenList 页面校验当前管理员密码",
                ),
            )
        }
        logSync(traceId, taskId, "auth", "已获取管理认证 token")

        // 3. 扫描源目录
        val sourceDir = File(taskConfig.sourcePath)
        if (!sourceDir.exists() || !sourceDir.isDirectory) {
            Log.w(TAG, "Source directory does not exist: ${taskConfig.sourcePath}")
            recordHistory(context, taskId, 0, 0, 0, 0, 1,
                listOf("Source directory does not exist: ${taskConfig.sourcePath}"))
            return@withContext Result.failure()
        }

        // 4. 收集要上传的文件
        val filesToUpload = mutableListOf<File>()
        val excludeNames = taskConfig.excludeFolders.map { it.trimEnd('/') }.toSet()
        val scanState = ScanProgressState()
        publishProgress(
            phase = "SCANNING",
            currentPhaseProgress = 0,
            currentPhaseDetail = "正在扫描本地目录",
            currentFile = taskConfig.sourcePath,
            scannedFiles = 0,
        )
        updateForegroundNotification(
            title = taskConfig.name,
            detail = "扫描本地目录",
            progress = 0,
            indeterminate = true,
        )
        collectFiles(
            dir = sourceDir,
            extensions = taskConfig.fileExtensions,
            excludeFolders = excludeNames,
            result = filesToUpload,
            scanState = scanState,
        )
        logSync(traceId, taskId, "scan", "扫描完成 total=${filesToUpload.size} source=${taskConfig.sourcePath}")
        publishProgress(
            phase = "SCANNING",
            currentPhaseProgress = 100,
            currentPhaseDetail = "本地扫描完成，共 ${filesToUpload.size} 个文件",
            scannedFiles = filesToUpload.size,
        )
        updateForegroundNotification(
            title = taskConfig.name,
            detail = "本地扫描完成，共 ${filesToUpload.size} 个文件",
            progress = 100,
            indeterminate = false,
        )

        if (filesToUpload.isEmpty()) {
            Log.d(TAG, "No files to upload for task $taskId")
            recordHistory(context, taskId, 0, 0, 0, 0, 0, emptyList())
            return@withContext Result.success()
        }

        // 5. 过滤已同步文件（增量判断 + 远端兜底校验）
        val newOrModified = mutableListOf<File>()
        var skippedByLocalRecord = 0
        var skippedByRemotePresence = 0
        val cleanupCandidates = linkedSetOf<String>()

        filesToUpload.forEachIndexed { index, file ->
            val checked = index + 1
            if (checked == 1 || checked % 25 == 0 || checked == filesToUpload.size) {
                val filterProgress = ((checked.toDouble() / filesToUpload.size.toDouble()) * 100.0)
                    .toInt()
                    .coerceIn(0, 100)
                publishProgress(
                    phase = "FILTERING_REMOTE",
                    currentPhaseProgress = filterProgress,
                    currentPhaseDetail = "正在校验远端已存在文件 $checked/${filesToUpload.size}",
                    currentFile = file.name,
                    scannedFiles = filesToUpload.size,
                    pendingFiles = newOrModified.size,
                    skippedFiles = skippedByLocalRecord + skippedByRemotePresence,
                )
                updateForegroundNotification(
                    title = taskConfig.name,
                    detail = "校验远端文件 $checked/${filesToUpload.size}",
                    progress = filterProgress,
                    indeterminate = false,
                )
            }
            val remotePath = buildRemotePath(taskConfig, sourceDir, file)
            val alreadySyncedLocally = SyncRecordStore.isAlreadySynced(
                context,
                taskId,
                file.absolutePath,
                file.length(),
                file.lastModified(),
                remotePath
            )

            val remoteProbe = probeRemoteFile(remotePath, authToken)
            val localSize = file.length()
            val sizeMatchesRemote = remoteProbe.size != null &&
                (remoteProbe.size == localSize || remoteProbe.size == localSize + V2_HEADER_SIZE)
            if (remoteProbe.exists && !remoteProbe.isDir && sizeMatchesRemote) {
                if (!alreadySyncedLocally) {
                    SyncRecordStore.markSynced(
                        context,
                        SyncRecord(
                            taskId = taskId,
                            filePath = file.absolutePath,
                            fileSize = file.length(),
                            lastModified = file.lastModified(),
                            syncedAt = System.currentTimeMillis(),
                            remotePath = remotePath
                        )
                    )
                    skippedByRemotePresence++
                    logSync(
                        traceId,
                        taskId,
                        "scan",
                        "远端已存在同尺寸文件，补记同步记录 remotePath=$remotePath file=${file.name} size=${file.length()}",
                    )
                } else {
                    skippedByLocalRecord++
                }
                if (taskConfig.deleteAfterSync) {
                    cleanupCandidates.add(file.absolutePath)
                }
                return@forEachIndexed
            }

            if (alreadySyncedLocally) {
                logSync(
                    traceId,
                    taskId,
                    "scan",
                    "本地同步记录已存在但远端缺失或尺寸不匹配，重新上传 remotePath=$remotePath file=${file.name} probe=${remoteProbe.message}",
                    LogLevel.WARN,
                )
            }

            if (remoteProbe.exists && !remoteProbe.isDir && remoteProbe.size != null &&
                remoteProbe.size != localSize && remoteProbe.size != localSize + V2_HEADER_SIZE) {
                logSync(
                    traceId,
                    taskId,
                    "scan",
                    "远端存在同路径但尺寸不同，继续上传 remotePath=$remotePath localSize=${file.length()} remoteSize=${remoteProbe.size}",
                    LogLevel.WARN,
                )
            }

            newOrModified.add(file)
        }
        val skippedCount = skippedByLocalRecord + skippedByRemotePresence
        logSync(
            traceId,
            taskId,
            "scan",
            "增量筛选完成 total=${filesToUpload.size} pending=${newOrModified.size} skipped=$skippedCount localRecord=$skippedByLocalRecord remoteExists=$skippedByRemotePresence",
        )
        publishProgress(
            phase = "READY",
            currentPhaseProgress = 100,
            currentPhaseDetail = "增量筛选完成，待上传 ${newOrModified.size} 个文件",
            scannedFiles = filesToUpload.size,
            pendingFiles = newOrModified.size,
            skippedFiles = skippedCount,
        )

        if (newOrModified.isEmpty()) {
            Log.d(TAG, "No new or modified files to upload for task $taskId")
        }

        // 6. 逐个上传
        var successCount = 0
        var failureCount = 0
        val errors = mutableListOf<String>()
        val uploadSucceededFiles = mutableListOf<File>()

        for (file in newOrModified) {
            try {
                val remotePath = buildRemotePath(taskConfig, sourceDir, file)
                publishProgress(
                    phase = "UPLOADING",
                    currentPhaseDetail = "正在上传文件",
                    currentFile = file.name,
                    currentUploadTaskId = null,
                    currentUploadTaskProgress = null,
                    currentUploadTaskStatus = null,
                    currentUploadTaskError = null,
                    scannedFiles = filesToUpload.size,
                    pendingFiles = newOrModified.size,
                    skippedFiles = skippedCount,
                    uploadedFiles = successCount,
                    failedFiles = failureCount,
                )
                updateForegroundNotification(
                    title = taskConfig.name,
                    detail = "上传 ${successCount + failureCount + 1}/${newOrModified.size}: ${file.name}",
                    progress = if (newOrModified.isEmpty()) 0 else ((successCount + failureCount).toDouble() / newOrModified.size.toDouble() * 100.0).toInt().coerceIn(0, 99),
                    indeterminate = false,
                )
                val progressBefore = buildProgressPercent(successCount, failureCount, newOrModified.size)
                logSync(
                    traceId,
                    taskId,
                    "upload",
                    "上传开始 progress=$progressBefore remotePath=$remotePath file=${file.name} size=${file.length()}",
                )
                uploadFileAsTask(
                    file = file,
                    remotePath = remotePath,
                    authToken = authToken,
                    traceId = traceId,
                    taskId = taskId,
                    successCount = successCount,
                    failureCount = failureCount,
                    totalPending = newOrModified.size,
                    displayPath = remotePath,
                    uploadSpeedLimitKbps = taskConfig.uploadSpeedLimitKbps,
                )

                // 记录同步成功
                SyncRecordStore.markSynced(
                    context,
                    SyncRecord(
                        taskId = taskId,
                        filePath = file.absolutePath,
                        fileSize = file.length(),
                        lastModified = file.lastModified(),
                        syncedAt = System.currentTimeMillis(),
                        remotePath = remotePath
                    )
                )
                uploadSucceededFiles.add(file)
                successCount++
                val progressAfter = buildProgressPercent(successCount, failureCount, newOrModified.size)
                logSync(traceId, taskId, "upload", "上传成功 progress=$progressAfter remotePath=$remotePath file=${file.name}")
                publishProgress(
                    phase = "UPLOADING",
                    currentPhaseDetail = "正在上传文件",
                    currentFile = file.name,
                    currentUploadTaskId = null,
                    currentUploadTaskProgress = null,
                    currentUploadTaskStatus = null,
                    currentUploadTaskError = null,
                    scannedFiles = filesToUpload.size,
                    pendingFiles = newOrModified.size,
                    skippedFiles = skippedCount,
                    uploadedFiles = successCount,
                    failedFiles = failureCount,
                )
                Log.d(TAG, "Uploaded: ${file.absolutePath} -> $remotePath")
            } catch (e: Exception) {
                failureCount++
                val errorMsg = "${file.name}: ${e.message}"
                errors.add(errorMsg)
                val progressAfter = buildProgressPercent(successCount, failureCount, newOrModified.size)
                logSync(traceId, taskId, "upload", "上传失败 progress=$progressAfter file=${file.name} error=${e.message}", LogLevel.ERROR)
                publishProgress(
                    phase = "UPLOADING",
                    currentFile = file.name,
                    currentUploadTaskId = null,
                    currentUploadTaskProgress = null,
                    currentUploadTaskStatus = null,
                    currentUploadTaskError = e.message,
                    scannedFiles = filesToUpload.size,
                    pendingFiles = newOrModified.size,
                    skippedFiles = skippedCount,
                    uploadedFiles = successCount,
                    failedFiles = failureCount,
                )
                Log.e(TAG, "Failed to upload ${file.absolutePath}: ${e.message}", e)
                // 单文件失败不终止整个任务
            }
        }

        // 7. 如启用 deleteAfterSync，删除已确认在云端存在的文件
        var cleanupFailureCount = 0
        val cleanupErrors = mutableListOf<String>()
        if (taskConfig.deleteAfterSync) {
            uploadSucceededFiles.forEach { file -> cleanupCandidates.add(file.absolutePath) }
            val cleanupList = cleanupCandidates.toList()
            for ((index, filePath) in cleanupList.withIndex()) {
                val file = File(filePath)
                val cleanupProgress = if (cleanupList.isEmpty()) 100 else {
                    (((index + 1).toDouble() / cleanupList.size.toDouble()) * 100.0).toInt().coerceIn(0, 100)
                }
                try {
                    if (!file.exists()) {
                        continue
                    }
                    publishProgress(
                        phase = "CLEANUP_DELETING",
                        currentPhaseProgress = cleanupProgress,
                        currentPhaseDetail = "正在清理本地源文件 ${index + 1}/${cleanupList.size}",
                        currentFile = file.name,
                        scannedFiles = filesToUpload.size,
                        pendingFiles = newOrModified.size,
                        skippedFiles = skippedCount,
                        uploadedFiles = successCount,
                        failedFiles = failureCount + cleanupFailureCount,
                    )
                    updateForegroundNotification(
                        title = taskConfig.name,
                        detail = "清理本地源文件 ${index + 1}/${cleanupList.size}",
                        progress = cleanupProgress,
                        indeterminate = false,
                    )
                    val deleted = file.delete()
                    if (deleted || !file.exists()) {
                        notifyMediaLibraryChanged(file)
                        pruneEmptyDirectories(file.parentFile, sourceDir)
                        logSync(traceId, taskId, "cleanup", "已删除本地源文件 file=${file.absolutePath}")
                        Log.d(TAG, "Deleted synced file: ${file.absolutePath}")
                    } else {
                        cleanupFailureCount++
                        val cleanupError = "删除本地源文件失败 file=${file.absolutePath}: delete() returned false"
                        cleanupErrors.add(cleanupError)
                        logSync(traceId, taskId, "cleanup", cleanupError, LogLevel.WARN)
                        Log.w(TAG, cleanupError)
                    }
                } catch (e: Exception) {
                    cleanupFailureCount++
                    val cleanupError = "删除本地源文件失败 file=${file.absolutePath} error=${e.message}"
                    cleanupErrors.add(cleanupError)
                    logSync(traceId, taskId, "cleanup", cleanupError, LogLevel.WARN)
                    Log.e(TAG, "Failed to delete ${file.absolutePath}: ${e.message}")
                }
            }
        }

        val totalFailureCount = failureCount + cleanupFailureCount

        // 8. 写入历史
        recordHistory(
            context,
            taskId,
            filesToUpload.size,
            newOrModified.size,
            skippedCount,
            successCount,
            totalFailureCount,
            errors + cleanupErrors
        )

        // 9. Worker 返回 success/failure 取决于是否完成主流程（不论单文件失败）
        publishProgress(
            phase = "COMPLETED",
            currentPhaseProgress = 100,
            currentPhaseDetail = "任务执行完成",
            scannedFiles = filesToUpload.size,
            pendingFiles = newOrModified.size,
            skippedFiles = skippedCount,
            uploadedFiles = successCount,
            failedFiles = totalFailureCount,
        )
        updateForegroundNotification(
            title = taskConfig.name,
            detail = if (totalFailureCount > 0) "任务完成，存在失败项" else "任务完成",
            progress = 100,
            indeterminate = false,
        )
        logSync(
            traceId,
            taskId,
            "complete",
            "任务完成 total=${filesToUpload.size} pending=${newOrModified.size} skipped=$skippedCount success=$successCount uploadFailure=$failureCount cleanupFailure=$cleanupFailureCount progress=100%",
            if (totalFailureCount > 0) LogLevel.WARN else LogLevel.INFO,
        )
        if (totalFailureCount > 0) {
            Result.success() // 主流程完成，单文件失败不影响
        } else {
            Result.success()
        }
    }

    private fun hasStorageAccess(): Boolean {
        return if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            applicationContext.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        }
    }

    private fun isProxyAlive(): Boolean {
        return isServiceAlive("${proxyBaseUrl()}/ping")
    }

    private fun isAlistAlive(): Boolean {
        val port = try {
            OpenList.getHttpPort()
        } catch (_: Exception) {
            5244
        }
        return isServiceAlive("http://127.0.0.1:$port/ping") ||
            isServiceAlive("$DEFAULT_ALIST_BASE_URL/ping")
    }

    private fun isServiceAlive(url: String): Boolean {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = 2000
            conn.readTimeout = 2000
            conn.requestMethod = "GET"
            val code = conn.responseCode
            conn.disconnect()
            code in 200..499
        } catch (_: Exception) {
            false
        }
    }

    private suspend fun collectFiles(
        dir: File,
        extensions: List<String>,
        excludeFolders: Set<String>,
        result: MutableList<File>,
        scanState: ScanProgressState,
        sourceRoot: File? = null,
        currentRelative: String = ""
    ) {
        val root = sourceRoot ?: dir
        scanState.visitedDirectories++
        publishScanProgress(scanState, currentRelative.ifEmpty { root.absolutePath }, result.size)
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (file.isDirectory) {
                val relPath = if (currentRelative.isEmpty()) file.name
                              else "$currentRelative/${file.name}"
                // 排除匹配：按目录名匹配，也按相对路径匹配
                val shouldExclude = excludeFolders.contains(file.name) ||
                    excludeFolders.contains(relPath) ||
                    excludeFolders.any { relPath.startsWith(it.trimEnd('/') + "/") || relPath == it.trimEnd('/') }
                if (shouldExclude) {
                    Log.d(TAG, "Excluding directory: $relPath")
                    continue
                }
                collectFiles(file, extensions, excludeFolders, result, scanState, root, relPath)
            } else if (file.isFile) {
                if (shouldInclude(file, extensions)) {
                    result.add(file)
                    scanState.matchedFiles++
                    if (result.size % 25 == 0) {
                        publishScanProgress(scanState, currentRelative.ifEmpty { dir.name }, result.size)
                    }
                }
            }
        }
    }

    private fun shouldInclude(file: File, extensions: List<String>): Boolean {
        // 空列表表示包含所有文件
        if (extensions.isEmpty()) return true
        val fileName = file.name.lowercase()
        return extensions.any { ext ->
            fileName.endsWith(ext.lowercase())
        }
    }

    private fun buildRemotePath(
        config: SyncTaskConfig,
        sourceDir: File,
        file: File
    ): String {
        val targetPath = normalizeOpenListPath(config.targetPath)
        return if (config.preserveFolderStructure) {
            val relativePath = file.absolutePath
                .removePrefix(sourceDir.absolutePath)
                .trimStart('/')
            "$targetPath/$relativePath"
        } else {
            "$targetPath/${file.name}"
        }
    }

    private suspend fun uploadFileAsTask(
        file: File,
        remotePath: String,
        authToken: String,
        traceId: String,
        taskId: String,
        successCount: Int,
        failureCount: Int,
        totalPending: Int,
        displayPath: String,
        uploadSpeedLimitKbps: Int = 0,
    ) {
        val submission = submitUploadTask(file, remotePath, authToken, uploadSpeedLimitKbps)
        logSync(
            traceId,
            taskId,
            "upload",
            "上传任务已提交 progress=${buildProgressPercent(successCount, failureCount, totalPending)} remotePath=$displayPath uploadTaskId=${submission.taskId} taskProgress=${submission.progress.toInt()}% status=${submission.status}",
        )
        publishProgress(
            phase = "UPLOADING_TASK",
            currentFile = file.name,
            currentUploadTaskId = submission.taskId,
            currentUploadTaskProgress = submission.progress.toInt().coerceIn(0, 100),
            currentUploadTaskStatus = submission.status,
            currentUploadTaskError = null,
            pendingFiles = totalPending,
            uploadedFiles = successCount,
            failedFiles = failureCount,
        )
        waitForUploadTaskComplete(
            uploadTaskId = submission.taskId,
            file = file,
            remotePath = remotePath,
            authToken = authToken,
            traceId = traceId,
            taskId = taskId,
            successCount = successCount,
            failureCount = failureCount,
            totalPending = totalPending,
            displayPath = displayPath,
        )
    }

    private fun submitUploadTask(
        file: File,
        remotePath: String,
        authToken: String,
        uploadSpeedLimitKbps: Int = 0,
    ): UploadTaskSubmission {
        val url = URL("${proxyBaseUrl()}/api/fs/put")
        val conn = url.openConnection() as HttpURLConnection
        try {
            val speedInfo = if (uploadSpeedLimitKbps > 0) " speedLimit=${uploadSpeedLimitKbps}KB/s" else ""
            appLog(LogLevel.INFO, "媒体备份上传开始：remotePath=$remotePath local=${file.name} size=${file.length()}$speedInfo")
            conn.requestMethod = "PUT"
            conn.doOutput = true
            conn.connectTimeout = 60000
            conn.readTimeout = 3600000 // 60 min for large files
            conn.setFixedLengthStreamingMode(file.length())
            val encodedPath = android.net.Uri.encode(remotePath)
            conn.setRequestProperty("File-Path", encodedPath)
            conn.setRequestProperty("Content-Length", file.length().toString())
            conn.setRequestProperty("As-Task", "true")
            conn.setRequestProperty("Connection", "close")
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.setRequestProperty("Authorization", authToken)

            // Write file body with optional rate limiting
            FileInputStream(file).use { input ->
                conn.outputStream.use { output ->
                    if (uploadSpeedLimitKbps > 0) {
                        val bufferSize = 64 * 1024
                        val bytesPerSecond = uploadSpeedLimitKbps * 1024L
                        val buffer = ByteArray(bufferSize)
                        var totalWritten = 0L
                        val startTime = System.nanoTime()
                        var read: Int
                        while (input.read(buffer).also { read = it } != -1) {
                            output.write(buffer, 0, read)
                            totalWritten += read
                            val elapsed = (System.nanoTime() - startTime).toDouble() / 1_000_000_000.0
                            if (elapsed > 0) {
                                val expectedTime = totalWritten.toDouble() / bytesPerSecond
                                val sleepMs = ((expectedTime - elapsed) * 1000).toLong()
                                if (sleepMs > 5) {
                                    Thread.sleep(sleepMs.coerceAtMost(500))
                                }
                            }
                        }
                        output.flush()
                    } else {
                        input.copyTo(output, 8192)
                    }
                }
            }

            val responseCode = conn.responseCode
            val responseBody = try {
                if (responseCode in 200..299) {
                    conn.inputStream?.bufferedReader()?.readText().orEmpty()
                } else {
                    conn.errorStream?.bufferedReader()?.readText().orEmpty()
                }
            } catch (_: Exception) {
                ""
            }

            if (responseCode >= 400) {
                appLog(
                    LogLevel.WARN,
                    "媒体备份上传失败：remotePath=$remotePath http=$responseCode body=${compactBody(responseBody)}"
                )
                throw Exception("HTTP $responseCode: $responseBody")
            }

            val json = try {
                if (responseBody.isBlank()) {
                    null
                } else {
                    JSONObject(responseBody)
                }
            } catch (_: Exception) {
                null
            }
            val apiCode = json?.optInt("code", -1) ?: -1
            val message = json?.optString("message").orEmpty()
            if (apiCode != 200) {
                appLog(
                    LogLevel.WARN,
                    "媒体备份上传失败：remotePath=$remotePath http=$responseCode apiCode=$apiCode message=$message body=${compactBody(responseBody)}"
                )
                throw Exception(
                    if (message.isNotBlank()) "API code $apiCode: $message"
                    else "API code $apiCode: $responseBody"
                )
            }
            val taskJson = json?.optJSONObject("data")?.optJSONObject("task")
                ?: json?.optJSONObject("data")
            val submittedTaskId = taskJson?.optString("id").orEmpty()
            if (submittedTaskId.isBlank()) {
                appLog(
                    LogLevel.WARN,
                    "媒体备份上传失败：remotePath=$remotePath 未返回 upload task id body=${compactBody(responseBody)}"
                )
                throw Exception("上传任务提交成功但未返回 task id")
            }
            appLog(
                LogLevel.INFO,
                "媒体备份上传任务提交成功：remotePath=$remotePath http=$responseCode apiCode=$apiCode message=$message taskId=$submittedTaskId"
            )
            return UploadTaskSubmission(
                taskId = submittedTaskId,
                progress = taskJson?.optDouble("progress", 0.0) ?: 0.0,
                status = taskJson?.optString("status").orEmpty(),
            )
        } finally {
            conn.disconnect()
        }
    }

    private suspend fun waitForUploadTaskComplete(
        uploadTaskId: String,
        file: File,
        remotePath: String,
        authToken: String,
        traceId: String,
        taskId: String,
        successCount: Int,
        failureCount: Int,
        totalPending: Int,
        displayPath: String,
    ) {
        val timeoutMs = estimateTaskTimeoutMs(file.length())
        val startedAt = System.currentTimeMillis()
        var lastProgressBucket = -1
        var lastStatus = ""
        while (true) {
            val elapsedMs = System.currentTimeMillis() - startedAt
            if (elapsedMs > timeoutMs) {
                throw Exception("上传任务超时: uploadTaskId=$uploadTaskId elapsed=${elapsedMs / 1000}s")
            }
            val snapshot = getUploadTaskSnapshot(uploadTaskId, authToken)
            val progressBucket = snapshot.progress.toInt()
            if (progressBucket != lastProgressBucket || snapshot.status != lastStatus) {
                lastProgressBucket = progressBucket
                lastStatus = snapshot.status
                logSync(
                    traceId,
                    taskId,
                    "upload-task",
                    "任务追踪 progress=${buildProgressPercent(successCount, failureCount, totalPending)} remotePath=$displayPath uploadTaskId=$uploadTaskId taskState=${snapshot.state} taskProgress=${progressBucket}% taskStatus=${snapshot.status.ifBlank { "-" }}",
                )
                publishProgress(
                    phase = "UPLOADING_TASK",
                    currentFile = file.name,
                    currentUploadTaskId = uploadTaskId,
                    currentUploadTaskProgress = progressBucket.coerceIn(0, 100),
                    currentUploadTaskStatus = snapshot.status,
                    currentUploadTaskError = if (snapshot.error.isBlank()) null else snapshot.error,
                    pendingFiles = totalPending,
                    uploadedFiles = successCount,
                    failedFiles = failureCount,
                )
            }
            when (snapshot.state) {
                2 -> {
                    appLog(
                        LogLevel.INFO,
                        "媒体备份上传完成：remotePath=$remotePath uploadTaskId=$uploadTaskId taskProgress=${snapshot.progress.toInt()}%"
                    )
                    clearSucceededUploadTasks(authToken)
                    return
                }
                4, 5, 6, 7 -> {
                    publishProgress(
                        phase = "UPLOAD_TASK_FAILED",
                        currentFile = file.name,
                        currentUploadTaskId = uploadTaskId,
                        currentUploadTaskProgress = snapshot.progress.toInt().coerceIn(0, 100),
                        currentUploadTaskStatus = snapshot.status,
                        currentUploadTaskError = snapshot.error.ifBlank { "unknown" },
                        pendingFiles = totalPending,
                        uploadedFiles = successCount,
                        failedFiles = failureCount + 1,
                    )
                    throw Exception(
                        "上传任务失败: uploadTaskId=$uploadTaskId state=${snapshot.state} status=${snapshot.status} error=${snapshot.error}"
                    )
                }
            }
            Thread.sleep(TASK_POLL_INTERVAL_MS)
        }
    }

    private fun getUploadTaskSnapshot(
        uploadTaskId: String,
        authToken: String,
    ): UploadTaskSnapshot {
        val encodedTid = URLEncoder.encode(uploadTaskId, Charsets.UTF_8.name())
        val url = URL("${proxyBaseUrl()}/api/task/upload/info?tid=$encodedTid")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 15000
            conn.readTimeout = 30000
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Authorization", authToken)
            conn.setRequestProperty("Connection", "close")
            val responseCode = conn.responseCode
            val responseBody = try {
                if (responseCode in 200..299) {
                    conn.inputStream?.bufferedReader()?.readText().orEmpty()
                } else {
                    conn.errorStream?.bufferedReader()?.readText().orEmpty()
                }
            } catch (_: Exception) {
                ""
            }
            if (responseCode >= 400) {
                throw Exception("HTTP $responseCode: $responseBody")
            }
            val json = JSONObject(responseBody)
            val apiCode = json.optInt("code", -1)
            if (apiCode != 200) {
                throw Exception("API code $apiCode: ${json.optString("message")}")
            }
            val data = json.optJSONObject("data")
                ?: throw Exception("task info data missing")
            return UploadTaskSnapshot(
                id = data.optString("id"),
                state = data.optInt("state", -1),
                progress = data.optDouble("progress", 0.0),
                status = data.optString("status"),
                error = data.optString("error"),
            )
        } finally {
            conn.disconnect()
        }
    }

    private fun probeRemoteFile(
        remotePath: String,
        authToken: String,
    ): RemoteFileProbe {
        val url = URL("${proxyBaseUrl()}/api/fs/get")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 15000
            conn.readTimeout = 30000
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8")
            conn.setRequestProperty("Authorization", authToken)
            conn.setRequestProperty("Connection", "close")
            val requestBody = JSONObject().apply {
                put("path", remotePath)
                put("password", "")
            }.toString()
            conn.outputStream.use { it.write(requestBody.toByteArray(Charsets.UTF_8)) }

            val responseCode = conn.responseCode
            val responseBody = try {
                if (responseCode in 200..299) {
                    conn.inputStream?.bufferedReader()?.readText().orEmpty()
                } else {
                    conn.errorStream?.bufferedReader()?.readText().orEmpty()
                }
            } catch (_: Exception) {
                ""
            }

            if (responseCode >= 400 || responseBody.isBlank()) {
                return RemoteFileProbe(
                    exists = false,
                    size = null,
                    isDir = false,
                    message = "http=$responseCode"
                )
            }

            val json = try {
                JSONObject(responseBody)
            } catch (_: Exception) {
                return RemoteFileProbe(false, null, false, "invalid-json")
            }
            val apiCode = json.optInt("code", -1)
            if (apiCode != 200) {
                return RemoteFileProbe(
                    exists = false,
                    size = null,
                    isDir = false,
                    message = json.optString("message").ifBlank { "api=$apiCode" }
                )
            }
            val data = json.optJSONObject("data")
                ?: return RemoteFileProbe(false, null, false, "missing-data")
            val size = if (data.has("size") && !data.isNull("size")) data.optLong("size") else null
            return RemoteFileProbe(
                exists = true,
                size = size,
                isDir = data.optBoolean("is_dir", false),
                message = "ok"
            )
        } catch (e: Exception) {
            return RemoteFileProbe(false, null, false, e.message ?: "probe-failed")
        } finally {
            conn.disconnect()
        }
    }

    private fun clearSucceededUploadTasks(authToken: String) {
        val url = URL("${proxyBaseUrl()}/api/task/upload/clear_succeeded")
        val conn = url.openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.connectTimeout = 10000
            conn.readTimeout = 20000
            conn.setRequestProperty("Accept", "application/json")
            conn.setRequestProperty("Authorization", authToken)
            conn.setRequestProperty("Connection", "close")
            val responseCode = conn.responseCode
            if (responseCode !in 200..299) {
                val responseBody = conn.errorStream?.bufferedReader()?.readText().orEmpty()
                appLog(LogLevel.WARN, "清理成功上传任务失败：http=$responseCode body=${compactBody(responseBody)}")
            }
        } catch (e: Exception) {
            appLog(LogLevel.WARN, "清理成功上传任务异常：${e.message}")
        } finally {
            conn.disconnect()
        }
    }

    private fun estimateTaskTimeoutMs(fileSize: Long): Long {
        val sizeMb = fileSize.toDouble() / 1024.0 / 1024.0
        val uploadSpeedMbps = 50.0
        val uploadSpeedMBps = uploadSpeedMbps / 8.0
        val estimatedSeconds = ((sizeMb / uploadSpeedMBps) * 1.5 + 120.0).toLong()
        val minSeconds = 3600L
        return maxOf(minSeconds, estimatedSeconds) * 1000L
    }

    private fun ensureRuntimeReady() {
        try {
            if (!isAlistAlive()) {
                OpenList.startup()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start OpenList before sync: ${e.message}")
        }

        try {
            val configPath = File(AppConfig.dataDir, "encrypt_config.json").absolutePath
            Openlistlib.initEncryptProxy(configPath)
            if (!Openlistlib.isEncryptProxyRunning()) {
                Openlistlib.startEncryptProxy()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start encrypt proxy before sync: ${e.message}")
        }
    }

    private fun proxyBaseUrl(): String {
        val configuredPort = try {
            Openlistlib.getEncryptProxyPort()
        } catch (_: Exception) {
            DEFAULT_PROXY_PORT
        }
        val port = if (configuredPort > 0) configuredPort else DEFAULT_PROXY_PORT
        return "http://127.0.0.1:$port"
    }

    private fun currentOpenListPort(): Int {
        return try {
            OpenList.getHttpPort()
        } catch (_: Exception) {
            5244
        }
    }

    private fun isEncryptedTargetPath(targetPath: String): Boolean {
        val target = normalizeOpenListPath(targetPath)
        if (target.isBlank()) return false
        return try {
            val configJson = Openlistlib.getEncryptConfigJson()
            if (configJson.isBlank() || configJson == "{}") return false
            val paths = JSONObject(configJson).optJSONArray("encryptPaths") ?: return false
            for (i in 0 until paths.length()) {
                val item = paths.optJSONObject(i) ?: continue
                if (!item.optBoolean("enable", true)) continue
                val encryptPath = normalizeOpenListPath(item.optString("path"))
                if (encryptPath.isBlank()) continue
                if (encryptPath == "/" || target == encryptPath || target.startsWith("$encryptPath/")) {
                    return true
                }
            }
            false
        } catch (e: Exception) {
            Log.w(TAG, "Failed to validate encrypted target path: ${e.message}")
            false
        }
    }

    private fun normalizeOpenListPath(path: String): String {
        val trimmed = path.trim().replace('\\', '/')
        if (trimmed == "/") return "/"
        val wildcardNormalized = if (trimmed.endsWith("/*")) {
            trimmed.dropLast(2)
        } else {
            trimmed
        }
        val normalized = wildcardNormalized.trimEnd('/')
        if (normalized.isBlank()) return ""
        return if (normalized.startsWith("/")) normalized else "/$normalized"
    }

    private suspend fun publishProgress(
        phase: String,
        currentPhaseProgress: Int? = null,
        currentPhaseDetail: String? = null,
        currentFile: String? = null,
        currentUploadTaskId: String? = null,
        currentUploadTaskProgress: Int? = null,
        currentUploadTaskStatus: String? = null,
        currentUploadTaskError: String? = null,
        scannedFiles: Int? = null,
        pendingFiles: Int? = null,
        skippedFiles: Int? = null,
        uploadedFiles: Int? = null,
        failedFiles: Int? = null,
    ) {
        val builder = Data.Builder()
            .putString("phase", phase)
        currentPhaseProgress?.let { builder.putInt("currentPhaseProgress", it) }
        currentPhaseDetail?.let { builder.putString("currentPhaseDetail", it) }
        currentFile?.let { builder.putString("currentFile", it) }
        currentUploadTaskId?.let { builder.putString("currentUploadTaskId", it) }
        currentUploadTaskProgress?.let { builder.putInt("currentUploadTaskProgress", it) }
        currentUploadTaskStatus?.let { builder.putString("currentUploadTaskStatus", it) }
        currentUploadTaskError?.let { builder.putString("currentUploadTaskError", it) }
        scannedFiles?.let { builder.putInt("scannedFiles", it) }
        pendingFiles?.let { builder.putInt("pendingFiles", it) }
        skippedFiles?.let { builder.putInt("skippedFiles", it) }
        uploadedFiles?.let { builder.putInt("uploadedFiles", it) }
        failedFiles?.let { builder.putInt("failedFiles", it) }
        setProgress(builder.build())
    }

    private suspend fun publishScanProgress(scanState: ScanProgressState, currentLocation: String, scannedFiles: Int) {
        val detail = "正在扫描目录: ${currentLocation.ifBlank { "/" }}"
        if (scanState.lastPublishedFiles == scannedFiles && scanState.lastDetail == detail) {
            return
        }
        scanState.lastPublishedFiles = scannedFiles
        scanState.lastDetail = detail
        val progress = scanState.heuristicProgress()
        publishProgress(
            phase = "SCANNING",
            currentPhaseProgress = progress,
            currentPhaseDetail = detail,
            currentFile = currentLocation,
            scannedFiles = scannedFiles,
        )
        updateForegroundNotification(
            title = foregroundTitle,
            detail = "扫描本地目录，已发现 $scannedFiles 个文件",
            progress = progress,
            indeterminate = false,
        )
    }

    private fun compactBody(body: String, maxLen: Int = 240): String {
        val compact = body.replace('\n', ' ').replace('\r', ' ').trim()
        return if (compact.length <= maxLen) compact else compact.take(maxLen) + "..."
    }

    private fun appLog(level: Int, msg: String) {
        Logger.log(level, logDateFormatter.format(System.currentTimeMillis()), msg)
    }

    private fun logSync(traceId: String, taskId: String, step: String, msg: String, level: Int = LogLevel.INFO) {
        SyncRecordStore.addLog(
            applicationContext,
            SyncLogEntry(
                taskId = taskId,
                timestamp = System.currentTimeMillis(),
                level = level,
                step = step,
                message = msg,
            )
        )
        appLog(level, "[sync][trace=$traceId][task=$taskId][step=$step] $msg")
    }

    private fun buildProgressPercent(successCount: Int, failureCount: Int, totalPending: Int): String {
        if (totalPending <= 0) return "0%"
        val completed = successCount + failureCount
        val percent = ((completed.toDouble() / totalPending.toDouble()) * 100.0).toInt().coerceIn(0, 100)
        return "$percent%"
    }

    private fun buildTraceId(taskId: String): String {
        val suffix = if (taskId.length > 8) taskId.takeLast(8) else taskId
        return "sync-$suffix-${java.lang.Long.toString(System.currentTimeMillis(), 36)}"
    }

    private fun recordHistory(
        context: Context,
        taskId: String,
        totalFiles: Int,
        pendingFiles: Int,
        skippedFiles: Int,
        successCount: Int,
        failureCount: Int,
        errors: List<String>
    ) {
        SyncRecordStore.addHistory(
            context,
            SyncHistoryEntry(
                taskId = taskId,
                runAt = System.currentTimeMillis(),
                totalFiles = totalFiles,
                pendingFiles = pendingFiles,
                skippedFiles = skippedFiles,
                successCount = successCount,
                failureCount = failureCount,
                errors = errors
            )
        )

        // 更新任务的最后同步状态到 AppConfig
        updateTaskStatus(context, taskId, totalFiles, if (errors.isNotEmpty()) errors.last() else null)
    }

    private fun updateTaskStatus(
        context: Context,
        taskId: String,
        fileCount: Int,
        lastError: String?
    ) {
        try {
            val tasksJson = AppConfig.syncTasksJson
            val tasks = try {
                SyncTaskConfig.listFromJsonArray(tasksJson)
            } catch (_: Exception) {
                return
            }

            val index = tasks.indexOfFirst { it.id == taskId }
            if (index >= 0) {
                val updated = tasks.toMutableList()
                val old = tasks[index]
                updated[index] = old.copy(
                    lastSyncTime = System.currentTimeMillis(),
                    lastSyncFileCount = fileCount,
                    lastError = lastError
                )
                AppConfig.syncTasksJson = Json { ignoreUnknownKeys = true }
                    .encodeToString(updated)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update task status for $taskId", e)
        }
    }

    override suspend fun getForegroundInfo(): ForegroundInfo {
        return createForegroundInfo("媒体加密备份运行中", "正在准备任务", 0, true)
    }

    private suspend fun updateForegroundNotification(
        title: String,
        detail: String,
        progress: Int,
        indeterminate: Boolean,
    ) {
        setForeground(createForegroundInfo(title, detail, progress, indeterminate))
    }

    private fun createForegroundInfo(
        title: String,
        detail: String,
        progress: Int,
        indeterminate: Boolean,
    ): ForegroundInfo {
        ensureForegroundChannel()
        val notification = NotificationCompat.Builder(applicationContext, FOREGROUND_CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(title)
            .setContentText(detail)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setProgress(100, progress.coerceIn(0, 100), indeterminate)
            .build()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(
                FOREGROUND_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            ForegroundInfo(FOREGROUND_NOTIFICATION_ID, notification)
        }
    }

    private fun ensureForegroundChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return
        }
        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            ?: return
        val existing = manager.getNotificationChannel(FOREGROUND_CHANNEL_ID)
        if (existing != null) {
            return
        }
        val channel = NotificationChannel(
            FOREGROUND_CHANNEL_ID,
            "媒体加密备份",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "媒体加密备份任务运行通知"
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        }
        manager.createNotificationChannel(channel)
    }

    private fun notifyMediaLibraryChanged(file: File) {
        try {
            MediaScannerConnection.scanFile(
                applicationContext,
                arrayOf(file.absolutePath, file.parentFile?.absolutePath ?: ""),
                null,
                null,
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to refresh media scanner for ${file.absolutePath}: ${e.message}")
        }
    }

    private fun pruneEmptyDirectories(startDir: File?, stopDir: File) {
        var current = startDir
        val stopPath = stopDir.absoluteFile
        while (current != null) {
            val normalized = current.absoluteFile
            if (normalized == stopPath || !normalized.absolutePath.startsWith(stopPath.absolutePath)) {
                break
            }
            val children = normalized.listFiles()
            if (children != null && children.isEmpty()) {
                val removed = runCatching { normalized.delete() }.getOrDefault(false)
                if (removed) {
                    notifyMediaLibraryChanged(normalized)
                    current = normalized.parentFile
                    continue
                }
            }
            break
        }
    }
}

/**
 * SyncTaskConfig 扩展：从 JSON 数组字符串解析
 */
private fun SyncTaskConfig.Companion.listFromJsonArray(jsonArray: String): List<SyncTaskConfig> {
    if (jsonArray.isBlank() || jsonArray == "[]") return emptyList()
    val json = Json { ignoreUnknownKeys = true }
    return json.decodeFromString(jsonArray)
}
