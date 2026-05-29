package com.openlist.mobile.sync

import android.content.Context
import android.content.pm.PackageManager
import android.os.Environment
import android.util.Log
import androidx.work.*
import com.openlist.mobile.constant.LogLevel
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

    companion object {
        const val TAG = "SyncWorker"
        const val KEY_TASK_ID = "task_id"
        const val KEY_TASK_JSON = "task_json"
        const val DEFAULT_ALIST_BASE_URL = "http://127.0.0.1:5244"
        const val DEFAULT_PROXY_PORT = 5344L
        private val logDateFormatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val taskId = inputData.getString(KEY_TASK_ID) ?: return@withContext Result.failure()
        val taskJson = inputData.getString(KEY_TASK_JSON) ?: return@withContext Result.failure()
        val context = applicationContext

        val taskConfig: SyncTaskConfig
        try {
            taskConfig = SyncTaskConfig.fromJsonString(taskJson)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse task config for $taskId", e)
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("任务配置解析失败: ${e.message ?: "unknown error"}"))
            return@withContext Result.failure()
        }

        publishProgress(phase = "PREPARING")

        // 1. 校验存储权限
        if (!hasStorageAccess()) {
            Log.w(TAG, "No storage access for task $taskId")
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("缺少本地存储访问权限"))
            return@withContext Result.failure()
        }

        // 2. 校验本地 OpenList / 加密代理服务存活
        ensureRuntimeReady()
        if (!isProxyAlive()) {
            Log.w(TAG, "Encrypt proxy not alive for task $taskId")
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("加密代理服务不可用"))
            return@withContext Result.failure()
        }
        if (!isAlistAlive()) {
            Log.w(TAG, "OpenList not alive for task $taskId")
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("OpenList 服务(5244)不可用"))
            return@withContext Result.failure()
        }

        // 2.1. 强制要求目标路径在已启用加密路径内，避免明文上传后误删本地文件
        if (!isEncryptedTargetPath(taskConfig.targetPath)) {
            Log.w(TAG, "Target path is not covered by enabled encrypt paths: ${taskConfig.targetPath}")
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

        // 2.5. 获取认证 token（唯一来源：SyncScheduler.acquireAuthToken）
        val authToken = SyncScheduler.acquireAuthToken()
        if (authToken.isNullOrEmpty()) {
            recordHistory(context, taskId, 0, 0, 0, 0, 1, listOf("未获取到管理认证 token，请先配置管理员密码"))
            return@withContext Result.failure()
        }

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
        collectFiles(sourceDir, taskConfig.fileExtensions, excludeNames, filesToUpload)
        publishProgress(
            phase = "SCANNING",
            scannedFiles = filesToUpload.size,
        )

        if (filesToUpload.isEmpty()) {
            Log.d(TAG, "No files to upload for task $taskId")
            recordHistory(context, taskId, 0, 0, 0, 0, 0, emptyList())
            return@withContext Result.success()
        }

        // 5. 过滤已同步文件（增量判断）
        val newOrModified = filesToUpload.filter { file ->
            val remotePath = buildRemotePath(taskConfig, sourceDir, file)
            !SyncRecordStore.isAlreadySynced(
                context,
                taskId,
                file.absolutePath,
                file.length(),
                file.lastModified(),
                remotePath
            )
        }
        val skippedCount = filesToUpload.size - newOrModified.size
        publishProgress(
            phase = "READY",
            scannedFiles = filesToUpload.size,
            pendingFiles = newOrModified.size,
            skippedFiles = skippedCount,
        )

        if (newOrModified.isEmpty()) {
            Log.d(TAG, "All files already synced for task $taskId")
            recordHistory(
                context,
                taskId,
                filesToUpload.size,
                0,
                skippedCount,
                0,
                0,
                emptyList()
            )
            return@withContext Result.success()
        }

        // 6. 逐个上传
        var successCount = 0
        var failureCount = 0
        val errors = mutableListOf<String>()
        val syncedFiles = mutableListOf<File>()

        for (file in newOrModified) {
            try {
                val remotePath = buildRemotePath(taskConfig, sourceDir, file)
                publishProgress(
                    phase = "UPLOADING",
                    currentFile = file.name,
                    scannedFiles = filesToUpload.size,
                    pendingFiles = newOrModified.size,
                    skippedFiles = skippedCount,
                    uploadedFiles = successCount,
                    failedFiles = failureCount,
                )
                uploadFile(file, remotePath, authToken)

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
                syncedFiles.add(file)
                successCount++
                publishProgress(
                    phase = "UPLOADING",
                    currentFile = file.name,
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
                publishProgress(
                    phase = "UPLOADING",
                    currentFile = file.name,
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

        // 7. 写入历史
        recordHistory(
            context,
            taskId,
            filesToUpload.size,
            newOrModified.size,
            skippedCount,
            successCount,
            failureCount,
            errors
        )

        // 8. 如启用 deleteAfterSync，仅删除已成功上传的文件
        if (taskConfig.deleteAfterSync) {
            for (file in syncedFiles) {
                try {
                    if (file.exists()) {
                        file.delete()
                        Log.d(TAG, "Deleted synced file: ${file.absolutePath}")
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to delete ${file.absolutePath}: ${e.message}")
                }
            }
        }

        // 9. Worker 返回 success/failure 取决于是否完成主流程（不论单文件失败）
        publishProgress(
            phase = "COMPLETED",
            scannedFiles = filesToUpload.size,
            pendingFiles = newOrModified.size,
            skippedFiles = skippedCount,
            uploadedFiles = successCount,
            failedFiles = failureCount,
        )
        if (failureCount > 0) {
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

    private fun collectFiles(
        dir: File,
        extensions: List<String>,
        excludeFolders: Set<String>,
        result: MutableList<File>,
        sourceRoot: File? = null,
        currentRelative: String = ""
    ) {
        val root = sourceRoot ?: dir
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
                collectFiles(file, extensions, excludeFolders, result, root, relPath)
            } else if (file.isFile) {
                if (shouldInclude(file, extensions)) {
                    result.add(file)
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
        val targetPath = config.targetPath.trimEnd('/')
        return if (config.preserveFolderStructure) {
            val relativePath = file.absolutePath
                .removePrefix(sourceDir.absolutePath)
                .trimStart('/')
            "$targetPath/$relativePath"
        } else {
            "$targetPath/${file.name}"
        }
    }

    private fun uploadFile(file: File, remotePath: String, authToken: String?) {
        val url = URL("${proxyBaseUrl()}/api/fs/put")
        val conn = url.openConnection() as HttpURLConnection
        try {
            appLog(LogLevel.INFO, "媒体备份上传开始：remotePath=$remotePath local=${file.name} size=${file.length()}")
            conn.requestMethod = "PUT"
            conn.doOutput = true
            conn.connectTimeout = 30000
            conn.readTimeout = 300000 // 5 min for large files
            val encodedPath = android.net.Uri.encode(remotePath)
            conn.setRequestProperty("File-Path", encodedPath)
            conn.setRequestProperty("Content-Length", file.length().toString())
            // 如果配置了管理员密码，携带认证 token
            if (!authToken.isNullOrEmpty()) {
                conn.setRequestProperty("Authorization", authToken)
            }

            // Write file body
            FileInputStream(file).use { input ->
                conn.outputStream.use { output ->
                    input.copyTo(output, 8192)
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
            appLog(
                LogLevel.INFO,
                "媒体备份上传成功：remotePath=$remotePath http=$responseCode apiCode=$apiCode message=$message"
            )
        } finally {
            conn.disconnect()
        }
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
        val normalized = trimmed.trimEnd('/')
        if (normalized.isBlank()) return ""
        return if (normalized.startsWith("/")) normalized else "/$normalized"
    }

    private suspend fun publishProgress(
        phase: String,
        currentFile: String? = null,
        scannedFiles: Int? = null,
        pendingFiles: Int? = null,
        skippedFiles: Int? = null,
        uploadedFiles: Int? = null,
        failedFiles: Int? = null,
    ) {
        val builder = Data.Builder()
            .putString("phase", phase)
        currentFile?.let { builder.putString("currentFile", it) }
        scannedFiles?.let { builder.putInt("scannedFiles", it) }
        pendingFiles?.let { builder.putInt("pendingFiles", it) }
        skippedFiles?.let { builder.putInt("skippedFiles", it) }
        uploadedFiles?.let { builder.putInt("uploadedFiles", it) }
        failedFiles?.let { builder.putInt("failedFiles", it) }
        setProgress(builder.build())
    }

    private fun compactBody(body: String, maxLen: Int = 240): String {
        val compact = body.replace('\n', ' ').replace('\r', ' ').trim()
        return if (compact.length <= maxLen) compact else compact.take(maxLen) + "..."
    }

    private fun appLog(level: Int, msg: String) {
        Logger.log(level, logDateFormatter.format(System.currentTimeMillis()), msg)
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
}

/**
 * SyncTaskConfig 扩展：从 JSON 数组字符串解析
 */
private fun SyncTaskConfig.Companion.listFromJsonArray(jsonArray: String): List<SyncTaskConfig> {
    if (jsonArray.isBlank() || jsonArray == "[]") return emptyList()
    val json = Json { ignoreUnknownKeys = true }
    return json.decodeFromString(jsonArray)
}
