package com.openlist.mobile.sync

import android.content.Context
import android.util.Log
import com.openlist.mobile.config.AppConfig
import com.openlist.mobile.constant.LogLevel
import com.openlist.mobile.model.openlist.Logger
import com.openlist.mobile.model.openlist.OpenList
import kotlinx.serialization.json.Json
import openlistlib.Openlistlib
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Locale

object SyncSourceCleaner {
    private const val TAG = "SyncSourceCleaner"
    private const val DEFAULT_PROXY_PORT = 5344L
    private val logDateFormatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())

    data class CleanupSummary(
        val scanned: Int,
        val remoteMatched: Int,
        val deleted: Int,
        val failed: Int,
    ) {
        fun toUserMessage(): String {
            return "清理完成：扫描 $scanned，云端匹配 $remoteMatched，已删除 $deleted，失败 $failed"
        }
    }

    private data class RemoteFileProbe(
        val exists: Boolean,
        val size: Long?,
        val isDir: Boolean,
    )

    fun cleanUploadedSourceFiles(context: Context, taskId: String): CleanupSummary {
        val task = loadTask(taskId) ?: throw IllegalArgumentException("未找到任务: $taskId")
        val traceId = buildTraceId(taskId)

        ensureRuntimeReady()
        val authToken = SyncScheduler.acquireAuthToken()
            ?: throw IllegalStateException("未取得管理认证 token，请先在 OpenList 页面校验当前管理员密码")

        val sourceDir = File(task.sourcePath)
        if (!sourceDir.exists() || !sourceDir.isDirectory) {
            throw IllegalStateException("源目录不存在: ${task.sourcePath}")
        }

        val filesToCheck = mutableListOf<File>()
        val excludeNames = task.excludeFolders.map { it.trimEnd('/') }.toSet()
        collectFiles(sourceDir, task.fileExtensions, excludeNames, filesToCheck)

        var remoteMatched = 0
        var deleted = 0
        var failed = 0

        filesToCheck.forEach { file ->
            val remotePath = buildRemotePath(task, sourceDir, file)
            val remoteProbe = probeRemoteFile(remotePath, authToken)
            if (!remoteProbe.exists || remoteProbe.isDir || remoteProbe.size != file.length()) {
                return@forEach
            }

            remoteMatched++
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

            if (!file.exists()) {
                return@forEach
            }

            val removed = try {
                file.delete()
            } catch (e: Exception) {
                log(traceId, taskId, "cleanup", "手动清理异常 file=${file.absolutePath} error=${e.message}", LogLevel.WARN)
                false
            }

            if (removed || !file.exists()) {
                deleted++
                log(traceId, taskId, "cleanup", "手动清理已删除本地源文件 file=${file.absolutePath}")
            } else {
                failed++
                log(traceId, taskId, "cleanup", "手动清理删除失败 file=${file.absolutePath}: delete() returned false", LogLevel.WARN)
            }
        }

        return CleanupSummary(
            scanned = filesToCheck.size,
            remoteMatched = remoteMatched,
            deleted = deleted,
            failed = failed,
        )
    }

    private fun loadTask(taskId: String): SyncTaskConfig? {
        val tasksJson = AppConfig.syncTasksJson
        val tasks = try {
            Json { ignoreUnknownKeys = true }.decodeFromString<List<SyncTaskConfig>>(tasksJson)
        } catch (_: Exception) {
            emptyList()
        }
        return tasks.find { it.id == taskId }
    }

    private fun collectFiles(
        dir: File,
        extensions: List<String>,
        excludeFolders: Set<String>,
        result: MutableList<File>,
        sourceRoot: File? = null,
        currentRelative: String = ""
    ) {
        val files = dir.listFiles() ?: return
        for (file in files) {
            if (file.isDirectory) {
                val relPath = if (currentRelative.isEmpty()) file.name else "$currentRelative/${file.name}"
                val shouldExclude = excludeFolders.contains(file.name) ||
                    excludeFolders.contains(relPath) ||
                    excludeFolders.any { relPath.startsWith(it.trimEnd('/') + "/") || relPath == it.trimEnd('/') }
                if (shouldExclude) {
                    continue
                }
                collectFiles(file, extensions, excludeFolders, result, sourceRoot ?: dir, relPath)
            } else if (file.isFile) {
                if (shouldInclude(file, extensions)) {
                    result.add(file)
                }
            }
        }
    }

    private fun shouldInclude(file: File, extensions: List<String>): Boolean {
        if (extensions.isEmpty()) return true
        val fileName = file.name.lowercase()
        return extensions.any { ext -> fileName.endsWith(ext.lowercase()) }
    }

    private fun buildRemotePath(config: SyncTaskConfig, sourceDir: File, file: File): String {
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

    private fun normalizeOpenListPath(path: String): String {
        val trimmed = path.trim().replace('\\', '/')
        if (trimmed == "/") return "/"
        val wildcardNormalized = if (trimmed.endsWith("/*")) trimmed.dropLast(2) else trimmed
        val normalized = wildcardNormalized.trimEnd('/')
        if (normalized.isBlank()) return ""
        return if (normalized.startsWith("/")) normalized else "/$normalized"
    }

    private fun probeRemoteFile(remotePath: String, authToken: String): RemoteFileProbe {
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
                return RemoteFileProbe(false, null, false)
            }
            val json = try {
                JSONObject(responseBody)
            } catch (_: Exception) {
                return RemoteFileProbe(false, null, false)
            }
            val apiCode = json.optInt("code", -1)
            if (apiCode != 200) {
                return RemoteFileProbe(false, null, false)
            }
            val data = json.optJSONObject("data") ?: return RemoteFileProbe(false, null, false)
            val size = if (data.has("size") && !data.isNull("size")) data.optLong("size") else null
            return RemoteFileProbe(true, size, data.optBoolean("is_dir", false))
        } finally {
            conn.disconnect()
        }
    }

    private fun ensureRuntimeReady() {
        try {
            if (!OpenList.isRunning()) {
                OpenList.startup()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start OpenList before cleanup: ${e.message}")
        }

        try {
            val configPath = File(AppConfig.dataDir, "encrypt_config.json").absolutePath
            Openlistlib.initEncryptProxy(configPath)
            if (!Openlistlib.isEncryptProxyRunning()) {
                Openlistlib.startEncryptProxy()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start encrypt proxy before cleanup: ${e.message}")
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

    private fun log(traceId: String, taskId: String, step: String, msg: String, level: Int = LogLevel.INFO) {
        Logger.log(level, logDateFormatter.format(System.currentTimeMillis()), "[sync][trace=$traceId][task=$taskId][step=$step] $msg")
    }

    private fun buildTraceId(taskId: String): String {
        val suffix = if (taskId.length > 8) taskId.takeLast(8) else taskId
        return "clean-$suffix-${java.lang.Long.toString(System.currentTimeMillis(), 36)}"
    }
}
