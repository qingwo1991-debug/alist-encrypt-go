package com.openlist.mobile.sync

import android.content.Context
import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

/**
 * 同步记录模型
 */
@Serializable
data class SyncRecord(
    val taskId: String,
    val filePath: String,
    val fileSize: Long,
    val lastModified: Long,
    val syncedAt: Long,
    val remotePath: String
)

/**
 * 同步历史记录模型
 */
@Serializable
data class SyncHistoryEntry(
    val taskId: String,
    val runAt: Long,
    val totalFiles: Int,
    val pendingFiles: Int = 0,
    val skippedFiles: Int = 0,
    val successCount: Int,
    val failureCount: Int,
    val errors: List<String> = emptyList()
)

/**
 * 同步记录持久化存储（线程安全）
 *
 * 设计要点：
 * - 使用 @Synchronized 保护 load-modify-save 操作
 * - 原子写入：先写临时文件，再 rename 到目标文件
 * - 文件损坏恢复：读取失败时返回空容器
 */
object SyncRecordStore {
    private const val TAG = "SyncRecordStore"

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = false
    }

    @Serializable
    private data class RecordsContainer(
        val records: MutableMap<String, SyncRecord> = mutableMapOf(),
        val history: MutableList<SyncHistoryEntry> = mutableListOf()
    )

    private fun getRecordsFile(context: Context): File {
        val dataDir = com.openlist.mobile.config.AppConfig.dataDir
        return File(dataDir, "sync_records.json")
    }

    @Synchronized
    private fun load(context: Context): RecordsContainer {
        val file = getRecordsFile(context)
        if (!file.exists()) return RecordsContainer()
        return try {
            val text = file.readText()
            if (text.isBlank()) RecordsContainer()
            else json.decodeFromString<RecordsContainer>(text)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load sync_records.json, starting fresh", e)
            // 损坏文件重命名为备份
            try {
                file.renameTo(File(file.absolutePath + ".corrupted.${System.currentTimeMillis()}"))
            } catch (_: Exception) {}
            RecordsContainer()
        }
    }

    /**
     * 原子写入：先写临时文件，再 rename
     */
    @Synchronized
    private fun save(context: Context, container: RecordsContainer) {
        val file = getRecordsFile(context)
        val dir = file.parentFile ?: return
        if (!dir.exists()) dir.mkdirs()

        val tmpFile = File(dir, "sync_records.json.tmp")
        try {
            tmpFile.writeText(json.encodeToString(container))
            // 原子替换：先删除目标（某些系统上 rename 要求目标不存在）
            if (file.exists()) file.delete()
            if (!tmpFile.renameTo(file)) {
                // rename 失败时直接复制
                tmpFile.copyTo(file, overwrite = true)
                tmpFile.delete()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save sync_records.json", e)
            // 清理临时文件
            try { tmpFile.delete() } catch (_: Exception) {}
        }
    }

    @Synchronized
    fun getRecords(context: Context, taskId: String): List<SyncRecord> {
        val container = load(context)
        return container.records.values.filter { it.taskId == taskId }
    }

    @Synchronized
    fun isAlreadySynced(
        context: Context,
        taskId: String,
        filePath: String,
        fileSize: Long,
        lastModified: Long,
        remotePath: String
    ): Boolean {
        val key = "$taskId:$filePath"
        val container = load(context)
        val existing = container.records[key]
        return existing != null &&
            existing.remotePath == remotePath &&
            existing.fileSize == fileSize &&
            existing.lastModified == lastModified
    }

    @Synchronized
    fun markSynced(context: Context, record: SyncRecord) {
        val key = "${record.taskId}:${record.filePath}"
        val container = load(context)
        container.records[key] = record
        save(context, container)
    }

    @Synchronized
    fun addHistory(context: Context, entry: SyncHistoryEntry) {
        val container = load(context)
        container.history.add(entry)
        if (container.history.size > 50) {
            container.history.removeAt(0)
        }
        save(context, container)
    }

    @Synchronized
    fun getHistory(context: Context, taskId: String): List<SyncHistoryEntry> {
        val container = load(context)
        return container.history.filter { it.taskId == taskId }
    }

    @Synchronized
    fun clearRecords(context: Context, taskId: String) {
        val container = load(context)
        container.records.entries.removeIf { it.value.taskId == taskId }
        save(context, container)
    }
}
