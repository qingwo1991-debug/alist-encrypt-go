package com.openlist.mobile.sync

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * 同步任务配置（从 Flutter 传入的 JSON 解析）
 */
@Serializable
data class SyncTaskConfig(
    val id: String,
    val name: String,
    val sourcePath: String,
    val targetPath: String,
    val fileExtensions: List<String> = emptyList(),
    val excludeFolders: List<String> = emptyList(),
    val intervalHours: Int = 1,
    val wifiOnly: Boolean = true,
    val enabled: Boolean = true,
    val deleteAfterSync: Boolean = false,
    val preserveFolderStructure: Boolean = true,
    val uploadSpeedLimitKbps: Int = 0,
    val lastSyncTime: Long? = null,
    val lastSyncFileCount: Int? = null,
    val lastError: String? = null
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        fun fromJsonString(jsonString: String): SyncTaskConfig {
            return json.decodeFromString(jsonString)
        }
    }

    fun toJsonString(): String {
        return json.encodeToString(this)
    }
}

/**
 * 同步任务运行时状态（结构化模型）
 */
@Serializable
data class SyncTaskStatus(
    val taskId: String,
    val periodicState: String = "UNKNOWN",
    val oneTimeState: String = "NONE",
    val cleanupState: String = "NONE",
    val currentPhase: String? = null,
    val currentPhaseProgress: Int? = null,
    val currentPhaseDetail: String? = null,
    val currentFile: String? = null,
    val currentUploadTaskId: String? = null,
    val currentUploadTaskProgress: Int? = null,
    val currentUploadTaskStatus: String? = null,
    val currentUploadTaskError: String? = null,
    val scannedFiles: Int? = null,
    val pendingFiles: Int? = null,
    val skippedFiles: Int? = null,
    val uploadedFiles: Int? = null,
    val failedFiles: Int? = null,
    val lastSyncTime: Long? = null,
    val lastSyncFileCount: Int? = null,
    val lastError: String? = null,
    val lastHistoryEntry: SyncHistoryEntry? = null,
    val recentLogs: List<SyncLogEntry> = emptyList(),
) {
    companion object {
        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

        fun toJsonString(status: SyncTaskStatus): String {
            return json.encodeToString(status)
        }
    }
}
