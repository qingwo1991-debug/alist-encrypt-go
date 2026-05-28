package com.openlist.mobile.sync

import android.content.Context
import android.util.Log
import androidx.work.*
import com.openlist.mobile.config.AppConfig
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * WorkManager 同步任务调度器
 *
 * 使用：
 * - PeriodicWorkRequest 用于周期任务
 * - OneTimeWorkRequest 用于立即执行
 *
 * 约束：
 * - wifiOnly=true -> NetworkType.UNMETERED
 * - 否则 -> NetworkType.CONNECTED
 * - setRequiresBatteryNotLow(true)
 */
object SyncScheduler {
    private const val TAG = "SyncScheduler"
    private const val WORK_NAME_PREFIX = "sync_task_"
    private const val WORK_NAME_ONETIME_PREFIX = "sync_task_onetime_"
    private const val ENCRYPT_CONFIG_FILE_NAME = "encrypt_config.json"

    /**
     * 调度一个定时同步任务（PeriodicWorkRequest）
     */
    fun schedule(context: Context, taskId: String, taskJson: String) {
        val taskConfig: SyncTaskConfig
        try {
            taskConfig = SyncTaskConfig.fromJsonString(taskJson)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse task config for scheduling: $taskId", e)
            return
        }

        if (!taskConfig.enabled) {
            Log.d(TAG, "Task $taskId is disabled, not scheduling")
            return
        }

        val workName = WORK_NAME_PREFIX + taskId

        // 取消已存在的调度
        WorkManager.getInstance(context).cancelUniqueWork(workName)

        // 构建约束
        val constraints = buildConstraints(taskConfig.wifiOnly)

        // 最小间隔 15 分钟（WorkManager 限制）
        val intervalHours = taskConfig.intervalHours.coerceAtLeast(1)
        val intervalMinutes = (intervalHours * 60).coerceAtLeast(15).toLong()

        val inputData = Data.Builder()
            .putString(SyncWorker.KEY_TASK_ID, taskId)
            .putString(SyncWorker.KEY_TASK_JSON, taskJson)
            .build()

        val periodicWork = PeriodicWorkRequestBuilder<SyncWorker>(
            intervalMinutes, TimeUnit.MINUTES
        )
            .setConstraints(constraints)
            .setInputData(inputData)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                10, TimeUnit.MINUTES
            )
            .build()

        WorkManager.getInstance(context)
            .enqueueUniquePeriodicWork(
                workName,
                ExistingPeriodicWorkPolicy.UPDATE,
                periodicWork
            )

        Log.d(TAG, "Scheduled periodic sync for task $taskId with interval ${intervalMinutes}m")
    }

    /**
     * 立即执行同步任务（OneTimeWorkRequest）
     */
    fun runNow(context: Context, taskId: String) {
        val tasksJson = AppConfig.syncTasksJson
        val tasks = try {
            Json { ignoreUnknownKeys = true }
                .decodeFromString<List<SyncTaskConfig>>(tasksJson)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse tasks for runNow: $taskId", e)
            return
        }

        val task = tasks.find { it.id == taskId } ?: run {
            Log.w(TAG, "Task $taskId not found for runNow")
            return
        }

        val taskJson = task.toJsonString()
        val workName = WORK_NAME_ONETIME_PREFIX + taskId

        // 取消已存在的 one-time work
        WorkManager.getInstance(context).cancelUniqueWork(workName)

        val constraints = buildConstraints(task.wifiOnly)

        val inputData = Data.Builder()
            .putString(SyncWorker.KEY_TASK_ID, taskId)
            .putString(SyncWorker.KEY_TASK_JSON, taskJson)
            .build()

        val oneTimeWork = OneTimeWorkRequestBuilder<SyncWorker>()
            .setConstraints(constraints)
            .setInputData(inputData)
            .setBackoffCriteria(
                BackoffPolicy.EXPONENTIAL,
                5, TimeUnit.MINUTES
            )
            .build()

        WorkManager.getInstance(context)
            .enqueueUniqueWork(
                workName,
                ExistingWorkPolicy.REPLACE,
                oneTimeWork
            )

        Log.d(TAG, "Enqueued one-time sync for task $taskId")
    }

    /**
     * 取消同步任务调度
     */
    fun cancel(context: Context, taskId: String) {
        val periodicName = WORK_NAME_PREFIX + taskId
        val onetimeName = WORK_NAME_ONETIME_PREFIX + taskId
        WorkManager.getInstance(context).apply {
            cancelUniqueWork(periodicName)
            cancelUniqueWork(onetimeName)
        }
        Log.d(TAG, "Cancelled sync scheduling for task $taskId")
    }

    /**
     * 获取同步任务状态（结构化 JSON）
     */
    fun getStatus(context: Context, taskId: String): String {
        val periodicName = WORK_NAME_PREFIX + taskId
        val onetimeName = WORK_NAME_ONETIME_PREFIX + taskId
        val workManager = WorkManager.getInstance(context)

        var periodicState = "NOT_SCHEDULED"
        var oneTimeState = "NONE"

        // 检查 PeriodicWork
        try {
            val periodicWorkInfo = workManager
                .getWorkInfosForUniqueWork(periodicName)
                .get()
            if (periodicWorkInfo.isNotEmpty()) {
                periodicState = periodicWorkInfo[0].state.name
            }
        } catch (_: Exception) {
            periodicState = "UNKNOWN"
        }

        // 检查 OneTimeWork
        try {
            val oneTimeWorkInfo = workManager
                .getWorkInfosForUniqueWork(onetimeName)
                .get()
            if (oneTimeWorkInfo.isNotEmpty()) {
                oneTimeState = oneTimeWorkInfo[0].state.name
            }
        } catch (_: Exception) {
            oneTimeState = "UNKNOWN"
        }

        // 读取任务配置中的 lastSyncTime / lastSyncFileCount / lastError
        var lastSyncTime: Long? = null
        var lastSyncFileCount: Int? = null
        var lastError: String? = null
        try {
            val tasksJson = AppConfig.syncTasksJson
            val tasks = Json { ignoreUnknownKeys = true }
                .decodeFromString<List<SyncTaskConfig>>(tasksJson)
            val task = tasks.find { it.id == taskId }
            if (task != null) {
                lastSyncTime = task.lastSyncTime
                lastSyncFileCount = task.lastSyncFileCount
                lastError = task.lastError
            }
        } catch (_: Exception) {}

        // 读取最近一次历史记录
        val history = SyncRecordStore.getHistory(context, taskId)
        val lastHistoryEntry = history.lastOrNull()

        val status = SyncTaskStatus(
            taskId = taskId,
            periodicState = periodicState,
            oneTimeState = oneTimeState,
            lastSyncTime = lastSyncTime,
            lastSyncFileCount = lastSyncFileCount,
            lastError = lastError,
            lastHistoryEntry = lastHistoryEntry
        )

        return SyncTaskStatus.toJsonString(status)
    }

    /**
     * 获取同步任务历史记录（JSON 字符串）
     */
    fun getHistory(context: Context, taskId: String): String {
        val entries = SyncRecordStore.getHistory(context, taskId)
        return Json { ignoreUnknownKeys = true }.encodeToString(entries)
    }

    private fun buildConstraints(wifiOnly: Boolean): Constraints {
        return Constraints.Builder()
            .setRequiredNetworkType(
                if (wifiOnly) NetworkType.UNMETERED
                else NetworkType.CONNECTED
            )
            .setRequiresBatteryNotLow(true)
            .build()
    }

    // ── 认证令牌获取（供 SyncWorker、SyncBridge 等复用）──

    private const val PROXY_BASE_URL = "http://127.0.0.1:5344"

    /**
     * 使用已存储的 encryptAdminPassword 登录加密代理获取 JWT token。
     *
     * 这是唯一可信的 token 获取来源：
     * - 密码由 EncryptProxyBridge.setEncryptAdminPassword 写入 AppConfig
     * - 不依赖 SharedPreferences 或其他第二套凭据
     *
     * @return token 字符串；未配置密码或登录失败返回 null
     */
    fun acquireAuthToken(): String? {
        var password = AppConfig.encryptAdminPassword.trim()
        if (password.isBlank()) {
            password = loadPasswordFromEncryptConfig().orEmpty()
        }
        if (password.isBlank()) {
            Log.w(TAG, "No encrypt admin password configured, cannot acquire token")
            return null
        }

        acquireAuthTokenWithPassword(password)?.let { return it }

        // 兼容中途接入同步/挂载功能的旧安装：如果 AppConfig 里的密码失效，
        // 但 encrypt_config.json 中已有现成密码，则使用配置文件里的值再试一次。
        val configPassword = loadPasswordFromEncryptConfig()
        if (!configPassword.isNullOrBlank() && configPassword != password) {
            acquireAuthTokenWithPassword(configPassword)?.let { return it }
        }

        return null
    }

    private fun acquireAuthTokenWithPassword(password: String): String? {
        return try {
            val loginUrl = URL("$PROXY_BASE_URL/api/auth/login")
            val conn = loginUrl.openConnection() as HttpURLConnection
            try {
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.setRequestProperty("Content-Type", "application/json")

                val loginBody = JSONObject().apply {
                    put("username", "admin")
                    put("password", password)
                }.toString()

                OutputStreamWriter(conn.outputStream).use { it.write(loginBody) }
                conn.outputStream.close()

                if (conn.responseCode == 200) {
                    val response = conn.inputStream.bufferedReader().readText()
                    val json = JSONObject(response)
                    val token = json.optJSONObject("data")?.optString("token")
                    if (!token.isNullOrEmpty()) {
                        if (AppConfig.encryptAdminPassword != password) {
                            AppConfig.encryptAdminPassword = password
                        }
                        Log.d(TAG, "Auth token acquired for admin API access")
                        return token
                    }
                }
                Log.w(TAG, "Token login failed: HTTP ${conn.responseCode}")
            } finally {
                conn.disconnect()
            }
            null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire auth token: ${e.message}")
            null
        }
    }

    private fun loadPasswordFromEncryptConfig(): String? {
        return try {
            val configFile = File(AppConfig.dataDir, ENCRYPT_CONFIG_FILE_NAME)
            if (!configFile.exists()) {
                return null
            }

            val raw = configFile.readText()
            if (raw.isBlank()) {
                return null
            }

            val password = JSONObject(raw).optString("adminPassword").trim()
            if (password.isBlank()) {
                return null
            }

            if (AppConfig.encryptAdminPassword != password) {
                AppConfig.encryptAdminPassword = password
            }
            Log.d(TAG, "Recovered encrypt admin password from config file")
            password
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read encrypt admin password from config file: ${e.message}")
            null
        }
    }
}
