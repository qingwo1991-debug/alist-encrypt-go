package com.openlist.mobile.sync

import android.content.Context
import android.util.Log
import androidx.work.*
import com.openlist.mobile.constant.LogLevel
import com.openlist.mobile.config.AppConfig
import com.openlist.mobile.model.openlist.Logger
import com.openlist.mobile.model.openlist.OpenList
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Locale
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
    private val logDateFormatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())

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
        var activeProgress: Data? = null

        // 检查 PeriodicWork
        try {
            val periodicWorkInfo = workManager
                .getWorkInfosForUniqueWork(periodicName)
                .get()
            if (periodicWorkInfo.isNotEmpty()) {
                val info = periodicWorkInfo[0]
                periodicState = info.state.name
                if (activeProgress == null && !info.progress.keyValueMap.isEmpty()) {
                    activeProgress = info.progress
                }
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
                val info = oneTimeWorkInfo[0]
                oneTimeState = info.state.name
                if (!info.progress.keyValueMap.isEmpty()) {
                    activeProgress = info.progress
                }
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
            currentPhase = activeProgress?.getString("phase"),
            currentFile = activeProgress?.getString("currentFile"),
            scannedFiles = activeProgress?.getInt("scannedFiles", -1)?.takeIf { it >= 0 },
            pendingFiles = activeProgress?.getInt("pendingFiles", -1)?.takeIf { it >= 0 },
            skippedFiles = activeProgress?.getInt("skippedFiles", -1)?.takeIf { it >= 0 },
            uploadedFiles = activeProgress?.getInt("uploadedFiles", -1)?.takeIf { it >= 0 },
            failedFiles = activeProgress?.getInt("failedFiles", -1)?.takeIf { it >= 0 },
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

    private const val DEFAULT_OPENLIST_PORT = 5244

    /**
     * 使用已存储的 admin 密码登录 OpenList 管理 API 获取 JWT token。
     *
     * 这是唯一可信的 token 获取来源：
     * - OpenList.setAdminPassword 写入 OpenList 用户密码后，同时更新 AppConfig 中的本地缓存
     * - 用户也可以在挂载页直接录入当前 OpenList 管理员密码做校验和缓存
     * - token 直接来自 OpenList(5244/实际配置端口)，本地挂载不依赖 5344 代理是否启动
     *
     * @return token 字符串；未配置密码或登录失败返回 null
     */
    fun acquireAuthToken(): String? {
        val password = AppConfig.encryptAdminPassword.trim()
        if (password.isBlank()) {
            Log.w(TAG, "No cached OpenList admin password configured, cannot acquire token")
            appLog(LogLevel.WARN, "本地挂载认证跳过：未缓存 OpenList 管理员密码")
            return null
        }

        acquireAuthTokenWithPassword(password)?.let { return it }
        appLog(LogLevel.WARN, "本地挂载认证失败：缓存的 OpenList 管理员密码无法登录")
        return null
    }

    fun acquireAuthTokenByPassword(rawPassword: String): String? {
        val password = rawPassword.trim()
        if (password.isBlank()) {
            Log.w(TAG, "acquireAuthTokenByPassword skipped: blank password")
            appLog(LogLevel.WARN, "本地挂载认证跳过：输入的 OpenList 管理员密码为空")
            return null
        }
        Log.d(TAG, "Trying explicit admin password for management token")
        return acquireAuthTokenWithPassword(password)
    }

    private fun acquireAuthTokenWithPassword(password: String): String? {
        ensureOpenListReady()
        for (baseUrl in openListBaseUrls()) {
            acquireAuthTokenWithPassword(baseUrl, password)?.let { return it }
        }
        return null
    }

    private fun acquireAuthTokenWithPassword(baseUrl: String, password: String): String? {
        return try {
            val loginUrl = URL("$baseUrl/api/auth/login/hash")
            val conn = loginUrl.openConnection() as HttpURLConnection
            try {
                appLog(LogLevel.INFO, "本地挂载认证开始：$baseUrl/api/auth/login/hash")
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.setRequestProperty("Accept", "application/json")
                conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8")

                val loginBody = JSONObject().apply {
                    put("username", "admin")
                    put("password", staticHash(password))
                    put("otp_code", "")
                }.toString()

                OutputStreamWriter(conn.outputStream).use { it.write(loginBody) }
                conn.outputStream.close()

                val responseCode = conn.responseCode
                val response = if (responseCode in 200..299) {
                    conn.inputStream.bufferedReader().readText()
                } else {
                    conn.errorStream?.bufferedReader()?.readText().orEmpty()
                }
                if (responseCode == 200 && response.isNotBlank()) {
                    val json = JSONObject(response)
                    val apiCode = json.optInt("code", 0)
                    val message = json.optString("message")
                    val token = json.optJSONObject("data")?.optString("token")
                    if (apiCode == 200 && !token.isNullOrEmpty()) {
                        if (AppConfig.encryptAdminPassword != password) {
                            AppConfig.encryptAdminPassword = password
                        }
                        Log.d(TAG, "Auth token acquired via login/hash for admin API access via $baseUrl")
                        appLog(LogLevel.INFO, "本地挂载认证成功：OpenList 管理员密码已校验")
                        return token
                    }
                    appLog(
                        LogLevel.WARN,
                        "本地挂载认证失败：http=$responseCode apiCode=$apiCode message=$message tokenEmpty=${token.isNullOrEmpty()}"
                    )
                    Log.w(
                        TAG,
                        "OpenList login/hash failed via $baseUrl: http=$responseCode apiCode=$apiCode " +
                            "message=$message tokenEmpty=${token.isNullOrEmpty()}"
                    )
                } else {
                    appLog(LogLevel.WARN, "本地挂载认证失败：http=$responseCode emptyBody=${response.isBlank()}")
                    Log.w(TAG, "OpenList login/hash failed via $baseUrl: http=$responseCode emptyBody=${response.isBlank()}")
                }
            } finally {
                conn.disconnect()
            }
            acquireAuthTokenWithPlainLogin(baseUrl, password)?.let { return it }
            null
        } catch (e: Exception) {
            appLog(LogLevel.WARN, "本地挂载认证异常：${e.javaClass.simpleName}: ${e.message}")
            Log.w(TAG, "Failed to acquire auth token via $baseUrl: ${e.message}")
            null
        }
    }

    private fun acquireAuthTokenWithPlainLogin(baseUrl: String, password: String): String? {
        return try {
            val loginUrl = URL("$baseUrl/api/auth/login")
            val conn = loginUrl.openConnection() as HttpURLConnection
            try {
                appLog(LogLevel.INFO, "本地挂载认证回退：$baseUrl/api/auth/login")
                conn.requestMethod = "POST"
                conn.doOutput = true
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.setRequestProperty("Accept", "application/json")
                conn.setRequestProperty("Content-Type", "application/json;charset=UTF-8")

                val loginBody = JSONObject().apply {
                    put("username", "admin")
                    put("password", password)
                    put("otp_code", "")
                }.toString()
                OutputStreamWriter(conn.outputStream).use { it.write(loginBody) }
                conn.outputStream.close()

                val responseCode = conn.responseCode
                val response = if (responseCode in 200..299) {
                    conn.inputStream.bufferedReader().readText()
                } else {
                    conn.errorStream?.bufferedReader()?.readText().orEmpty()
                }
                if (responseCode == 200 && response.isNotBlank()) {
                    val json = JSONObject(response)
                    val apiCode = json.optInt("code", 0)
                    val message = json.optString("message")
                    val token = json.optJSONObject("data")?.optString("token")
                    if (apiCode == 200 && !token.isNullOrEmpty()) {
                        if (AppConfig.encryptAdminPassword != password) {
                            AppConfig.encryptAdminPassword = password
                        }
                        appLog(LogLevel.INFO, "本地挂载认证成功：OpenList 明文登录校验通过")
                        return token
                    }
                    appLog(
                        LogLevel.WARN,
                        "本地挂载认证回退失败：http=$responseCode apiCode=$apiCode message=$message tokenEmpty=${token.isNullOrEmpty()}"
                    )
                }
            } finally {
                conn.disconnect()
            }
            null
        } catch (e: Exception) {
            appLog(LogLevel.WARN, "本地挂载认证回退异常：${e.javaClass.simpleName}: ${e.message}")
            null
        }
    }

    private fun openListBaseUrls(): List<String> {
        val urls = linkedSetOf<String>()
        val configuredPort = try {
            OpenList.getHttpPort()
        } catch (_: Exception) {
            DEFAULT_OPENLIST_PORT
        }
        if (configuredPort > 0) {
            urls.add("http://127.0.0.1:$configuredPort")
        }
        urls.add("http://127.0.0.1:$DEFAULT_OPENLIST_PORT")
        return urls.toList()
    }

    private fun ensureOpenListReady() {
        try {
            if (!OpenList.isRunning()) {
                OpenList.startup()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to ensure OpenList ready before auth: ${e.message}")
        }
    }

    private fun staticHash(password: String): String {
        val input = "$password-https://github.com/alist-org/alist"
        val digest = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private fun appLog(level: Int, msg: String) {
        val time = synchronized(logDateFormatter) {
            logDateFormatter.format(System.currentTimeMillis())
        }
        Logger.log(level, time, msg)
    }
}
