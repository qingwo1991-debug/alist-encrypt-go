package com.openlist.mobile.sync

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.ServiceInfo
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.openlist.mobile.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class SyncCleanupWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    companion object {
        const val TAG = "SyncCleanupWorker"
        const val KEY_TASK_ID = "task_id"
        const val KEY_TASK_JSON = "task_json"
        private const val FOREGROUND_CHANNEL_ID = "media_backup_sync"
        private const val FOREGROUND_NOTIFICATION_ID = 53441
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val taskId = inputData.getString(KEY_TASK_ID) ?: return@withContext Result.failure()
        val taskJson = inputData.getString(KEY_TASK_JSON)
        updateForegroundNotification("媒体加密备份清理中", "准备清理本地源文件", 0, true)
        try {
            SyncSourceCleaner.cleanUploadedSourceFiles(
                context = applicationContext,
                taskId = taskId,
                taskJson = taskJson,
            ) { progress ->
                val title = "媒体加密备份清理中"
                val detail = progress.currentPhaseDetail
                    ?: progress.currentUploadTaskStatus
                    ?: "正在清理本地源文件"
                val progressValue = progress.currentPhaseProgress ?: 0
                setForegroundAsync(createForegroundInfo(title, detail, progressValue, progress.currentPhaseProgress == null))
                setProgressAsync(
                    Data.Builder()
                        .putString("phase", progress.phase)
                        .putInt("currentPhaseProgress", progress.currentPhaseProgress ?: -1)
                        .putString("currentPhaseDetail", progress.currentPhaseDetail)
                        .putString("currentFile", progress.currentFile)
                        .putString("currentUploadTaskStatus", progress.currentUploadTaskStatus)
                        .putString("currentUploadTaskError", progress.currentUploadTaskError)
                        .putInt("scannedFiles", progress.scannedFiles ?: -1)
                        .putInt("pendingFiles", progress.pendingFiles ?: -1)
                        .putInt("skippedFiles", progress.skippedFiles ?: -1)
                        .putInt("uploadedFiles", progress.uploadedFiles ?: -1)
                        .putInt("failedFiles", progress.failedFiles ?: -1)
                        .build()
                )
            }
            updateForegroundNotification("媒体加密备份清理完成", "清理任务已完成", 100, false)
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Cleanup failed for task $taskId: ${e.message}", e)
            updateForegroundNotification("媒体加密备份清理失败", e.message ?: "清理任务失败", 100, false)
            setProgressAsync(
                Data.Builder()
                    .putString("phase", "CLEANUP_FAILED")
                    .putInt("currentPhaseProgress", -1)
                    .putString("currentUploadTaskStatus", "清理失败")
                    .putString("currentUploadTaskError", e.message)
                    .build()
            )
            Result.failure()
        }
    }

    override suspend fun getForegroundInfo(): ForegroundInfo {
        return createForegroundInfo("媒体加密备份清理中", "准备清理本地源文件", 0, true)
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
        if (manager.getNotificationChannel(FOREGROUND_CHANNEL_ID) != null) {
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
}
