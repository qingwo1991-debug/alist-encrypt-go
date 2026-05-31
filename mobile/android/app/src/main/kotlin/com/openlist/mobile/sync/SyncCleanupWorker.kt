package com.openlist.mobile.sync

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.WorkerParameters
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
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val taskId = inputData.getString(KEY_TASK_ID) ?: return@withContext Result.failure()
        val taskJson = inputData.getString(KEY_TASK_JSON)
        try {
            SyncSourceCleaner.cleanUploadedSourceFiles(
                context = applicationContext,
                taskId = taskId,
                taskJson = taskJson,
            ) { progress ->
                setProgressAsync(
                    Data.Builder()
                        .putString("phase", progress.phase)
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
            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Cleanup failed for task $taskId: ${e.message}", e)
            setProgressAsync(
                Data.Builder()
                    .putString("phase", "CLEANUP_FAILED")
                    .putString("currentUploadTaskStatus", "清理失败")
                    .putString("currentUploadTaskError", e.message)
                    .build()
            )
            Result.failure()
        }
    }
}
