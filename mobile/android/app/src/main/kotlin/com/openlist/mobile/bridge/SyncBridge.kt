package com.openlist.mobile.bridge

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.openlist.mobile.config.AppConfig
import com.openlist.mobile.sync.SyncScheduler
import io.flutter.plugin.common.BasicMessageChannel
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.StandardMessageCodec
import java.util.concurrent.Executors

/**
 * 同步任务管理桥接
 *
 * 负责：
 * - 本地挂载配置 JSON 的持久化读写
 * - 同步任务配置 JSON 的持久化读写
 * - WorkManager 调度管理
 * - 同步任务状态与历史查询
 */
class SyncBridge(private val context: Context) {
    companion object {
        private const val TAG = "SyncBridge"
        private const val CHANNEL_PREFIX = "dev.flutter.pigeon.openlist_mobile.SyncTaskApi"
        private val authExecutor = Executors.newSingleThreadExecutor()
        private val mainHandler = Handler(Looper.getMainLooper())

        fun setUp(binaryMessenger: BinaryMessenger, bridge: SyncBridge) {
            val codec = StandardMessageCodec()

            // getLocalMountsJson
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.getLocalMountsJson", codec)
                .setMessageHandler { _, reply ->
                    try {
                        reply.reply(listOf(AppConfig.localMountsJson))
                    } catch (e: Exception) {
                        Log.e(TAG, "getLocalMountsJson error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // setLocalMountsJson
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.setLocalMountsJson", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val json = args[0] as String
                        AppConfig.localMountsJson = json
                        reply.reply(listOf(null))
                    } catch (e: Exception) {
                        Log.e(TAG, "setLocalMountsJson error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // getSyncTasksJson
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.getSyncTasksJson", codec)
                .setMessageHandler { _, reply ->
                    try {
                        reply.reply(listOf(AppConfig.syncTasksJson))
                    } catch (e: Exception) {
                        Log.e(TAG, "getSyncTasksJson error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // setSyncTasksJson
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.setSyncTasksJson", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val json = args[0] as String
                        AppConfig.syncTasksJson = json
                        reply.reply(listOf(null))
                    } catch (e: Exception) {
                        Log.e(TAG, "setSyncTasksJson error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // scheduleSyncTask
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.scheduleSyncTask", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val taskId = args[0] as String
                        val taskJson = args[1] as String
                        SyncScheduler.schedule(bridge.context, taskId, taskJson)
                        reply.reply(listOf(null))
                    } catch (e: Exception) {
                        Log.e(TAG, "scheduleSyncTask error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // cancelSyncTask
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.cancelSyncTask", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val taskId = args[0] as String
                        SyncScheduler.cancel(bridge.context, taskId)
                        reply.reply(listOf(null))
                    } catch (e: Exception) {
                        Log.e(TAG, "cancelSyncTask error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // runSyncTaskNow
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.runSyncTaskNow", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val taskId = args[0] as String
                        SyncScheduler.runNow(bridge.context, taskId)
                        reply.reply(listOf(null))
                    } catch (e: Exception) {
                        Log.e(TAG, "runSyncTaskNow error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // getSyncTaskStatus
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.getSyncTaskStatus", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val taskId = args[0] as String
                        val status = SyncScheduler.getStatus(bridge.context, taskId)
                        reply.reply(listOf(status))
                    } catch (e: Exception) {
                        Log.e(TAG, "getSyncTaskStatus error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // getSyncTaskHistory
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.getSyncTaskHistory", codec)
                .setMessageHandler { message, reply ->
                    try {
                        val args = message as List<*>
                        val taskId = args[0] as String
                        val history = SyncScheduler.getHistory(bridge.context, taskId)
                        reply.reply(listOf(history))
                    } catch (e: Exception) {
                        Log.e(TAG, "getSyncTaskHistory error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // acquireAuthToken
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.acquireAuthToken", codec)
                .setMessageHandler { _, reply ->
                    authExecutor.execute {
                        try {
                            val token = SyncScheduler.acquireAuthToken()
                            replyOnMain(reply, listOf(token ?: ""))
                        } catch (e: Exception) {
                            Log.e(TAG, "acquireAuthToken error", e)
                            replyOnMain(reply, listOf(e.javaClass.simpleName, e.message, null))
                        }
                    }
                }

            // acquireAuthTokenByPassword
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.acquireAuthTokenByPassword", codec)
                .setMessageHandler { message, reply ->
                    authExecutor.execute {
                        try {
                            val args = message as List<*>
                            val password = args[0] as String
                            val token = SyncScheduler.acquireAuthTokenByPassword(password)
                            replyOnMain(reply, listOf(token ?: ""))
                        } catch (e: Exception) {
                            Log.e(TAG, "acquireAuthTokenByPassword error", e)
                            replyOnMain(reply, listOf(e.javaClass.simpleName, e.message, null))
                        }
                    }
                }
        }

        private fun replyOnMain(reply: BasicMessageChannel.Reply<Any>, payload: List<Any?>) {
            mainHandler.post {
                reply.reply(payload)
            }
        }
    }
}
