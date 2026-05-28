package com.openlist.mobile.bridge

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.util.Log
import io.flutter.plugin.common.BasicMessageChannel
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.StandardMessageCodec

/**
 * 存储访问权限桥接
 *
 * Android 策略：
 * - 9-10：检查 READ_EXTERNAL_STORAGE
 * - 11+：检查 MANAGE_EXTERNAL_STORAGE
 */
class StorageBridge(private val context: Context) {
    companion object {
        private const val TAG = "StorageBridge"
        private const val CHANNEL_PREFIX = "dev.flutter.pigeon.openlist_mobile.StorageAccess"

        fun setUp(binaryMessenger: BinaryMessenger, bridge: StorageBridge) {
            val codec = StandardMessageCodec()

            // isStorageAccessGranted
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.isStorageAccessGranted", codec)
                .setMessageHandler { _, reply ->
                    try {
                        val granted = bridge.isStorageAccessGranted()
                        reply.reply(listOf(granted))
                    } catch (e: Exception) {
                        Log.e(TAG, "isStorageAccessGranted error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // requestStorageAccess
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.requestStorageAccess", codec)
                .setMessageHandler { _, reply ->
                    try {
                        val granted = bridge.requestStorageAccess()
                        reply.reply(listOf(granted))
                    } catch (e: Exception) {
                        Log.e(TAG, "requestStorageAccess error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }

            // openStorageAccessSettings
            BasicMessageChannel<Any>(binaryMessenger, "$CHANNEL_PREFIX.openStorageAccessSettings", codec)
                .setMessageHandler { _, reply ->
                    try {
                        bridge.openStorageAccessSettings()
                        reply.reply(listOf(null))
                    } catch (e: Exception) {
                        Log.e(TAG, "openStorageAccessSettings error", e)
                        reply.reply(listOf(e.javaClass.simpleName, e.message, null))
                    }
                }
        }
    }

    fun isStorageAccessGranted(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            // Android 9-10: check READ_EXTERNAL_STORAGE
            context.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED
        }
    }

    fun requestStorageAccess(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11+: 引导到 MANAGE_EXTERNAL_STORAGE 设置页
            // 因为 MANAGE_EXTERNAL_STORAGE 不能通过运行时弹窗授予
            openStorageAccessSettings()
            return isStorageAccessGranted()
        }
        // Android 9-10: 权限在 Flutter 端通过 permission_handler 请求
        return isStorageAccessGranted()
    }

    fun openStorageAccessSettings() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        } else {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:${context.packageName}")
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
        }
    }
}
