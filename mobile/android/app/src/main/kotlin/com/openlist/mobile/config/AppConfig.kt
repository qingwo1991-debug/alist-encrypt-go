package com.openlist.mobile.config

import com.cioccarellia.ksprefs.KsPrefs
import com.cioccarellia.ksprefs.dynamic
import com.openlist.mobile.app

object AppConfig {
    val prefs by lazy { KsPrefs(app, "app") }

    var isSilentJumpAppEnabled by prefs.dynamic("isSilentJumpAppEnabled", fallback = false)

    // 默认启用 WakeLock，确保后台服务网络连接不被系统限制
    var isWakeLockEnabled: Boolean by prefs.dynamic("isWakeLockEnabled", fallback = true)
    var isStartAtBootEnabled: Boolean by prefs.dynamic("isStartAtBootEnabled", fallback = false)
    var isAutoCheckUpdateEnabled: Boolean by prefs.dynamic(
        "isAutoCheckUpdateEnabled",
        fallback = false
    )

    var isAutoOpenWebPageEnabled: Boolean by prefs.dynamic(
        "isAutoOpenWebPageEnabled",
        fallback = false
    )

    // 用户手动停止服务的标志，当为true时，保活机制不会重启服务
    var isManuallyStoppedByUser: Boolean by prefs.dynamic("isManuallyStoppedByUser", fallback = false)

    // 使用内部存储作为默认数据目录，确保卸载时数据会被清除
    // getFilesDir() 返回的内部存储路径在卸载时始终会被删除
    // getExternalFilesDir() 返回的外部存储路径在某些厂商ROM上可能不会被清除
    val defaultDataDir by lazy { 
        app.filesDir.resolve("data").apply { mkdirs() }.absolutePath 
    }

    private var mDataDir: String by prefs.dynamic("dataDir", fallback = defaultDataDir)


    var dataDir: String
        get() {
            if (mDataDir.isBlank()) mDataDir = defaultDataDir
            // 确保目录存在
            java.io.File(mDataDir).mkdirs()
            return mDataDir
        }
        set(value) {
            if (value.isBlank()) {
                mDataDir = defaultDataDir
                return
            }

            mDataDir = value
        }

}