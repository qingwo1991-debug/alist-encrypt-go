package com.openlist.mobile.bridge

import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import com.openlist.mobile.OpenListService
import com.openlist.mobile.BuildConfig
import com.openlist.mobile.R
import com.openlist.mobile.SwitchServerActivity
import com.openlist.mobile.config.AppConfig
import com.openlist.mobile.constant.LogLevel
import com.openlist.mobile.model.openlist.Logger
import com.openlist.mobile.model.openlist.OpenList
import com.openlist.mobile.utils.MyTools
import com.openlist.mobile.utils.ToastUtils.longToast
import com.openlist.mobile.utils.ToastUtils.toast
import com.openlist.pigeon.GeneratedApi
import openlistlib.Openlistlib
import java.text.SimpleDateFormat
import java.util.Locale

class AndroidBridge(private val context: Context) : GeneratedApi.Android {
    companion object {
        private const val TAG = "AndroidBridge"
        private val logDateFormatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())
    }

    override fun addShortcut() {
        MyTools.addShortcut(
            context,
            context.getString(R.string.app_switch),
            "openlist_mobile_switch",
            R.drawable.openlist_switch,
            Intent(context, SwitchServerActivity::class.java)
        )
    }

    override fun startService() {
        // 清除手动停止标志，表示用户手动启动了服务
        AppConfig.isManuallyStoppedByUser = false
        Log.d(TAG, "Starting service via AndroidBridge, manual stop flag cleared")
        context.startService(Intent(context, OpenListService::class.java))
    }

    override fun setAdminPwd(pwd: String) {
        Log.d(TAG, "setAdminPwd requested length=${pwd.length}")
        try {
            val normalized = pwd.trim()
            require(normalized.length >= 4) { "管理员密码至少需要 4 位" }
            Logger.log(LogLevel.INFO, logDateFormatter.format(System.currentTimeMillis()), "开始更新 OpenList 管理员密码")
            Openlistlib.setConfigData(AppConfig.dataDir)
            Openlistlib.setAdminPassword(normalized)
            AppConfig.encryptAdminPassword = normalized
            Logger.log(LogLevel.INFO, logDateFormatter.format(System.currentTimeMillis()), "OpenList 管理员密码更新完成")
            Log.d(TAG, "setAdminPwd completed successfully")
        } catch (e: Exception) {
            Log.e(TAG, "setAdminPwd failed", e)
            throw e
        }
    }

    override fun getOpenListHttpPort(): Long {
        return OpenList.getHttpPort().toLong()
    }

    override fun setOpenListHttpPort(port: Long) {
        OpenList.setHttpPort(port.toInt())
    }

    override fun isRunning() = OpenListService.isRunning


    override fun getOpenListVersion() = BuildConfig.OPENLIST_VERSION
}
