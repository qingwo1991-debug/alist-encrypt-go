package com.openlist.mobile.bridge

import android.content.Context
import android.content.Intent
import android.os.Build
import com.openlist.mobile.BuildConfig
import com.openlist.mobile.model.openlist.Logger
import com.openlist.mobile.utils.ToastUtils.longToast
import com.openlist.mobile.utils.ToastUtils.toast
import com.openlist.pigeon.GeneratedApi
import java.text.SimpleDateFormat
import java.util.Locale

class CommonBridge(private val context: Context) : GeneratedApi.NativeCommon {
    private val formatter = SimpleDateFormat("MM-dd HH:mm:ss", Locale.getDefault())
    override fun startActivityFromUri(intentUri: String): Boolean {
        val intent = Intent.parseUri(intentUri, Intent.URI_INTENT_SCHEME)
        return if (intent.resolveActivity(context.packageManager) != null){
            context.startActivity(intent)
            true
        }else{
            false
        }
    }

    override fun getDeviceSdkInt(): Long {
        return Build.VERSION.SDK_INT.toLong()
    }


    override fun getDeviceCPUABI(): String {
        return Build.SUPPORTED_ABIS[0]
    }

    override fun getVersionName() = BuildConfig.VERSION_NAME
    override fun getVersionCode() = BuildConfig.VERSION_CODE.toLong()


    override fun toast(msg: String) {
        context.toast(msg)
    }

    override fun longToast(msg: String) {
        context.longToast(msg)
    }

    override fun writeAppLog(level: Long, msg: String) {
        Logger.log(level.toInt(), formatter.format(System.currentTimeMillis()), msg)
    }
}
