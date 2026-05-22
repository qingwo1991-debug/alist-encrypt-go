package com.openlist.mobile

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.util.Log
import androidx.lifecycle.lifecycleScope
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.openlist.mobile.bridge.AndroidBridge
import com.openlist.mobile.bridge.AppConfigBridge
import com.openlist.mobile.bridge.CommonBridge
import com.openlist.mobile.bridge.EncryptProxyBridge
import com.openlist.mobile.bridge.ServiceBridge
import com.openlist.mobile.model.ShortCuts
import com.openlist.mobile.model.openlist.Logger
import com.openlist.pigeon.GeneratedApi
import com.openlist.pigeon.GeneratedApi.VoidResult
import io.flutter.embedding.android.FlutterActivity
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugins.GeneratedPluginRegistrant
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : FlutterActivity() {
    companion object {
        private const val TAG = "MainActivity"

        // 静态引用，供其他组件访问
        @Volatile
        var serviceBridge: ServiceBridge? = null
            private set
    }

    private val receiver by lazy { MyReceiver() }
    private var mEvent: GeneratedApi.Event? = null
    private var mLoggerListener: Logger.Listener? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        ShortCuts.buildShortCuts(this)
        LocalBroadcastManager.getInstance(this)
            .registerReceiver(receiver, IntentFilter(OpenListService.ACTION_STATUS_CHANGED))

        GeneratedPluginRegistrant.registerWith(this.flutterEngine!!)

        val binaryMessage = flutterEngine!!.dartExecutor.binaryMessenger
        GeneratedApi.AppConfig.setUp(binaryMessage, AppConfigBridge)
        GeneratedApi.Android.setUp(binaryMessage, AndroidBridge(this))
        GeneratedApi.NativeCommon.setUp(binaryMessage, CommonBridge(this))
        GeneratedApi.EncryptProxy.setUp(binaryMessage, EncryptProxyBridge(this))
        mEvent = GeneratedApi.Event(binaryMessage)

        // 设置服务桥接
        val serviceChannel = MethodChannel(binaryMessage, "com.openlist.mobile/service")
        serviceBridge = ServiceBridge(this, serviceChannel)

        // 保存监听器引用，以便在 onDestroy 中移除，防止内存泄漏
        mLoggerListener = object : Logger.Listener {
            override fun onLog(level: Int, time: String, msg: String) {
                // 使用 lifecycleScope 替代 GlobalScope，确保 Activity 销毁时协程自动取消
                lifecycleScope.launch(Dispatchers.Main) {
                    mEvent?.onServerLog(level.toLong(), time, msg, object : VoidResult {
                        override fun success() {
                        }

                        override fun error(error: Throwable) {
                        }
                    })
                }
            }
        }
        Logger.addListener(mLoggerListener!!)
    }

    override fun onPause() {
        super.onPause()
        // Trigger database sync when app goes to background
        triggerDatabaseSync("onPause")
    }

    override fun onStop() {
        super.onStop()
        // Trigger database sync when app is stopped
        triggerDatabaseSync("onStop")
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        // Trigger database sync on memory pressure
        when (level) {
            TRIM_MEMORY_UI_HIDDEN,
            TRIM_MEMORY_BACKGROUND,
            TRIM_MEMORY_MODERATE,
            TRIM_MEMORY_COMPLETE -> {
                triggerDatabaseSync("onTrimMemory:$level")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Trigger database sync before activity is destroyed
        triggerDatabaseSync("onDestroy")

        // 移除 Logger 监听器，防止内存泄漏
        mLoggerListener?.let { Logger.removeListener(it) }
        mLoggerListener = null

        // 清除静态引用
        serviceBridge = null

        LocalBroadcastManager.getInstance(this).unregisterReceiver(receiver)
    }

    /**
     * Trigger database synchronization through the service
     */
    private fun triggerDatabaseSync(reason: String) {
        try {
            val serviceInstance = OpenListService.serviceInstance
            if (serviceInstance != null && OpenListService.isRunning) {
                Log.d(TAG, "Triggering database sync due to: $reason")
                serviceInstance.forceImmediateDbSync()
            } else {
                Log.d(TAG, "Service not running, skipping database sync for: $reason")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to trigger database sync for $reason", e)
        }
    }


    inner class MyReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.action) {
                OpenListService.ACTION_STATUS_CHANGED -> {
                    Log.d(TAG, "onReceive: ACTION_STATUS_CHANGED")

                    mEvent?.onServiceStatusChanged(OpenListService.isRunning, object : VoidResult {
                        override fun success() {}
                        override fun error(error: Throwable) {
                        }
                    })
                }



            }

        }
    }

}
