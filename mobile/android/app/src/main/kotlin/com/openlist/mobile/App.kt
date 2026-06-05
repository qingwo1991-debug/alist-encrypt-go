package com.openlist.mobile

import android.app.Application
import android.util.Log
import com.openlist.mobile.utils.ToastUtils.longToast
import io.flutter.app.FlutterApplication

val app by lazy { App.app }

class App : FlutterApplication() {
    companion object {
        private const val TAG = "App"
        lateinit var app: Application
    }


    override fun onCreate() {
        super.onCreate()

        app = this
        
        // Set global exception handler to catch uncaught exceptions
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            Log.e(TAG, "Uncaught exception in thread ${thread.name}", throwable)
            
            // Log detailed info for JNI related errors
            if (throwable.message?.contains("JNI") == true || 
                throwable.message?.contains("native") == true ||
                throwable is UnsatisfiedLinkError) {
                Log.e(TAG, "Native/JNI related crash detected")
            }
            
            // Call default exception handler
            val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
            defaultHandler?.uncaughtException(thread, throwable)
        }
    }
}
