package com.openlist.mobile.utils

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.annotation.StringRes

object ToastUtils {
    private val mainHandler = Handler(Looper.getMainLooper())

    /**
     * 在主线程执行代码块
     * 使用 Handler 替代 GlobalScope，避免内存泄漏风险
     */
    fun runMain(block: () -> Unit) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            block()
        } else {
            mainHandler.post(block)
        }
    }

    fun Context.toast(str: String) {
        runMain {
            Toast.makeText(this, str, Toast.LENGTH_SHORT).show()
        }
    }

    fun Context.toast(@StringRes strId: Int, vararg args: Any) {
        runMain {
            Toast.makeText(
                this,
                getString(strId, *args),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    fun Context.longToast(str: String) {
        runMain {
            Toast.makeText(this, str, Toast.LENGTH_LONG).show()
        }
    }

    fun Context.longToast(@StringRes strId: Int) {
        runMain {
            Toast.makeText(this, strId, Toast.LENGTH_LONG).show()
        }
    }

    fun Context.longToast(@StringRes strId: Int, vararg args: Any) {
        runMain {
            Toast.makeText(
                this,
                getString(strId, *args),
                Toast.LENGTH_LONG
            ).show()
        }
    }
}