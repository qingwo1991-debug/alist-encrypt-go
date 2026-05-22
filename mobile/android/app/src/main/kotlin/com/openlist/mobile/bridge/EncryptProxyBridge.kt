package com.openlist.mobile.bridge

import android.content.Context
import android.util.Log
import com.openlist.mobile.config.AppConfig
import com.openlist.pigeon.GeneratedApi
import openlistlib.Openlistlib
import java.io.File

/**
 * 加密代理桥接类，实现 Flutter 与 Go 的通信
 */
class EncryptProxyBridge(private val context: Context) : GeneratedApi.EncryptProxy {
    
    companion object {
        private const val TAG = "EncryptProxyBridge"
        private const val CONFIG_FILE_NAME = "encrypt_config.json"
    }
    
    private val configPath: String
        get() = File(AppConfig.dataDir, CONFIG_FILE_NAME).absolutePath
    
    override fun initEncryptProxy(configPath: String) {
        Log.d(TAG, "initEncryptProxy: $configPath")
        try {
            val path = if (configPath.isEmpty()) this.configPath else configPath
            Openlistlib.initEncryptProxy(path)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init encrypt proxy", e)
            throw e
        }
    }
    
    override fun startEncryptProxy() {
        Log.d(TAG, "startEncryptProxy")
        try {
            Openlistlib.startEncryptProxy()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start encrypt proxy", e)
            throw e
        }
    }
    
    override fun stopEncryptProxy() {
        Log.d(TAG, "stopEncryptProxy")
        try {
            Openlistlib.stopEncryptProxy()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop encrypt proxy", e)
            throw e
        }
    }
    
    override fun restartEncryptProxy() {
        Log.d(TAG, "restartEncryptProxy")
        try {
            Openlistlib.restartEncryptProxy()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to restart encrypt proxy", e)
            throw e
        }
    }
    
    override fun isEncryptProxyRunning(): Boolean {
        return try {
            Openlistlib.isEncryptProxyRunning()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check encrypt proxy status", e)
            false
        }
    }
    
    override fun getEncryptProxyPort(): Long {
        return try {
            Openlistlib.getEncryptProxyPort()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get encrypt proxy port", e)
            5344L
        }
    }
    
    override fun setEncryptAlistHost(host: String, port: Long, https: Boolean) {
        Log.d(TAG, "setEncryptAlistHost: host=$host, port=$port, https=$https")
        try {
            Openlistlib.setEncryptAlistHost(host, port, https)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set alist host", e)
            throw e
        }
    }
    
    override fun setEncryptProxyPort(port: Long) {
        Log.d(TAG, "setEncryptProxyPort: port=$port")
        try {
            Openlistlib.setEncryptProxyPort(port)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set proxy port", e)
            throw e
        }
    }
    
    override fun setEncryptEnableH2C(enable: Boolean) {
        Log.d(TAG, "setEncryptEnableH2C: enable=$enable")
        try {
            Openlistlib.setEncryptEnableH2C(enable)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set H2C enable", e)
            throw e
        }
    }
    
    override fun getEncryptEnableH2C(): Boolean {
        return try {
            Openlistlib.getEncryptEnableH2C()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get H2C enable", e)
            false
        }
    }

    override fun setEncryptDbExportSyncConfig(
        enable: Boolean,
        baseUrl: String,
        intervalSeconds: Long,
        authEnabled: Boolean,
        username: String,
        password: String
    ) {
        Log.d(
            TAG,
            "setEncryptDbExportSyncConfig: enable=$enable, baseUrl=$baseUrl, intervalSeconds=$intervalSeconds, authEnabled=$authEnabled, username=$username"
        )
        try {
            Openlistlib.setEncryptDbExportSyncConfig(
                enable,
                baseUrl,
                intervalSeconds,
                authEnabled,
                username,
                password
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set DB_EXPORT sync config", e)
            throw e
        }
    }

    override fun setEncryptNetworkPolicy(
        upstreamTimeoutSeconds: Long,
        probeTimeoutSeconds: Long,
        probeBudgetSeconds: Long,
        upstreamBackoffSeconds: Long,
        enableLocalBypass: Boolean
    ) {
        Log.d(
            TAG,
            "setEncryptNetworkPolicy: upstreamTimeout=$upstreamTimeoutSeconds, probeTimeout=$probeTimeoutSeconds, probeBudget=$probeBudgetSeconds, upstreamBackoff=$upstreamBackoffSeconds, enableLocalBypass=$enableLocalBypass"
        )
        try {
            Openlistlib.setEncryptNetworkPolicy(
                upstreamTimeoutSeconds,
                probeTimeoutSeconds,
                probeBudgetSeconds,
                upstreamBackoffSeconds,
                enableLocalBypass
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set network policy", e)
            throw e
        }
    }
    
    override fun addEncryptPath(path: String, password: String, encType: String, encName: Boolean, encSuffix: String) {
        Log.d(TAG, "addEncryptPath: path=$path, encType=$encType, encName=$encName, encSuffix=$encSuffix")
        try {
            Openlistlib.addEncryptPathConfig(path, password, encType, encName, encSuffix)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to add encrypt path", e)
            throw e
        }
    }
    
    override fun updateEncryptPath(
        index: Long,
        path: String,
        password: String,
        encType: String,
        encName: Boolean,
        encSuffix: String,
        enable: Boolean
    ) {
        Log.d(TAG, "updateEncryptPath: index=$index, path=$path")
        try {
            Openlistlib.updateEncryptPathConfig(index, path, password, encType, encName, encSuffix, enable)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update encrypt path", e)
            throw e
        }
    }
    
    override fun removeEncryptPath(index: Long) {
        Log.d(TAG, "removeEncryptPath: index=$index")
        try {
            Openlistlib.removeEncryptPathConfig(index)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove encrypt path", e)
            throw e
        }
    }
    
    override fun getEncryptPathsJson(): String {
        return try {
            Openlistlib.getEncryptPathsJson()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get encrypt paths", e)
            "[]"
        }
    }
    
    override fun getEncryptConfigJson(): String {
        return try {
            Openlistlib.getEncryptConfigJson()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get encrypt config", e)
            "{}"
        }
    }
    
    override fun setEncryptAdminPassword(password: String) {
        Log.d(TAG, "setEncryptAdminPassword")
        try {
            Openlistlib.setEncryptAdminPassword(password)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set admin password", e)
            throw e
        }
    }
    
    override fun verifyEncryptAdminPassword(password: String): Boolean {
        return try {
            Openlistlib.verifyEncryptAdminPassword(password)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to verify admin password", e)
            false
        }
    }
}
