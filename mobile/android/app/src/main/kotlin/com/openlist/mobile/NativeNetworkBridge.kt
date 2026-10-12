package com.openlist.mobile

import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import com.openlist.mobile.model.openlist.OpenList
import openlistlib.NetworkBridge
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetAddress
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/** Per-service bridge. Tokens identify immutable Network snapshots, never fwmarks. */
class NativeNetworkBridge : NetworkBridge, AutoCloseable {
    companion object {
        private val generations = AtomicLong()
        private const val MAX_QUERIES = 64
        private const val UNSUPPORTED = 95L
        private const val INVALID = 22L
        private const val NO_ROUTE = 101L
        private const val BUSY = 11L
    }

    private class Query(val network: Network) {
        val signals = arrayOf(CancellationSignal(), CancellationSignal())
        val completed = booleanArrayOf(false, false)
        val addresses = linkedSetOf<String>()
        var error = 5L
        var result: String? = null
        var deadline: ScheduledFuture<*>? = null
        var retirement: ScheduledFuture<*>? = null
    }

    private val lock = Any()
    private val routes = mutableMapOf<String, Network>()
    private val queries = mutableMapOf<String, Query>()
    private val callbacks = ThreadPoolExecutor(2, 2, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(64))
    private val deadlines = ScheduledThreadPoolExecutor(1).apply { removeOnCancelPolicy = true }
    private val instance = UUID.randomUUID().toString()
    private var closed = false
    private var initialized = false
    private var defaultNetwork: Network? = null
    private var physicalNetwork: Network? = null

    fun install() {
        OpenList.setNativeNetworkBridge(this)
    }

    /** Retired tokens immediately fail new dials; active DNS keeps its Network reference. */
    fun updateRoutes(default: Network?, physical: Network?) = synchronized(lock) {
        if (closed || (initialized && default == defaultNetwork && physical == physicalNetwork)) return@synchronized
        initialized = true
        defaultNetwork = default
        physicalNetwork = physical
        routes.clear()
        val generation = generations.incrementAndGet()
        var defaultToken = ""
        var physicalToken = ""
        // Older Android has no cancellable same-Network DNS contract. Publish no selected route.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            if (default != null) {
                defaultToken = "$instance:$generation:default"
                routes[defaultToken] = default
            }
            if (physical != null) {
                physicalToken = "$instance:$generation:physical"
                routes[physicalToken] = physical
            }
        }
        OpenList.setNativeNetworkRoutes(defaultToken, physicalToken, generation)
    }

    override fun bindSocket(fd: Long, token: String): Long {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return UNSUPPORTED
        if (fd < 0 || fd > Int.MAX_VALUE) return INVALID
        val network = synchronized(lock) { if (closed) null else routes[token] } ?: return NO_ROUTE
        return try {
            // fromFd DUPLICATES the Go-owned descriptor. Never adopt/close the original.
            ParcelFileDescriptor.fromFd(fd.toInt()).use { duplicate ->
                network.bindSocket(duplicate.fileDescriptor)
            }
            0L
        } catch (_: Exception) {
            NO_ROUTE
        }
    }

    override fun startDNS(id: String, token: String, host: String, timeoutMillis: Long): Long {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return UNSUPPORTED
        if (id.isEmpty() || id.length > 128 || host.isEmpty() || host.length > 253 || host.any { it <= ' ' } || timeoutMillis <= 0) return INVALID
        val query: Query
        synchronized(lock) {
            if (closed) return NO_ROUTE
            val network = routes[token] ?: return NO_ROUTE
            if (queries.containsKey(id)) return INVALID
            if (queries.size >= MAX_QUERIES) return BUSY
            query = Query(network)
            queries[id] = query
            query.deadline = deadlines.schedule({ finish(id, query, 110L) }, timeoutMillis.coerceAtMost(15000), TimeUnit.MILLISECONDS)
        }
        val resolver = DnsResolver.getInstance()
        for ((slot, type) in listOf(DnsResolver.TYPE_A, DnsResolver.TYPE_AAAA).withIndex()) {
            val executor = Executor { task ->
                try {
                    callbacks.execute(task)
                } catch (_: RejectedExecutionException) {
                    finish(id, query, BUSY)
                }
            }
            try {
                resolver.query(query.network, host, type, 0, executor, query.signals[slot], object : DnsResolver.Callback<List<InetAddress>> {
                    override fun onAnswer(results: List<InetAddress>, rcode: Int) {
                        answer(id, query, slot, results, if (rcode == 0) 0L else 5L)
                    }
                    override fun onError(error: DnsResolver.DnsException) {
                        answer(id, query, slot, emptyList(), 5L)
                    }
                })
            } catch (_: Exception) {
                answer(id, query, slot, emptyList(), 5L)
            }
        }
        return 0L
    }

    private fun answer(id: String, query: Query, slot: Int, addresses: List<InetAddress>, error: Long) {
        synchronized(lock) {
            if (queries[id] !== query || query.result != null || query.completed[slot]) return
            query.completed[slot] = true
            if (error == 0L) {
                for (address in addresses) {
                    if (query.addresses.size >= 64) break
                    // Remove IPv6 zone suffix: Go receives literal IPs, not interface names.
                    address.hostAddress?.substringBefore('%')?.let { query.addresses.add(it) }
                }
            } else query.error = error
            if (query.completed.all { it }) finishLocked(id, query, if (query.addresses.isEmpty()) query.error else 0L)
        }
    }

    private fun finishLocked(id: String, query: Query, error: Long) {
        if (queries[id] !== query || query.result != null) return
        query.result = if (error == 0L) {
            JSONObject().put("status", "ok").put("addresses", JSONArray(query.addresses.toList())).toString()
        } else JSONObject().put("status", "error").put("code", error).toString()
        query.deadline?.cancel(false)
        // Bound abandoned terminal records as well as active queries.
        query.retirement = deadlines.schedule({ cancelQuery(id, query) }, 30, TimeUnit.SECONDS)
    }

    private fun finish(id: String, query: Query, error: Long) {
        synchronized(lock) { finishLocked(id, query, error) }
        query.signals.forEach { it.cancel() }
    }

    /** A terminal JSON result is consumed exactly once. */
    override fun pollDNS(id: String): String = synchronized(lock) {
        val query = queries[id] ?: return@synchronized "{\"status\":\"error\",\"code\":2}"
        val result = query.result ?: return@synchronized "{\"status\":\"pending\"}"
        queries.remove(id)
        query.retirement?.cancel(false)
        result
    }

    private fun cancelQuery(id: String, expected: Query? = null) {
        val query = synchronized(lock) {
            val current = queries[id] ?: return
            if (expected != null && current !== expected) return
            queries.remove(id)
            current.deadline?.cancel(false)
            current.retirement?.cancel(false)
            current
        }
        query.signals.forEach { it.cancel() }
    }

    override fun cancelDNS(id: String) = cancelQuery(id)

    override fun close() {
        val active = synchronized(lock) {
            if (closed) return
            closed = true
            routes.clear()
            val records = queries.values.toList()
            queries.clear()
            records.forEach { it.deadline?.cancel(false); it.retirement?.cancel(false) }
            OpenList.setNativeNetworkRoutes("", "", generations.incrementAndGet())
            OpenList.setNativeNetworkBridge(null)
            records
        }
        active.forEach { query -> query.signals.forEach { it.cancel() } }
        callbacks.shutdownNow()
        deadlines.shutdownNow()
    }
}
