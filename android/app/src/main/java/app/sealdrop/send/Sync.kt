package app.sealdrop.send

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import app.sealdrop.Engine
import app.sealdrop.data.Vault
import app.sealdrop.net.S3Error
import app.sealdrop.pair.Pairer
import java.io.IOException
import kotlin.concurrent.withLock
import kotlin.random.Random

/**
 * One sync run (PROTOCOL.md §9.2, §9.3): uploads what waits, as the network allows, then reads the receipts. Never
 * during a hold. Failures end the run; [Jobs] starts the next one after the pause [Result.retryIn] gives.
 */
object Sync {
    enum class Net { NONE, WIFI, MOBILE }

    const val WIFI_ONLY = "settings.wifi_only"
    private const val MINUTE = 60_000L
    private const val DAY = 86_400_000L

    /** §8: 30 s, then 1, 2, 5 and 15 minutes, then hourly; each ±20 %. */
    private val PAUSES = longArrayOf(30_000, MINUTE, 2 * MINUTE, 5 * MINUTE, 15 * MINUTE, 60 * MINUTE)

    class Result(
        /** Start again after this long (a failure), or null. */
        val retryIn: Long? = null,
        /** A hold runs until then: start again after it. */
        val heldUntil: Long = 0,
        /** Deliveries wait for Wi-Fi. */
        val waitingForWifi: Boolean = false,
    )

    /** The network as §9.2 counts it: Wi-Fi without a metered flag, or mobile data; never roaming. */
    fun network(context: Context, wifiOnly: Boolean): Net {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val caps = cm.activeNetwork?.let(cm::getNetworkCapabilities) ?: return Net.NONE
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return Net.NONE
        val unmetered = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) ||
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_TEMPORARILY_NOT_METERED)
        val wifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        if (wifi && unmetered) return Net.WIFI
        if (wifiOnly) return Net.NONE
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)) return Net.NONE
        if (cm.restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED) return Net.NONE // Data Saver
        return Net.MOBILE
    }

    fun pause(attempt: Int, retryAfterSeconds: Long = -1): Long {
        val base = PAUSES[attempt.coerceIn(0, PAUSES.size - 1)]
        val varied = (base * (0.8 + 0.4 * Random.nextDouble())).toLong()
        return maxOf(varied, retryAfterSeconds * 1000)
    }

    /** [send]: upload and read receipts; otherwise receipts only. [stop]: Android ends the job. */
    fun run(engine: Engine, send: Boolean, stop: () -> Boolean, attempt: Int = 0, beforePart: (Int) -> Unit = {}): Result =
        engine.lock.withLock { runLocked(engine, send, stop, attempt, beforePart) }

    private fun runLocked(engine: Engine, send: Boolean, stop: () -> Boolean, attempt: Int, beforePart: (Int) -> Unit): Result {
        Pairer(engine).pollQuietly()
        val paired = engine.paired() ?: return Result()
        if (engine.broken()) return Result()
        if (Holds.held(engine)) return Result(heldUntil = Holds.endsAt(engine))
        val net = network(engine.context, engine.db.get(WIFI_ONLY) != null)
        if (net == Net.NONE) return Result(waitingForWifi = true)
        var waitingForWifi = false
        try {
            if (send) {
                val outbox = Outbox(engine, engine.upStore(paired), { stop() || Holds.held(engine) }, beforePart)
                waitingForWifi = outbox.run(if (net == Net.WIFI) Outbox.Net.WIFI else Outbox.Net.MOBILE).waitingForWifi
            }
            if (Holds.held(engine)) return Result(heldUntil = Holds.endsAt(engine))
            Inbox(engine, engine.ackStore(paired)) { stop() || Holds.held(engine) }.run()
            return Result(waitingForWifi = waitingForWifi)
        } catch (e: Outbox.Stopped) {
            return if (Holds.held(engine)) Result(heldUntil = Holds.endsAt(engine)) else Result(retryIn = pause(0))
        } catch (e: S3Error) {
            Engine.error("sync: storage answered ${e.status} ${e.code}")
            // 401 and 403: no quick retries, once a day and at the next sync run (§8).
            return Result(retryIn = if (e.refused && !e.clockWrong) DAY else pause(attempt, e.retryAfter))
        } catch (e: IOException) {
            Engine.error("sync: ${e.javaClass.simpleName}")
            return Result(retryIn = pause(attempt))
        } catch (e: Vault.Broken) {
            Engine.error("sync: keys unusable")
            engine.changed()
            return Result()
        } finally {
            engine.changed()
        }
    }

    /** §9.3: how long until receipts are fetched again. */
    fun receiptsIn(engine: Engine): Long {
        val db = engine.db
        if (db.long("SELECT COUNT(*) FROM deliveries WHERE state = 3") == 0L) return DAY
        val since = maxOf(db.getLong(Inbox.LAST_PASS), db.getLong(Outbox.LAST_UPLOAD))
        val quiet = engine.clock() - since
        return when {
            quiet < DAY -> 15 * MINUTE
            quiet < 3 * DAY -> 60 * MINUTE
            else -> 6 * 60 * MINUTE
        }
    }
}
