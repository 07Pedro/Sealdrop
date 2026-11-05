package app.sealdrop.send

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.os.PersistableBundle
import android.os.UserManager
import app.sealdrop.Engine
import app.sealdrop.pair.Pairer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Sealdrop's background work, as Android jobs, one at a time: sending (30 s after the last commit, on `sendNow`, after
 * a hold, on the retry timer and when Wi-Fi comes back), receipts (§9.3's timetable), and a pairing's receipt.
 */
class Jobs : JobService() {
    private val running = ConcurrentHashMap<Int, AtomicBoolean>()

    override fun onStartJob(params: JobParameters): Boolean {
        // Credential-encrypted storage: nothing to do before the first unlock after a restart (§9.4).
        if (!getSystemService(UserManager::class.java).isUserUnlocked) return false
        val stop = AtomicBoolean()
        running[params.jobId] = stop
        work.execute {
            try {
                run(params, stop)
            } catch (e: Exception) {
                Engine.error("job ${params.jobId}: ${e.javaClass.simpleName}")
            } finally {
                running.remove(params.jobId)
                jobFinished(params, false)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        running[params.jobId]?.set(true)
        return true
    }

    private fun run(params: JobParameters, stop: AtomicBoolean) {
        val engine = Engine.get(this)
        when (params.jobId) {
            PAIR -> {
                if (Pairer(engine).pollQuietly() == Pairer.Poll.WAITING) schedule(this, PAIR, Pairer.POLL_MS)
                return
            }
            else -> {
                val send = params.jobId != RECEIPTS
                val attempt = params.extras.getInt(ATTEMPT, 0)
                val result = Sync.run(engine, send, stop::get, attempt)
                after(this, engine, result, attempt)
            }
        }
    }

    interface Later {
        fun sendSoon()
        fun sendNow()
        fun afterHold()
        fun pairing()
        fun ensure()
        fun cancelAll()
    }

    class Real(private val context: Context) : Later {
        override fun sendSoon() = Companion.sendSoon(context)
        override fun sendNow() = Companion.sendNow(context)
        override fun afterHold() = Companion.afterHold(context)
        override fun pairing() = Companion.pairing(context)
        override fun ensure() = Companion.ensure(context)
        override fun cancelAll() = Companion.cancelAll(context)
    }

    companion object {
        const val SEND = 1
        const val RECEIPTS = 2
        const val PAIR = 3
        const val WIFI = 4
        private const val ATTEMPT = "attempt"
        private const val COMMIT_PAUSE_MS = 30_000L

        private val work = Executors.newSingleThreadExecutor()

        private fun scheduler(context: Context) = context.getSystemService(JobScheduler::class.java)

        private fun builder(context: Context, id: Int) =
            JobInfo.Builder(id, ComponentName(context, Jobs::class.java)).setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)

        private fun schedule(context: Context, id: Int, delayMs: Long, attempt: Int = 0) {
            val job = builder(context, id).setMinimumLatency(maxOf(0, delayMs)).setPersisted(true)
                .setExtras(PersistableBundle().apply { putInt(ATTEMPT, attempt) })
            if (id == WIFI) job.setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED)
            scheduler(context).schedule(job.build())
        }

        /** §9.2: a run starts 30 seconds after the last commit, so files handed over one after another travel together. */
        fun sendSoon(context: Context) = schedule(context, SEND, COMMIT_PAUSE_MS)

        /** A run asked for (`sendNow`, Send now, pairing done, sending resumed): expedited, like [afterHold]. */
        fun sendNow(context: Context) = expedited(context)

        /** The first run after a hold ends is expedited, so Android's power saving doesn't delay it. */
        fun afterHold(context: Context) = expedited(context)

        /** Android may hold back an ordinary job of an app not used lately (for about half an hour, to batch them). */
        private fun expedited(context: Context) {
            val job = builder(context, SEND).setExpedited(true).build()
            if (scheduler(context).schedule(job) != JobScheduler.RESULT_SUCCESS) schedule(context, SEND, 0)
        }

        fun pairing(context: Context) = schedule(context, PAIR, Pairer.POLL_MS)

        /** At start: the receipts job is always scheduled while paired. */
        fun ensure(context: Context) {
            if (scheduler(context).getPendingJob(RECEIPTS) == null) schedule(context, RECEIPTS, 60_000)
        }

        fun cancelAll(context: Context) = scheduler(context).cancelAll()

        private fun after(context: Context, engine: Engine, result: Sync.Result, attempt: Int) {
            when {
                result.heldUntil > 0 -> schedule(context, SEND, result.heldUntil - engine.clock() + 1000)
                result.retryIn != null -> schedule(context, SEND, result.retryIn, attempt + 1)
            }
            if (result.waitingForWifi) schedule(context, WIFI, 0)
            if (engine.paired() != null) schedule(context, RECEIPTS, Sync.receiptsIn(engine))
        }
    }
}
