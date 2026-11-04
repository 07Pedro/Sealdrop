package app.sealdrop.send

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import app.sealdrop.Engine
import app.sealdrop.api.AddResult
import app.sealdrop.api.BeginResult
import app.sealdrop.api.DeliveryState
import app.sealdrop.api.FileOffer
import app.sealdrop.api.ISealdrop
import app.sealdrop.api.Sealdrop
import app.sealdrop.api.SenderInfo
import app.sealdrop.core.Encoding
import app.sealdrop.core.FileEntry
import app.sealdrop.core.Manifests
import app.sealdrop.data.Db
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * The handover (PROTOCOL.md §9.1): handles, copying the offered files into private storage with their checks, and
 * committing them as a delivery. The caller is always Android's calling UID, checked on every call.
 */
class Handover(private val engine: Engine) {
    private class Handle(val id: String, val uid: Int, val app: String, val delivery: String, val network: Int, val folder: File) {
        val files = ArrayList<FileEntry>()
        var lastCall = 0L
        var busy = false
    }

    private val handles = HashMap<String, Handle>()
    private val copying = AtomicInteger()
    private val copier = Executors.newCachedThreadPool()

    private fun now() = engine.clock()

    // --- handles ----------------------------------------------------------------------------------------------------

    /** Ends handles 1 hour after their last call; their copies go. */
    private fun sweep() {
        val old = synchronized(handles) {
            handles.values.filter { !it.busy && now() - it.lastCall > HANDLE_MS }.onEach { handles.remove(it.id) }
        }
        old.forEach { it.folder.deleteRecursively() }
    }

    private fun handleOf(uid: Int, id: String?): Handle? = synchronized(handles) { handles[id]?.takeIf { it.uid == uid } }

    private fun end(h: Handle) {
        synchronized(handles) { handles.remove(h.id) }
        h.folder.deleteRecursively()
    }

    fun begin(uid: Int, delivery: String?, network: Int): BeginResult {
        sweep()
        val app = Approvals.approved(engine, uid) ?: return BeginResult().apply { code = Sealdrop.NOT_APPROVED }
        if (engine.paired() == null) return BeginResult().apply { code = Sealdrop.NOT_PAIRED }
        if (delivery == null || !Manifests.goodDelivery(delivery) || !Manifests.goodApp(app) ||
            network !in Sealdrop.NETWORK_MOBILE..Sealdrop.NETWORK_WIFI_ONLY
        ) return BeginResult().apply { code = Sealdrop.BAD_REQUEST }
        synchronized(handles) { handles.values.filter { it.uid == uid && it.delivery == delivery && !it.busy }.toList() }
            .forEach(::end)
        val id = Encoding.hex(Encoding.randomBytes(16))
        val h = Handle(id, uid, app, delivery, network, File(engine.incoming(), id)).apply { lastCall = now() }
        h.folder.mkdirs()
        synchronized(handles) { handles[id] = h }
        return BeginResult().apply { code = Sealdrop.OK; handle = id }
    }

    fun add(uid: Int, id: String?, offers: Array<FileOffer?>?): AddResult {
        fun result(code: Int, index: Int = -1) = AddResult().apply { this.code = code; this.index = index }
        try {
            Approvals.approved(engine, uid) ?: return result(Sealdrop.NOT_APPROVED)
            val h = handleOf(uid, id) ?: return result(Sealdrop.UNKNOWN_HANDLE)
            if (offers == null || offers.isEmpty() || offers.size > Sealdrop.MAX_FILES_PER_ADD) return result(Sealdrop.BAD_REQUEST)
            var total = 0L
            offers.forEachIndexed { i, o ->
                if (o?.file == null || o.path == null || !Manifests.goodPath(o.path) || o.size < 0 ||
                    o.sha256 == null || !SHA256.matches(o.sha256)
                ) return result(Sealdrop.BAD_REQUEST, i)
                total = try {
                    Math.addExact(total, o.size)
                } catch (e: ArithmeticException) {
                    return result(Sealdrop.BAD_REQUEST, i)
                }
            }
            if (offers.size > 1 && total > Sealdrop.MAX_BYTES_PER_ADD) return result(Sealdrop.BAD_REQUEST)
            val claimed = synchronized(handles) {
                if (h.busy) false else true.also { h.busy = true }
            }
            if (!claimed) return result(Sealdrop.BUSY)
            try {
                val paths = h.files.map { it.path } + offers.map { it!!.path }
                if (Manifests.pathsClash(paths) || h.files.size + offers.size > Manifests.MAX_FILES) return result(Sealdrop.BAD_REQUEST)
                if (h.files.sumOf { it.size } + total > Outbox.maxDeliveryBytes(engine)) return result(Sealdrop.TOO_BIG)
                if (engine.files.usableSpace < total + SPACE_RESERVE) return result(Sealdrop.NO_SPACE)
                if (copying.incrementAndGet() > MAX_COPYING) {
                    copying.decrementAndGet()
                    return result(Sealdrop.BUSY)
                }
                try {
                    val made = ArrayList<File>()
                    offers.forEachIndexed { i, o ->
                        val target = File(h.folder, (h.files.size + i).toString())
                        made += target
                        val code = copyWatched(o!!.file, o.size, o.sha256, target)
                        if (code != Sealdrop.OK) {
                            made.forEach { it.delete() }
                            Engine.log("add: offer $i refused with $code")
                            return result(code, i)
                        }
                    }
                    offers.forEach { h.files += FileEntry(it!!.path, it.size, it.sha256) }
                    return result(Sealdrop.OK)
                } finally {
                    copying.decrementAndGet()
                }
            } finally {
                synchronized(handles) {
                    h.busy = false
                    h.lastCall = now()
                }
            }
        } finally {
            offers?.forEach { o ->
                try {
                    o?.file?.close()
                } catch (e: IOException) {
                    // closed already
                }
            }
        }
    }

    /** Copies on another thread, so a read that stalls for 60 seconds can end the call with 8. */
    private fun copyWatched(fd: ParcelFileDescriptor, size: Long, sha256: String, target: File): Int {
        val cancelled = AtomicBoolean()
        val progress = AtomicLong(System.nanoTime())
        val job = copier.submit<Int> { copy(fd, size, sha256, target, cancelled, progress) }
        while (true) {
            try {
                return job.get(1, TimeUnit.SECONDS)
            } catch (e: TimeoutException) {
                if (System.nanoTime() - progress.get() > STALL_NS) {
                    cancelled.set(true)
                    job.cancel(true)
                    target.delete()
                    return Sealdrop.BUSY
                }
            } catch (e: java.util.concurrent.ExecutionException) {
                target.delete()
                return Sealdrop.BUSY
            }
        }
    }

    private fun copy(
        fd: ParcelFileDescriptor, size: Long, sha256: String, target: File, cancelled: AtomicBoolean, progress: AtomicLong,
    ): Int {
        val descriptor = fd.fileDescriptor
        try {
            val before = Os.fstat(descriptor)
            if (!OsConstants.S_ISREG(before.st_mode) || before.st_size != size) return Sealdrop.BAD_REQUEST
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(BUFFER)
            FileOutputStream(target).use { out ->
                var offset = 0L
                while (offset < size) {
                    if (cancelled.get()) return Sealdrop.BUSY
                    // Positional reads: the file offset is shared with the app.
                    val n = Os.pread(descriptor, buffer, 0, minOf(BUFFER.toLong(), size - offset).toInt(), offset)
                    if (n <= 0) return Sealdrop.BAD_REQUEST // the file got shorter
                    digest.update(buffer, 0, n)
                    out.write(buffer, 0, n)
                    offset += n
                    progress.set(System.nanoTime())
                }
                out.fd.sync()
            }
            if (Os.fstat(descriptor).st_size != size) return Sealdrop.BAD_REQUEST
            if (Encoding.hex(digest.digest()) != sha256) return Sealdrop.CHECKSUM_WRONG
            return Sealdrop.OK
        } catch (e: ErrnoException) {
            return if (e.errno == OsConstants.ENOSPC) Sealdrop.NO_SPACE else Sealdrop.BAD_REQUEST
        } catch (e: IOException) {
            return if ((e.cause as? ErrnoException)?.errno == OsConstants.ENOSPC) Sealdrop.NO_SPACE else Sealdrop.BUSY
        }
    }

    fun commit(uid: Int, id: String?): Int {
        val app = Approvals.approved(engine, uid) ?: return Sealdrop.NOT_APPROVED
        val h = synchronized(handles) {
            val h = handles[id]?.takeIf { it.uid == uid } ?: return Sealdrop.UNKNOWN_HANDLE
            if (h.busy) return Sealdrop.BUSY
            handles.remove(h.id)
            h
        }
        try {
            if (h.files.isEmpty()) return Sealdrop.BAD_REQUEST
            val bytes = h.files.sumOf { it.size }
            if (bytes > Outbox.maxDeliveryBytes(engine)) return Sealdrop.TOO_BIG
            val digest = Manifests.deliveryDigest(h.files)
            val now = now()
            val db = engine.db
            val code = db.tx {
                val known = db.string("SELECT digest FROM deliveries WHERE app = ? AND delivery = ?", app, h.delivery)
                if (known != null) return@tx if (known == digest) Sealdrop.ALREADY_HAVE else Sealdrop.CONFLICT
                val folder = Encoding.hex(Encoding.randomBytes(16))
                if (!h.folder.renameTo(File(engine.copies(), folder))) return@tx Sealdrop.NO_SPACE
                db.db.insertOrThrow("deliveries", null, Db.values(
                    "app" to app, "delivery" to h.delivery, "digest" to digest, "network" to h.network,
                    "state" to Sealdrop.STATE_QUEUED, "created" to now, "bytes" to bytes, "files" to h.files.size,
                    "folder" to folder, "queued_at" to now,
                ))
                h.files.forEachIndexed { i, f ->
                    db.exec("INSERT INTO files (app, delivery, idx, path, size, sha256) VALUES (?, ?, ?, ?, ?, ?)",
                        app, h.delivery, i, f.path, f.size, f.sha256)
                }
                Sealdrop.OK
            }
            if (code == Sealdrop.OK) {
                Engine.log("commit: ${h.files.size} files, $bytes bytes")
                engine.later.sendSoon()
                engine.changed()
            }
            return code
        } finally {
            h.folder.deleteRecursively()
        }
    }

    fun abort(uid: Int, id: String?) {
        val h = handleOf(uid, id) ?: return
        if (!h.busy) end(h)
    }

    // --- holds ------------------------------------------------------------------------------------------------------

    fun hold(uid: Int, seconds: Int) {
        val app = Approvals.approved(engine, uid) ?: return
        Holds.hold(engine, app, seconds.coerceIn(1, 900))
    }

    fun release(uid: Int) {
        val app = Approvals.approved(engine, uid) ?: return
        Holds.release(engine, app)
    }

    // --- asking -----------------------------------------------------------------------------------------------------

    fun status(uid: Int, ids: Array<String?>?): Array<DeliveryState>? {
        val app = Approvals.approved(engine, uid) ?: return emptyArray()
        if (ids == null) return emptyArray()
        if (ids.size > Sealdrop.MAX_STATUS_IDS) return null
        return ids.map { d ->
            val row = engine.db.query("SELECT state, time FROM deliveries WHERE app = ? AND delivery = ?", app, d) {
                it.getInt(0) to it.getLong(1)
            }.firstOrNull()
            DeliveryState().apply {
                delivery = d
                state = row?.first ?: Sealdrop.STATE_UNKNOWN
                time = if (state >= Sealdrop.STATE_PICKED_UP) row!!.second else 0
            }
        }.toTypedArray()
    }

    fun info(uid: Int): SenderInfo? {
        val app = Approvals.approved(engine, uid) ?: return null
        val paired = engine.paired()
        val db = engine.db
        return SenderInfo().apply {
            this.paired = paired != null && !engine.broken()
            fingerprint = paired?.fingerprint ?: ""
            lastPickup = db.getLong(Inbox.LAST_PICKUP)
            lastBackup = db.getLong(Inbox.LAST_BACKUP)
            waiting = db.long("SELECT COUNT(*) FROM deliveries WHERE app = ? AND state BETWEEN 1 AND 3", app).toInt()
            oldestWaiting = db.long("SELECT IFNULL(MIN(created), 0) FROM deliveries WHERE app = ? AND state BETWEEN 1 AND 3", app)
            warnings = Warnings.bits(engine, app)
            maxDeliveryBytes = Outbox.maxDeliveryBytes(engine)
            lostAt = db.long("SELECT IFNULL(MAX(at), 0) FROM lost WHERE app = ?", app)
        }
    }

    fun sendNow(uid: Int, allowMobile: Boolean): Int {
        val app = Approvals.approved(engine, uid) ?: return Sealdrop.NOT_APPROVED
        if (engine.paired() == null) return Sealdrop.NOT_PAIRED
        if (allowMobile) {
            engine.db.exec("UPDATE deliveries SET mobile_once = 1 WHERE app = ? AND state BETWEEN 1 AND 3 AND network = 2", app)
        }
        engine.later.sendNow()
        return Sealdrop.OK
    }

    companion object {
        private val SHA256 = Regex("[0-9a-f]{64}")
        const val HANDLE_MS = 3_600_000L
        private const val STALL_NS = 60_000_000_000L
        private const val MAX_COPYING = 2
        private const val BUFFER = 1 shl 20

        /** Room kept free besides the copies, for the sealed uploads and the database. */
        const val SPACE_RESERVE = 64L shl 20
    }
}

/** The bound service apps talk to (action [Sealdrop.ACTION_DELIVER]). */
class HandoverService : Service() {
    private lateinit var handover: Handover

    override fun onCreate() {
        super.onCreate()
        handover = Handover(Engine.get(this))
    }

    override fun onBind(intent: Intent): IBinder? = if (intent.action == Sealdrop.ACTION_DELIVER) binder else null

    private val binder = object : ISealdrop.Stub() {
        private fun uid() = Binder.getCallingUid()

        override fun apiVersion() = Sealdrop.API_VERSION
        override fun begin(delivery: String?, network: Int) = handover.begin(uid(), delivery, network)
        override fun add(handle: String?, files: Array<FileOffer?>?) = handover.add(uid(), handle, files)
        override fun commit(handle: String?) = handover.commit(uid(), handle)
        override fun abort(handle: String?) = handover.abort(uid(), handle)
        override fun hold(seconds: Int) = handover.hold(uid(), seconds)
        override fun release() = handover.release(uid())
        override fun status(deliveries: Array<String?>?) = handover.status(uid(), deliveries)
        override fun info() = handover.info(uid())
        override fun sendNow(allowMobileForWifiOnly: Boolean) = handover.sendNow(uid(), allowMobileForWifiOnly)
    }
}
