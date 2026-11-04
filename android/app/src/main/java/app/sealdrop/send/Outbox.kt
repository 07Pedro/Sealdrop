package app.sealdrop.send

import app.sealdrop.Engine
import app.sealdrop.core.Delivery
import app.sealdrop.core.Encoding
import app.sealdrop.core.FileEntry
import app.sealdrop.core.Json
import app.sealdrop.core.Keys
import app.sealdrop.core.Manifests
import app.sealdrop.core.Sealed
import app.sealdrop.core.Signer
import app.sealdrop.core.Sizes
import app.sealdrop.data.Db
import app.sealdrop.net.S3Error
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.io.SequenceInputStream

/**
 * Bundling and sending (PROTOCOL.md §9.2): packs the oldest waiting deliveries the network allows, seals each bundle
 * into `outbox/` and uploads it, in one request up to 8 MiB and in 8 MiB parts above, resuming where it stopped.
 * [stop] is asked before each upload and between parts (a hold, or Android ending the job).
 */
class Outbox(
    private val engine: Engine,
    private val up: UpStore,
    private val stop: () -> Boolean,
    /** Called before each part is sent; the tests use it to cut the connection. */
    private val beforePart: (Int) -> Unit = {},
) {
    enum class Net { WIFI, MOBILE }

    /** A hold or the end of the job: what's done so far is kept, the rest goes in the next run. */
    class Stopped : Exception("stopped")

    class Result(var uploads: Int = 0, var bytes: Long = 0, var waitingForWifi: Boolean = false)

    private class Item(
        val app: String, val delivery: String, val created: Long, val bytes: Long, val folder: String?, val alone: Boolean,
        val mobile: Boolean,
    )

    private class Upload(val name: String, val size: Long, val uploadId: String?, val etags: List<String>, val mobile: Boolean)

    private val db = engine.db
    private fun now() = engine.clock()

    fun run(net: Net): Result {
        val paired = engine.paired() ?: return Result()
        val signer = engine.signer(paired)
        val result = Result()
        tidy()
        var budget = if (net == Net.MOBILE) MOBILE_BUDGET else Long.MAX_VALUE
        for (u in pending()) {
            if (net == Net.MOBILE && (!u.mobile || u.size > budget)) {
                result.waitingForWifi = true
                continue
            }
            if (stop()) throw Stopped()
            if (upload(u)) {
                budget -= u.size
                result.uploads++
                result.bytes += u.size
            }
        }
        while (true) {
            val bundle = pack(net, budget) ?: break
            if (stop()) throw Stopped()
            val u = seal(bundle, paired, signer, net == Net.MOBILE) ?: continue
            if (upload(u)) {
                budget -= u.size
                result.uploads++
                result.bytes += u.size
            }
        }
        if (net == Net.MOBILE && db.long("SELECT COUNT(*) FROM deliveries WHERE state = 1") > 0) result.waitingForWifi = true
        if (result.uploads > 0) engine.changed()
        return result
    }

    /** A waiting delivery over the collector's limit fails at once; one without a receipt for 60 days is sent again. */
    private fun tidy() {
        val now = now()
        val max = maxDeliveryBytes(engine)
        db.exec("UPDATE deliveries SET state = 6, time = ?, final_at = ?, reason = 'too-big' WHERE state = 1 AND bytes > ?", now, now, max)
        db.exec("UPDATE deliveries SET state = 1, upload = NULL WHERE state = 3 AND inbox_at < ?", now - RESEND_MS)
    }

    // --- packing ----------------------------------------------------------------------------------------------------

    private fun files(app: String, delivery: String): List<FileEntry> =
        db.query("SELECT path, size, sha256 FROM files WHERE app = ? AND delivery = ? ORDER BY idx", app, delivery) {
            FileEntry(it.getString(0), it.getLong(1), it.getString(2))
        }

    /** The next bundle: the oldest waiting deliveries the network allows, until the next would break a limit. */
    private fun pack(net: Net, budget: Long): List<Pair<Item, List<FileEntry>>>? {
        val maxSealed = db.getLong(Inbox.MAX_SEALED, Sizes.DEFAULT_MAX_SEALED)
        val waiting = db.query(
            "SELECT app, delivery, created, bytes, folder, alone, network = 1 OR mobile_once = 1 FROM deliveries " +
                "WHERE state = 1 ORDER BY queued_at, created",
        ) { Item(it.getString(0), it.getString(1), it.getLong(2), it.getLong(3), it.getString(4), it.getInt(5) == 1, it.getInt(6) == 1) }
        val bundle = ArrayList<Pair<Item, List<FileEntry>>>()
        var content = 0L
        var count = 0
        var manifest = ENVELOPE
        for (d in waiting) {
            if (net == Net.MOBILE && !d.mobile) continue
            if (d.folder == null) {
                forget(d.app, d.delivery)
                continue
            }
            val entries = files(d.app, d.delivery)
            val own = Json.write(Manifests.bundleManifest(listOf(Delivery(d.app, d.delivery, d.created, entries)))).size - ENVELOPE
            if (d.alone && bundle.isNotEmpty()) continue
            val sealed = sealedSize(manifest + own + 1, content + d.bytes)
            val fits = bundle.size < Manifests.MAX_DELIVERIES && count + entries.size <= Manifests.MAX_FILES &&
                manifest + own + 1 <= Sizes.MANIFEST_ROOM && sealed <= maxSealed &&
                (if (net == Net.MOBILE) sealed <= budget else content + d.bytes <= WIFI_CONTENT)
            if (!fits) {
                if (bundle.isNotEmpty()) break
                // A single delivery that is bigger travels alone, on Wi-Fi; on mobile data it waits.
                if (net == Net.WIFI && sealedSize(manifest + own, d.bytes) <= maxSealed) return listOf(d to entries)
                continue
            }
            bundle += d to entries
            content += d.bytes
            count += entries.size
            manifest += own + 1
            if (d.alone) break
        }
        return bundle.ifEmpty { null }
    }

    private fun sealedSize(manifest: Int, content: Long) = Sizes.sealedSize(Sizes.paddedLength(Sizes.KIND_BUNDLE, 4L + manifest + content))

    private fun forget(app: String, delivery: String) {
        db.tx {
            db.exec("DELETE FROM deliveries WHERE app = ? AND delivery = ?", app, delivery)
            db.exec("DELETE FROM files WHERE app = ? AND delivery = ?", app, delivery)
        }
        Engine.error("a copy was missing: the app hands it over again")
    }

    // --- sealing ----------------------------------------------------------------------------------------------------

    private fun seal(bundle: List<Pair<Item, List<FileEntry>>>, paired: Engine.Paired, signer: Signer, mobile: Boolean): Upload? {
        for ((d, entries) in bundle) {
            val folder = File(engine.copies(), d.folder!!)
            if (entries.indices.any { !File(folder, it.toString()).isFile }) {
                forget(d.app, d.delivery)
                folder.deleteRecursively()
                return null
            }
        }
        val deliveries = bundle.map { (d, entries) -> Delivery(d.app, d.delivery, d.created, entries) }
        val prefix = Manifests.contentPrefix(Manifests.bundleManifest(deliveries))
        val n = prefix.size + bundle.sumOf { it.first.bytes }
        val streams = ArrayList<() -> InputStream>()
        streams += { ByteArrayInputStream(prefix) }
        for ((d, entries) in bundle) {
            for (i in entries.indices) streams += { FileInputStream(File(File(engine.copies(), d.folder!!), i.toString())) }
        }
        val opened = streams.iterator()
        val content = SequenceInputStream(object : java.util.Enumeration<InputStream> {
            override fun hasMoreElements() = opened.hasNext()
            override fun nextElement() = opened.next()()
        })
        val name = randomName()
        val temporary = File(engine.outbox(), "$name.tmp")
        val out = FileOutputStream(temporary)
        val sealed = try {
            val buffered = BufferedOutputStream(out, 1 shl 20)
            val result = content.use {
                Sealed.seal(buffered, Sizes.KIND_BUNDLE, it, n, Keys.x25519Public(paired.collectorOpen), signer, now())
            }
            buffered.flush()
            out.fd.sync()
            result
        } catch (e: Exception) {
            temporary.delete()
            throw e
        } finally {
            out.close()
        }
        if (!temporary.renameTo(File(engine.outbox(), name))) throw java.io.IOException("can't keep the sealed bundle")
        db.tx {
            db.db.insertOrThrow("uploads", null, Db.values(
                "name" to name, "size" to sealed.size, "sha256" to sealed.sha256, "message" to Encoding.hex(sealed.header.messageId),
                "key_id" to Encoding.hex(paired.keyId), "state" to UPLOAD_SEALED, "created" to now(), "mobile" to mobile,
            ))
            for ((d, _) in bundle) {
                val digest = db.string("SELECT digest FROM deliveries WHERE app = ? AND delivery = ?", d.app, d.delivery)
                db.exec("INSERT OR REPLACE INTO upload_deliveries (name, app, delivery, digest) VALUES (?, ?, ?, ?)",
                    name, d.app, d.delivery, digest)
                db.exec("UPDATE deliveries SET state = 2, upload = ? WHERE app = ? AND delivery = ?", name, d.app, d.delivery)
            }
        }
        Engine.log("sealed ${Encoding.hex(sealed.header.messageId)}: ${bundle.size} deliveries, ${sealed.size} bytes")
        return Upload(name, sealed.size, null, emptyList(), mobile)
    }

    // --- uploading --------------------------------------------------------------------------------------------------

    private fun pending(): List<Upload> =
        db.query("SELECT name, size, upload_id, etags, mobile FROM uploads WHERE state = ? ORDER BY created", UPLOAD_SEALED) {
            Upload(it.getString(0), it.getLong(1), it.getString(2),
                it.getString(3).split(',').filter(String::isNotEmpty), it.getInt(4) == 1)
        }

    /** False if the sealed file was gone: its deliveries wait to be packed again. */
    private fun upload(u: Upload): Boolean {
        val file = File(engine.outbox(), u.name)
        if (!file.isFile || file.length() != u.size) {
            db.tx {
                db.exec("UPDATE deliveries SET state = 1, upload = NULL WHERE upload = ? AND state = 2", u.name)
                db.exec("DELETE FROM upload_deliveries WHERE name = ?", u.name)
                db.exec("DELETE FROM uploads WHERE name = ?", u.name)
            }
            file.delete()
            return false
        }
        if (u.size <= PART) {
            val body = file.readBytes()
            Health.call(engine) { up.put(u.name, body) }
        } else {
            multipart(u, file, again = true)
        }
        val now = now()
        db.tx {
            db.exec("UPDATE uploads SET state = ?, uploaded_at = ?, upload_id = NULL, etags = '' WHERE name = ?", UPLOAD_SENT, now, u.name)
            val count = db.long("SELECT COUNT(*) FROM deliveries WHERE upload = ? AND state = 2", u.name)
            db.exec("UPDATE deliveries SET state = 3, inbox_at = ?, mobile_once = 0 WHERE upload = ? AND state = 2", now, u.name)
            db.putLong(LAST_UPLOAD, now)
            db.put(LAST_UPLOAD_WHAT, "$count ${u.size}")
        }
        file.delete()
        Engine.log("uploaded ${u.size} bytes")
        return true
    }

    private fun multipart(u: Upload, file: File, again: Boolean) {
        val id = u.uploadId ?: Health.call(engine) { up.createMultipart(u.name) }.also {
            db.exec("UPDATE uploads SET upload_id = ?, etags = '' WHERE name = ?", it, u.name)
        }
        val etags = if (u.uploadId == null) ArrayList() else ArrayList(u.etags)
        val parts = ((u.size + PART - 1) / PART).toInt()
        try {
            RandomAccessFile(file, "r").use { raf ->
                for (number in etags.size + 1..parts) {
                    if (stop()) throw Stopped()
                    beforePart(number)
                    val offset = (number - 1) * PART
                    val body = ByteArray(minOf(PART, u.size - offset).toInt())
                    raf.seek(offset)
                    raf.readFully(body)
                    etags += Health.call(engine) { up.uploadPart(u.name, id, number, body) }
                    db.exec("UPDATE uploads SET etags = ? WHERE name = ?", etags.joinToString(","), u.name)
                }
            }
            Health.call(engine) { up.completeMultipart(u.name, id, etags) }
        } catch (e: S3Error) {
            if (e.code != "NoSuchUpload" || !again) throw e
            // The provider forgot the upload (its lifecycle rule, for example): start over.
            db.exec("UPDATE uploads SET upload_id = NULL, etags = '' WHERE name = ?", u.name)
            multipart(Upload(u.name, u.size, null, emptyList(), u.mobile), file, again = false)
        }
    }

    companion object {
        const val PART = 8L shl 20
        const val MOBILE_BUDGET = 10L shl 20
        const val WIFI_CONTENT = 256L shl 20
        const val RESEND_MS = 60 * 86_400_000L
        const val UPLOAD_SEALED = 0
        const val UPLOAD_SENT = 2
        const val LAST_UPLOAD = "outbox.last_upload"
        const val LAST_UPLOAD_WHAT = "outbox.last_upload_what"

        /** `{"v":1,"type":"bundle","deliveries":[]}` */
        private const val ENVELOPE = 39

        /** §9.2: from the collector's `max_sealed` (4 GiB until the first receipt). */
        fun maxDeliveryBytes(engine: Engine): Long =
            Sizes.maxDeliveryBytes(engine.db.getLong(Inbox.MAX_SEALED, Sizes.DEFAULT_MAX_SEALED))

        /** 32 characters from a–z 2–7: 160 random bits (§8). */
        fun randomName(): String = Encoding.base32(Encoding.randomBytes(20)).lowercase(java.util.Locale.ROOT)
    }
}
