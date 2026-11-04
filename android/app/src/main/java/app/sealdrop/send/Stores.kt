package app.sealdrop.send

import app.sealdrop.Engine
import app.sealdrop.core.Pairing
import app.sealdrop.net.Listed
import app.sealdrop.net.S3
import app.sealdrop.net.S3Error

/** `up/`, as the phone may use it with the upload key (PROTOCOL.md §8): write only. Names are without the prefix. */
interface UpStore {
    fun put(name: String, body: ByteArray)
    fun createMultipart(name: String): String
    fun uploadPart(name: String, uploadId: String, number: Int, body: ByteArray): String
    fun completeMultipart(name: String, uploadId: String, etags: List<String>)
    fun abortMultipart(name: String, uploadId: String)
}

/** `ack/`, with the receipts key: list and read only. Names are without the prefix. */
interface AckStore {
    fun list(): List<Listed>
    fun get(name: String): ByteArray
}

class S3Up(private val s3: S3, private val at: Pairing.Location) : UpStore {
    override fun put(name: String, body: ByteArray) = s3.put(at.bucket, at.prefix + name, body)
    override fun createMultipart(name: String) = s3.createMultipart(at.bucket, at.prefix + name)
    override fun uploadPart(name: String, uploadId: String, number: Int, body: ByteArray) =
        s3.uploadPart(at.bucket, at.prefix + name, uploadId, number, body)
    override fun completeMultipart(name: String, uploadId: String, etags: List<String>) =
        s3.completeMultipart(at.bucket, at.prefix + name, uploadId, etags)
    override fun abortMultipart(name: String, uploadId: String) = s3.abortMultipart(at.bucket, at.prefix + name, uploadId)
}

class S3Ack(private val s3: S3, private val at: Pairing.Location) : AckStore {
    override fun list(): List<Listed> {
        val found = ArrayList<Listed>()
        var token: String? = null
        do {
            val (page, next) = s3.list(at.bucket, at.prefix, token)
            for (e in page) if (e.name.startsWith(at.prefix)) found += Listed(e.name.removePrefix(at.prefix), e.etag, e.size)
            token = next
        } while (token != null && found.size < MAX_LISTED)
        return found
    }

    override fun get(name: String): ByteArray = s3.get(at.bucket, at.prefix + name)

    companion object {
        /** A flooded `ack/` is read in parts: this many names per run. */
        const val MAX_LISTED = 10_000
    }
}

/**
 * What the storage's answers say about the keys and the clock (PROTOCOL.md §8, warning bits 1, 2 and 8 of §9.1): set
 * by a refusal, cleared by the next request the storage accepts (the clock: by any answer that isn't about it).
 */
object Health {
    const val KEY_REFUSED = "warn.key_refused"
    const val STORAGE_CAP = "warn.storage_cap"
    const val CLOCK = "warn.clock"

    fun <T> call(engine: Engine, request: () -> T): T {
        val result = try {
            request()
        } catch (e: S3Error) {
            noted(engine, e)
            throw e
        }
        val db = engine.db
        if (db.get(KEY_REFUSED) != null || db.get(STORAGE_CAP) != null || db.get(CLOCK) != null) {
            db.put(KEY_REFUSED, null)
            db.put(STORAGE_CAP, null)
            db.put(CLOCK, null)
            engine.changed()
        }
        return result
    }

    private fun noted(engine: Engine, e: S3Error) {
        val db = engine.db
        val now = engine.clock().toString()
        when {
            e.clockWrong -> db.put(CLOCK, now)
            e.status == 0 -> Unit // not an answer from the storage (a reply that couldn't be read)
            else -> {
                db.put(CLOCK, null)
                if (e.capExceeded) db.put(STORAGE_CAP, now) else if (e.refused) db.put(KEY_REFUSED, now)
            }
        }
        engine.changed()
        Engine.log("storage answered ${e.status} ${e.code}")
    }
}
