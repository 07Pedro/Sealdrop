package app.sealdrop.send

import app.sealdrop.Engine
import app.sealdrop.api.Sealdrop
import app.sealdrop.core.BytesSource
import app.sealdrop.core.Ed25519Verifier
import app.sealdrop.core.Encoding
import app.sealdrop.core.FormatException
import app.sealdrop.core.Keys
import app.sealdrop.core.Reading
import app.sealdrop.core.Reasons
import app.sealdrop.core.Receipts
import app.sealdrop.core.Rejected
import app.sealdrop.core.Sealed
import app.sealdrop.core.SealedFile
import app.sealdrop.core.Sizes
import app.sealdrop.core.Where
import java.io.File
import java.security.MessageDigest

/**
 * Receipts (PROTOCOL.md §6, the phone's side): fetches every new name in `ack/`, checks it, and matches its entries
 * against the uploads still pending. Final states (4, 5, 6) don't change through later receipts, except when the
 * collector lost deliveries.
 */
class Inbox(private val engine: Engine, private val ack: AckStore, private val stop: () -> Boolean = { false }) {
    private val db = engine.db
    private fun now() = engine.clock()

    private class Row(
        val app: String, val delivery: String, val digest: String, val state: Int, val folder: String?, val strikes: Int,
        val wholeRejects: Int, val upload: String?,
    )

    private class Upload(val name: String, val rejected: Boolean)

    /** The number of new receipts handled. */
    fun run(): Int {
        val listed = Health.call(engine) { ack.list() }
        val known = db.query("SELECT name FROM receipts") { it.getString(0) }.toHashSet()
        if (listed.size < S3Ack.MAX_LISTED) {
            // §6 step 7: names gone from the listing are forgotten.
            val present = listed.mapTo(HashSet()) { it.name }
            db.tx { for (name in known) if (name !in present) db.exec("DELETE FROM receipts WHERE name = ?", name) }
        }
        var handled = 0
        for (e in listed) {
            if (e.name in known) continue
            if (stop()) break
            val outcome = if (Sizes.lengthForSize(Where.ACK, e.size) == null) {
                unpassed()
                "size"
            } else {
                take(Health.call(engine) { ack.get(e.name) })
            }
            db.exec("INSERT OR REPLACE INTO receipts (name, outcome, at) VALUES (?, ?, ?)", e.name, outcome, now())
            if (outcome == "receipt") handled++
        }
        tidy()
        engine.changed()
        return handled
    }

    /** One file from `ack/`: what came of it (`receipt`, `paired`, `ignored`, `bad`). */
    fun take(data: ByteArray): String {
        val opening = engine.openings().firstOrNull { o ->
            try {
                Sealed.checkListedSize(Where.ACK, data.size.toLong())
                SealedFile(BytesSource(data)).openHeader(listOf(o.private), Sealed.INFO_TO_SENDER, listOf(Sizes.KIND_RECEIPT))
                true
            } catch (e: Rejected) {
                false
            }
        }
        if (opening == null) {
            unpassed() // for another phone, or junk
            return "ignored"
        }
        val receipt = try {
            val (_, manifest) = Reading.openReceipt(
                data, listOf(opening.private), Ed25519Verifier(opening.collectorSign), Keys.keyId(opening.collectorSign),
            )
            Receipts.parse(manifest, engine.ownKeyIds())
        } catch (e: Rejected) {
            cantRead(e.reason)
            return "bad"
        } catch (e: FormatException) {
            cantRead("form")
            return "bad"
        }
        db.put(CANT_READ_AT, null)
        db.put(UNPASSED_SINCE, null)
        db.putLong(LAST_PASS, now())
        if (receipt !is Receipts.Report) return "paired"
        db.tx { apply(receipt) }
        Engine.log("receipt: ${receipt.stored.size} stored, ${receipt.rejected.size} rejected")
        return "receipt"
    }

    private fun unpassed() {
        if (db.getLong(UNPASSED_SINCE) == 0L) db.putLong(UNPASSED_SINCE, now())
    }

    private fun cantRead(why: String) {
        db.putLong(CANT_READ_AT, now())
        Engine.error("a receipt opened but failed its checks: $why")
    }

    // --- matching (§6, steps 4 to 6) --------------------------------------------------------------------------------

    private fun row(app: String, delivery: String): Row? =
        db.query("SELECT app, delivery, digest, state, folder, strikes, whole_rejects, upload FROM deliveries WHERE app = ? AND delivery = ?",
            app, delivery) {
            Row(it.getString(0), it.getString(1), it.getString(2), it.getInt(3), it.getString(4), it.getInt(5), it.getInt(6), it.getString(7))
        }.firstOrNull()

    private fun uploadBy(sql: String, vararg args: Any?): Upload? =
        db.query("SELECT name, rejected FROM uploads WHERE $sql", *args) { Upload(it.getString(0), it.getInt(1) == 1) }.firstOrNull()

    private fun apply(r: Receipts.Report) {
        val keyId = Encoding.hex(r.forKeyId)
        val confirmed = HashSet<Pair<String, String>>()
        val displaced = HashSet<Pair<String, String>>()
        var reused: Long? = null
        var matched = 0
        for (s in r.stored) {
            val up = uploadBy("sha256 = ?", s.sealedSha256)
            for (d in s.deliveries) {
                val ok = d.result == "stored" || d.result == "duplicate"
                if (ok) confirmed += d.app to d.delivery
                val row = row(d.app, d.delivery)
                val sent = up?.let {
                    db.query("SELECT digest, counted FROM upload_deliveries WHERE name = ? AND app = ? AND delivery = ?",
                        it.name, d.app, d.delivery) { c -> c.getString(0) to (c.getInt(1) == 1) }.firstOrNull()
                }
                if (sent != null) {
                    if (sent.second) continue // the same entry again changes nothing
                    db.exec("UPDATE upload_deliveries SET counted = 1 WHERE name = ? AND app = ? AND delivery = ?",
                        up.name, d.app, d.delivery)
                    if (sent.first != d.digest) {
                        matched++ // the same delivery with another digest: a warning, never a confirmation
                        continue
                    }
                    if (row == null || row.digest != d.digest) continue
                    when (d.result) {
                        "stored", "duplicate" -> reused = confirm(row, s.received, d.seq, keyId, reused, displaced)
                        "conflict" -> conflict(row, s.received)
                        "rejected" -> {
                            matched++
                            strike(row, d.reason ?: Reasons.BAD_FILE)
                        }
                    }
                } else if (ok && row != null && row.digest == d.digest && row.state < Sealdrop.STATE_PICKED_UP) {
                    // From another upload: still confirms a delivery that isn't final yet.
                    reused = confirm(row, s.received, d.seq, keyId, reused, displaced)
                }
            }
        }
        for (x in r.rejected) {
            val up = (if (x.sealedSha256 != null) uploadBy("sha256 = ?", x.sealedSha256)
            else uploadBy("name = ? AND size = ?", x.name, x.size)) ?: continue
            if (up.rejected) continue
            db.exec("UPDATE uploads SET rejected = 1 WHERE name = ?", up.name)
            matched++
            wholeRejected(up.name, x.reason)
        }
        if (matched > 0) {
            val now = now()
            if (now - db.getLong(REJECTED_AT) > Warnings.WEEK) db.putLong(REJECTED_N, 0)
            db.putLong(REJECTED_N, db.getLong(REJECTED_N) + matched)
            db.putLong(REJECTED_AT, now)
        }

        val newest = r.time >= db.getLong(STATUS_TIME)
        if (newest) {
            val st = r.status
            db.putLong(STATUS_TIME, r.time)
            db.putLong(LAST_PICKUP, st.lastPickup ?: 0)
            db.putLong(LAST_BACKUP, st.lastBackup ?: 0)
            db.putLong(MAX_SEALED, st.maxSealed)
            db.put(COLLECTOR_WARNINGS, st.warnings.filter { it in KNOWN_WARNINGS }.joinToString(","))
            db.putLong(STATUS_SEQ, st.seq)
        }
        db.exec("INSERT INTO instances (time, instance) VALUES (?, ?)", r.time, Encoding.hex(r.status.instance))
        val two = twoCollectors(r.time) || (newest && r.status.vanished7d > 0)
        if (two) db.putLong(TWO_AT, now())
        if (now() - db.getLong(TWO_AT) >= Warnings.WEEK) {
            lost(keyId, if (newest) r.status.seq else null, reused, confirmed, displaced)
        }
    }

    /** Picked up: state 4 at `received`; the copy is dropped. Gives the lowest `seq` found reused. */
    private fun confirm(row: Row, received: Long, seq: Long?, keyId: String, reused: Long?, displaced: MutableSet<Pair<String, String>>): Long? {
        if (row.state >= Sealdrop.STATE_PICKED_UP) return reused
        db.exec("UPDATE deliveries SET state = 4, time = ?, final_at = ?, seq = ?, key_id = ?, upload = NULL WHERE app = ? AND delivery = ?",
            received, now(), seq, keyId, row.app, row.delivery)
        dropCopy(row)
        if (seq == null) return reused
        var lowest = reused
        db.query("SELECT app, delivery FROM seqs WHERE key_id = ? AND seq = ?", keyId, seq) { it.getString(0) to it.getString(1) }
            .firstOrNull()?.let { other ->
                if (other != row.app to row.delivery) {
                    displaced += other
                    lowest = minOf(lowest ?: seq, seq)
                }
            }
        db.exec("INSERT OR REPLACE INTO seqs (key_id, seq, app, delivery, at) VALUES (?, ?, ?, ?, ?)", keyId, seq, row.app, row.delivery, now())
        return lowest
    }

    private fun conflict(row: Row, received: Long) {
        if (row.state >= Sealdrop.STATE_PICKED_UP) return
        db.exec("UPDATE deliveries SET state = 5, time = ?, final_at = ?, upload = NULL WHERE app = ? AND delivery = ?",
            received, now(), row.app, row.delivery)
        dropCopy(row)
    }

    /** §6 step 5: after a strike the copy is checked; it goes again alone, or fails at the second strike. */
    private fun strike(row: Row, reason: String) {
        if (row.state >= Sealdrop.STATE_PICKED_UP) return
        if (!copyOk(row)) {
            Engine.error("strike: the copy failed its check; the app hands it over again")
            forget(row)
            return
        }
        val strikes = row.strikes + 1
        if (strikes >= 2) {
            db.exec("UPDATE deliveries SET state = 6, time = ?, final_at = ?, strikes = ?, reason = ?, upload = NULL WHERE app = ? AND delivery = ?",
                now(), now(), strikes, reason, row.app, row.delivery)
        } else {
            db.exec("UPDATE deliveries SET state = 1, strikes = ?, alone = 1, reason = ?, upload = NULL WHERE app = ? AND delivery = ?",
                strikes, reason, row.app, row.delivery)
        }
    }

    private fun wholeRejected(name: String, reason: String) {
        if (reason == Reasons.UNKNOWN_SENDER) return // under an old key after pairing again: sealed again already
        val sent = db.query("SELECT app, delivery, digest FROM upload_deliveries WHERE name = ?", name) {
            Triple(it.getString(0), it.getString(1), it.getString(2))
        }
        val rows = sent.mapNotNull { (app, delivery, digest) -> row(app, delivery)?.takeIf { it.digest == digest && it.state < 4 } }
        if (sent.size == 1) {
            rows.singleOrNull()?.let { strike(it, reason) } // an upload of only this delivery: a strike
            return
        }
        for (row in rows) {
            if (row.upload != name || row.state != Sealdrop.STATE_IN_INBOX) continue // already on its way again
            val whole = row.wholeRejects + if (reason == Reasons.DAMAGED || reason == Reasons.BAD_SIGNATURE) 1 else 0
            val alone = reason == Reasons.BAD_CONTENT || whole >= 2
            db.exec("UPDATE deliveries SET state = 1, upload = NULL, whole_rejects = ?, alone = MAX(alone, ?) WHERE app = ? AND delivery = ?",
                whole, if (alone) 1 else 0, row.app, row.delivery)
        }
    }

    /** The copy against the checksums the app gave. */
    private fun copyOk(row: Row): Boolean {
        val folder = File(engine.copies(), row.folder ?: return false)
        val files = db.query("SELECT idx, size, sha256 FROM files WHERE app = ? AND delivery = ?", row.app, row.delivery) {
            Triple(it.getInt(0), it.getLong(1), it.getString(2))
        }
        return files.isNotEmpty() && files.all { (idx, size, sha) ->
            val f = File(folder, idx.toString())
            f.isFile && f.length() == size && sha256(f) == sha
        }
    }

    private fun dropCopy(row: Row) {
        row.folder?.let { File(engine.copies(), it).deleteRecursively() }
        db.exec("UPDATE deliveries SET folder = NULL WHERE app = ? AND delivery = ?", row.app, row.delivery)
        db.exec("DELETE FROM files WHERE app = ? AND delivery = ?", row.app, row.delivery)
    }

    /** State 0: the app hands it over again. */
    private fun forget(row: Row) {
        dropCopy(row)
        db.exec("DELETE FROM deliveries WHERE app = ? AND delivery = ?", row.app, row.delivery)
    }

    /** Two instance IDs alternating (A, B, A) within 7 days of the collector's time. */
    private fun twoCollectors(time: Long): Boolean {
        val seen = db.query("SELECT instance FROM instances WHERE time >= ? ORDER BY time", time - Warnings.WEEK) { it.getString(0) }
        val runs = seen.fold(ArrayList<String>()) { acc, i -> acc.apply { if (lastOrNull() != i) add(i) } }
        return runs.size != runs.toSet().size
    }

    /** §6 step 6: deliveries the collector lost go back to state 0, so their apps hand them over again. */
    private fun lost(keyId: String, statusSeq: Long?, reused: Long?, confirmed: Set<Pair<String, String>>, displaced: Set<Pair<String, String>>) {
        var from = reused
        val highest = db.long("SELECT IFNULL(MAX(seq), 0) FROM seqs WHERE key_id = ?", keyId)
        if (statusSeq != null && statusSeq < highest) from = minOf(from ?: Long.MAX_VALUE, statusSeq + 1)
        val gone = LinkedHashSet<Pair<String, String>>()
        if (from != null) {
            db.query("SELECT app, delivery FROM seqs WHERE key_id = ? AND seq >= ?", keyId, from) { it.getString(0) to it.getString(1) }
                .filterTo(gone) { it !in confirmed }
        }
        displaced.filterTo(gone) { it !in confirmed }
        if (gone.isEmpty()) return
        val now = now()
        var count = 0
        for ((app, delivery) in gone) {
            db.exec("DELETE FROM seqs WHERE key_id = ? AND app = ? AND delivery = ?", keyId, app, delivery)
            val was = db.long("SELECT COUNT(*) FROM deliveries WHERE app = ? AND delivery = ? AND state = 4", app, delivery)
            if (was == 0L) continue
            db.exec("DELETE FROM deliveries WHERE app = ? AND delivery = ?", app, delivery)
            db.exec("INSERT OR REPLACE INTO lost (app, at) VALUES (?, ?)", app, now)
            count++
        }
        if (count == 0) return
        if (now - db.getLong(LOSS_AT) < Warnings.WEEK) db.putLong(TWO_AT, now) // a second loss within 7 days
        db.putLong(LOSS_AT, now)
        db.putLong(LOST_N, count.toLong())
        Engine.error("the collector lost $count deliveries; their apps hand them over again")
    }

    /** Uploads whose deliveries all have a final state are forgotten; so are `seq`s and final states after a year. */
    private fun tidy() {
        val now = now()
        db.tx {
            db.exec(
                "DELETE FROM uploads WHERE state = ? AND NOT EXISTS (SELECT 1 FROM upload_deliveries u JOIN deliveries d " +
                    "ON d.app = u.app AND d.delivery = u.delivery AND d.digest = u.digest WHERE u.name = uploads.name AND d.state < 4)",
                Outbox.UPLOAD_SENT,
            )
            db.exec("DELETE FROM upload_deliveries WHERE name NOT IN (SELECT name FROM uploads)")
            db.exec("DELETE FROM seqs WHERE at < ?", now - YEAR)
            db.exec("DELETE FROM deliveries WHERE state >= 4 AND final_at < ? AND folder IS NULL", now - YEAR - Warnings.WEEK * 5)
            db.exec("DELETE FROM instances WHERE time < ?", now - 30 * Warnings.DAY)
        }
    }

    companion object {
        const val STATUS_TIME = "status.time"
        const val LAST_PICKUP = "status.last_pickup"
        const val LAST_BACKUP = "status.last_backup"
        const val MAX_SEALED = "status.max_sealed"
        const val STATUS_SEQ = "status.seq"
        const val COLLECTOR_WARNINGS = "status.warnings"
        const val REJECTED_AT = "warn.rejected_at"
        const val REJECTED_N = "warn.rejected_n"
        const val TWO_AT = "warn.two_at"
        const val LOSS_AT = "warn.loss_at"
        const val LOST_N = "warn.lost_n"
        const val CANT_READ_AT = "warn.cant_read_at"
        const val UNPASSED_SINCE = "inbox.unpassed_since"
        const val LAST_PASS = "inbox.last_pass"
        private const val YEAR = 365 * Warnings.DAY
        val KNOWN_WARNINGS = setOf("disk-full", "inbox-flooded", "conflict", "storage-cap")

        /** Warning bit 9: a receipt opened but failed its checks, or none passed for 3 days although new ones came. */
        fun cantRead(engine: Engine): Boolean {
            val since = engine.db.getLong(UNPASSED_SINCE)
            return engine.db.get(CANT_READ_AT) != null || (since != 0L && engine.clock() - since > 3 * Warnings.DAY)
        }

        fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(1 shl 20)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    digest.update(buffer, 0, n)
                }
            }
            return Encoding.hex(digest.digest())
        }
    }
}
