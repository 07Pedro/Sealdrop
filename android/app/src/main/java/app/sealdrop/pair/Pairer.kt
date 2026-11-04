package app.sealdrop.pair

import app.sealdrop.Engine
import app.sealdrop.core.Ed25519Verifier
import app.sealdrop.core.Encoding
import app.sealdrop.core.FormatException
import app.sealdrop.core.Json
import app.sealdrop.core.Keys
import app.sealdrop.core.Manifests
import app.sealdrop.core.Pairing
import app.sealdrop.core.Reading
import app.sealdrop.core.Receipts
import app.sealdrop.core.Rejected
import app.sealdrop.core.Sealed
import app.sealdrop.core.Sizes
import app.sealdrop.core.Where
import app.sealdrop.send.Health
import app.sealdrop.send.Jobs
import app.sealdrop.send.Outbox
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException

/**
 * Pairing, the phone's side (PROTOCOL.md §7): checks the offer from the QR code, makes the new keys, shows the
 * fingerprint, sends the pairing request and waits for the paired receipt. The code from the QR code is only used for
 * the request's MAC and never kept.
 */
class Pairer(private val engine: Engine) {
    /** A QR code that can't be used, said in plain words. */
    class Problem(message: String) : Exception(message)

    enum class Poll { NONE, WAITING, PAIRED, EXPIRED }

    private val db = engine.db
    private val request get() = File(engine.files, "pair-request.sealed")

    /** §7 step 1. The scanned text is never logged. */
    fun read(text: String): Pairing.Offer {
        val parsed = try {
            Json.parse(text.toByteArray(Charsets.UTF_8))
        } catch (e: FormatException) {
            throw Problem("This isn't a Sealdrop pairing code.")
        }
        if (parsed !is Map<*, *> || parsed["type"] != "pair-offer") throw Problem("This isn't a Sealdrop pairing code.")
        return try {
            Pairing.checkOffer(parsed, engine.clock())
        } catch (e: FormatException) {
            if (e.message == "expired") throw Problem("This QR code has expired. Start pairing again on your server.")
            throw Problem("This pairing code isn't valid. Start pairing again on your server.")
        }
    }

    /** Steps 2 to 4: the keys, the fingerprint (returned), and the request, sent now or by [poll]. */
    fun start(offer: Pairing.Offer, label: String): String {
        if (!Manifests.goodLabel(label)) throw Problem("Choose a name of 1 to 40 characters.")
        stop()
        val old = engine.paired()
        val alias = engine.vault.newSigningKey()
        val signer = engine.vault.signer(alias)
        val opening = Keys.x25519Generate()
        val openPublic = Keys.x25519PublicBytes(opening.public)
        val replaces = old?.keyId
        val transcript = Pairing.macTranscript(offer.pairing, offer.collectorOpen, offer.collectorSign, signer.publicKey, openPublic, replaces)
        val mac = Pairing.pairMac(offer.code, offer.pairing, transcript)
        val manifest = Manifests.pairManifest(offer.pairing, signer.publicKey, openPublic, label, replaces, mac)
        val content = Manifests.contentPrefix(manifest)
        val sealed = ByteArrayOutputStream()
        Sealed.seal(sealed, Sizes.KIND_PAIR, ByteArrayInputStream(content), content.size.toLong(),
            Keys.x25519Public(offer.collectorOpen), signer, engine.clock())
        val fingerprint = Pairing.fingerprint(offer.pairing, offer.collectorOpen, offer.collectorSign, signer.publicKey, openPublic)
        val paired = Engine.Paired(signer.keyId, alias, fingerprint, label, 0, offer.collectorOpen, offer.collectorSign, offer.up, offer.ack)
        engine.updateSecrets {
            it["pending"] = linkedMapOf<String, Any?>(
                "paired" to Engine.pairedMap(paired), "pairing" to Encoding.b64url(offer.pairing), "expires" to offer.expires,
                "open" to Encoding.b64url(Keys.x25519PrivateBytes(opening.private)),
            ).apply { if (replaces != null) put("replaces", Encoding.hex(replaces)) }
        }
        val temporary = File(request.parentFile, request.name + ".tmp")
        temporary.writeBytes(sealed.toByteArray())
        temporary.renameTo(request)
        seen.clear()
        Engine.log("pairing started")
        engine.later.pairing()
        return fingerprint
    }

    /** Step 5: sends the request if it hasn't gone yet, then looks for the paired receipt. */
    fun poll(): Poll {
        val pending = engine.pending() ?: return Poll.NONE
        if (engine.clock() > pending.expires + AFTER_EXPIRY_MS) {
            stop()
            return Poll.EXPIRED
        }
        val paired = pending.paired
        if (request.exists()) {
            val data = request.readBytes()
            Health.call(engine) { engine.upStore(paired).put(Outbox.randomName(), data) }
            request.delete()
            Engine.log("pairing request sent")
        }
        val ack = engine.ackStore(paired)
        for (e in Health.call(engine) { ack.list() }) {
            if (e.name in seen) continue
            seen += e.name
            if (Sizes.lengthForSize(Where.ACK, e.size) == null) continue
            val data = Health.call(engine) { ack.get(e.name) }
            val receipt = try {
                val (_, manifest) = Reading.openReceipt(
                    data, listOf(pending.open), Ed25519Verifier(paired.collectorSign), Keys.keyId(paired.collectorSign),
                )
                Receipts.parse(manifest, listOf(paired.keyId))
            } catch (x: Rejected) {
                continue
            } catch (x: FormatException) {
                continue
            }
            if (receipt is Receipts.Paired && receipt.pairing.contentEquals(pending.pairing)) {
                complete(pending)
                return Poll.PAIRED
            }
        }
        return Poll.WAITING
    }

    /** [poll] for the background: network problems only mean "later". */
    fun pollQuietly(): Poll = try {
        poll()
    } catch (e: IOException) {
        Poll.WAITING
    } catch (e: Exception) {
        Engine.error("pairing: ${e.javaClass.simpleName}")
        Poll.WAITING
    }

    private fun complete(pending: Engine.Pending) {
        val now = engine.clock()
        val old = engine.paired()
        val paired = pending.paired
        engine.updateSecrets { s ->
            val kept = (s["opening"] as? List<*> ?: emptyList<Any>()).map { e ->
                LinkedHashMap(e as Map<*, *>).apply { if (this["until"] == 0L) this["until"] = now + KEEP_OLD_MS }
            }.filter { (it["until"] as Long) >= now }
            val p = s["pending"] as Map<*, *>
            s["opening"] = listOf(linkedMapOf<String, Any?>(
                "key_id" to Encoding.hex(paired.keyId), "private" to p["open"], "collector_sign" to Encoding.b64url(paired.collectorSign),
                "until" to 0L,
            )) + kept
            s["paired"] = Engine.pairedMap(Engine.Paired(paired.keyId, paired.signAlias, paired.fingerprint, paired.label, now,
                paired.collectorOpen, paired.collectorSign, paired.up, paired.ack))
            s.remove("pending")
        }
        if (old != null && old.signAlias != paired.signAlias) engine.vault.deleteKey(old.signAlias)
        // Everything not yet confirmed is sealed again for the new keys (§7), with new names.
        db.tx {
            for (name in db.query("SELECT name FROM uploads WHERE state = ?", Outbox.UPLOAD_SEALED) { it.getString(0) }) {
                File(engine.outbox(), name).delete()
                db.exec("DELETE FROM upload_deliveries WHERE name = ?", name)
                db.exec("DELETE FROM uploads WHERE name = ?", name)
            }
            db.exec("UPDATE deliveries SET state = 1, upload = NULL WHERE state BETWEEN 1 AND 3")
            for (key in listOf(Health.KEY_REFUSED, Health.STORAGE_CAP, Health.CLOCK)) db.put(key, null)
            db.put(app.sealdrop.send.Inbox.CANT_READ_AT, null)
            db.put(app.sealdrop.send.Inbox.UNPASSED_SINCE, null)
        }
        Engine.log("paired")
        engine.changed()
        engine.later.sendNow()
        engine.later.ensure()
    }

    /** Stops a running pairing (the codes differ, or the owner gave up): its new keys go. */
    fun stop() {
        val pending = engine.pending() ?: return
        engine.updateSecrets { it.remove("pending") }
        engine.vault.deleteKey(pending.paired.signAlias)
        request.delete()
        Engine.log("pairing stopped")
    }

    /** Unpairing: every key and secret, and the copies the collector hasn't confirmed (§9.4). Approvals stay. */
    fun unpair() {
        stop()
        engine.later.cancelAll()
        engine.vault.wipe()
        engine.forgetSecrets()
        db.tx {
            db.exec("DELETE FROM deliveries WHERE state BETWEEN 1 AND 3")
            db.exec("UPDATE deliveries SET folder = NULL")
            db.exec("DELETE FROM files")
            db.exec("DELETE FROM uploads")
            db.exec("DELETE FROM upload_deliveries")
            db.exec("DELETE FROM receipts")
            db.exec("DELETE FROM holds")
            db.exec("DELETE FROM kv WHERE k NOT LIKE 'settings.%'")
        }
        engine.copies().deleteRecursively()
        engine.outbox().deleteRecursively()
        Engine.log("unpaired")
        engine.changed()
    }

    companion object {
        const val POLL_MS = 30_000L
        private const val AFTER_EXPIRY_MS = 10 * 60_000L
        private const val KEEP_OLD_MS = 60 * 86_400_000L

        /** Names in `ack/` already looked at during this pairing. */
        private val seen = java.util.Collections.synchronizedSet(HashSet<String>())
    }
}
