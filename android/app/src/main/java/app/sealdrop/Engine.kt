package app.sealdrop

import android.content.Context
import android.util.Log
import app.sealdrop.core.Ed25519Verifier
import app.sealdrop.core.Encoding
import app.sealdrop.core.Keys
import app.sealdrop.core.Pairing
import app.sealdrop.core.Signer
import app.sealdrop.data.Db
import app.sealdrop.data.Vault
import app.sealdrop.net.Gate
import app.sealdrop.net.S3
import app.sealdrop.send.AckStore
import app.sealdrop.send.S3Ack
import app.sealdrop.send.S3Up
import app.sealdrop.send.UpStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.security.PrivateKey

/**
 * Sealdrop's parts in one place: the database, the vault, the network gate, and the pairing (the current one and a
 * running one). One per process.
 */
class Engine(val context: Context, val db: Db, val vault: Vault, val clock: () -> Long = System::currentTimeMillis) {
    /** One pairing: the collector's keys, this phone's keys for it, and the two locations with their keys. */
    class Paired(
        val keyId: ByteArray, val signAlias: String, val fingerprint: String, val label: String, val pairedAt: Long,
        val collectorOpen: ByteArray, val collectorSign: ByteArray, val up: Pairing.Location, val ack: Pairing.Location,
    ) {
        val collectorKeyId: ByteArray get() = Keys.keyId(collectorSign)
        override fun toString() = "Paired(${Encoding.hex(keyId).take(8)}…)"
    }

    /** A pairing waiting for its paired receipt (§7, step 5), with the new opening key. */
    class Pending(val paired: Paired, val pairing: ByteArray, val expires: Long, val replaces: ByteArray?, val open: PrivateKey)

    /** An opening key still kept, with the key ID and collector it was paired with (to read its receipts). */
    class Opening(val keyId: ByteArray, val private: PrivateKey, val collectorSign: ByteArray)

    val gate = Gate { hosts }
    val files: File get() = context.filesDir

    private val _changes = MutableStateFlow(0L)

    /** Bumped whenever something the screens show has changed. */
    val changes: StateFlow<Long> get() = _changes

    fun changed() {
        _changes.value = _changes.value + 1
    }

    @Volatile private var cache: Map<String, Any?>? = null
    @Volatile private var hosts: Set<Gate.Host> = emptySet()

    // --- secrets ----------------------------------------------------------------------------------------------------

    /** The vault's content; Vault.Broken if it can't be opened (then: pair again). */
    fun secrets(): Map<String, Any?> = cache ?: vault.read().also { remember(it) }

    fun updateSecrets(change: (MutableMap<String, Any?>) -> Unit) {
        synchronized(vault) {
            vault.update(change)
            remember(vault.read())
        }
        changed()
    }

    /** After unpairing: nothing cached, no host allowed. */
    fun forgetSecrets() {
        cache = null
        hosts = emptySet()
    }

    private fun remember(secrets: Map<String, Any?>) {
        cache = secrets
        hosts = listOfNotNull(secrets["paired"], (secrets["pending"] as? Map<*, *>)?.get("paired"))
            .flatMap { p -> listOf("up", "ack").map { Gate.hostOf(((p as Map<*, *>)[it] as Map<*, *>)["endpoint"] as String) } }
            .toSet()
    }

    fun paired(): Paired? = try {
        (secrets()["paired"] as? Map<*, *>)?.let(::pairedOf)
    } catch (e: Vault.Broken) {
        null
    }

    fun pending(): Pending? = try {
        (secrets()["pending"] as? Map<*, *>)?.let { p ->
            Pending(pairedOf(p["paired"] as Map<*, *>), Encoding.unb64url(p["pairing"]), p["expires"] as Long,
                (p["replaces"] as? String)?.let { Encoding.unhex(it, 32) }, Keys.x25519Private(Encoding.unb64url(p["open"], 32)))
        }
    } catch (e: Vault.Broken) {
        null
    }

    /** True if the keys can't be used: Sealdrop sends nothing and asks to pair again (§9.4). */
    fun broken(): Boolean {
        val paired = try {
            (secrets()["paired"] as? Map<*, *>)?.let(::pairedOf)
        } catch (e: Vault.Broken) {
            return true
        } ?: return false
        return try {
            vault.signer(paired.signAlias)
            false
        } catch (e: Vault.Broken) {
            true
        }
    }

    fun signer(paired: Paired): Signer = vault.signer(paired.signAlias)

    /** Every opening key still kept: the current one first, then older ones (for 60 days after pairing again). */
    fun openings(): List<Opening> {
        val now = clock()
        return (secrets()["opening"] as? List<*> ?: emptyList<Any>()).mapNotNull { e ->
            e as Map<*, *>
            val until = e["until"] as Long
            if (until != 0L && until < now) null
            else Opening(Encoding.unhex(e["key_id"], 32), Keys.x25519Private(Encoding.unb64url(e["private"], 32)),
                Encoding.unb64url(e["collector_sign"], 32))
        }
    }

    fun ownKeyIds(): List<ByteArray> = openings().map { it.keyId }

    fun collectorVerifier(paired: Paired) = Ed25519Verifier(paired.collectorSign)

    private fun client(l: Pairing.Location) = S3(l.endpoint, l.region, l.keyId, l.secret, gate, clock)

    /** The storage, through the gate. Tests put fakes here. */
    var upStore: (Paired) -> UpStore = { S3Up(client(it.up), it.up) }
    var ackStore: (Paired) -> AckStore = { S3Ack(client(it.ack), it.ack) }

    // --- folders ----------------------------------------------------------------------------------------------------

    /** Copies of committed deliveries: one folder each, files by their number. */
    fun copies(): File = File(files, "copies").apply { mkdirs() }

    /** Files of handles still open. */
    fun incoming(): File = File(files, "incoming").apply { mkdirs() }

    /** Sealed bundles until their upload is complete. */
    fun outbox(): File = File(files, "outbox").apply { mkdirs() }

    companion object {
        const val TAG = "Sealdrop"

        @Volatile private var instance: Engine? = null

        fun get(context: Context): Engine = instance ?: synchronized(this) {
            instance ?: Engine(context.applicationContext, Db(context.applicationContext), Vault(context.applicationContext))
                .also { instance = it; it.startUp() }
        }

        /** For tests: a fresh engine (after clearing the app's data). */
        fun reset() {
            instance = null
        }

        fun pairedOf(p: Map<*, *>): Paired {
            fun location(m: Map<*, *>) = Pairing.Location(
                m["endpoint"] as String, m["region"] as String, m["bucket"] as String, m["prefix"] as String,
                m["id"] as String, m["secret"] as String,
            )
            return Paired(
                Encoding.unhex(p["key_id"], 32), p["sign_alias"] as String, p["fingerprint"] as String, p["label"] as String,
                p["paired_at"] as Long, Encoding.unb64url(p["collector_open"], 32), Encoding.unb64url(p["collector_sign"], 32),
                location(p["up"] as Map<*, *>), location(p["ack"] as Map<*, *>),
            )
        }

        fun pairedMap(p: Paired): Map<String, Any?> {
            fun location(l: Pairing.Location) = linkedMapOf(
                "endpoint" to l.endpoint, "region" to l.region, "bucket" to l.bucket, "prefix" to l.prefix,
                "id" to l.keyId, "secret" to l.secret,
            )
            return linkedMapOf(
                "key_id" to Encoding.hex(p.keyId), "sign_alias" to p.signAlias, "fingerprint" to p.fingerprint,
                "label" to p.label, "paired_at" to p.pairedAt, "collector_open" to Encoding.b64url(p.collectorOpen),
                "collector_sign" to Encoding.b64url(p.collectorSign), "up" to location(p.up), "ack" to location(p.ack),
            )
        }

        /** Logs carry only message IDs, sizes, result codes and reasons (§9.4); release builds only errors. */
        fun log(text: String) {
            if (BuildConfig.DEBUG) Log.i(TAG, text)
        }

        fun error(text: String) = Log.e(TAG, text)
    }

    /** At process start: handles end with the process (§9.1), so their copies go. */
    private fun startUp() {
        incoming().listFiles()?.forEach { it.deleteRecursively() }
    }
}
