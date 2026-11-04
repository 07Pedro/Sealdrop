package app.sealdrop.send

import app.sealdrop.core.BytesSource
import app.sealdrop.core.Encoding
import app.sealdrop.core.Json
import app.sealdrop.core.Keys
import app.sealdrop.core.Manifests
import app.sealdrop.core.P256Verifier
import app.sealdrop.core.Pairing
import app.sealdrop.core.Reading
import app.sealdrop.core.Rejected
import app.sealdrop.core.Sealed
import app.sealdrop.core.SealedFile
import app.sealdrop.core.Signer
import app.sealdrop.core.Sizes
import app.sealdrop.core.Verifier
import app.sealdrop.net.Listed
import app.sealdrop.net.S3Error
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyPairGenerator
import java.security.Signature

/** `up/` in memory, with faults to inject. */
class FakeUp : UpStore {
    val objects = LinkedHashMap<String, ByteArray>()
    val multiparts = HashMap<String, MutableMap<Int, ByteArray>>()
    val calls = ArrayList<String>()

    /** Asked before every request: throw to make it fail. */
    var fault: (String) -> Unit = {}

    override fun put(name: String, body: ByteArray) {
        calls += "put"
        fault("put")
        objects[name] = body
    }

    override fun createMultipart(name: String): String {
        calls += "create"
        fault("create")
        return Encoding.hex(Encoding.randomBytes(8)).also { multiparts[it] = HashMap() }
    }

    override fun uploadPart(name: String, uploadId: String, number: Int, body: ByteArray): String {
        calls += "part$number"
        fault("part$number")
        val parts = multiparts[uploadId] ?: throw S3Error(404, "NoSuchUpload", "")
        parts[number] = body
        return "\"" + Encoding.hex(Encoding.sha256(body)).take(32) + "\""
    }

    override fun completeMultipart(name: String, uploadId: String, etags: List<String>) {
        calls += "complete"
        fault("complete")
        val parts = multiparts.remove(uploadId) ?: throw S3Error(404, "NoSuchUpload", "")
        val out = ByteArrayOutputStream()
        for (i in 1..etags.size) out.write(parts.getValue(i))
        objects[name] = out.toByteArray()
    }

    override fun abortMultipart(name: String, uploadId: String) {
        multiparts.remove(uploadId)
    }
}

/** `ack/` in memory. */
class FakeAck : AckStore {
    val objects = LinkedHashMap<String, ByteArray>()
    var fault: (String) -> Unit = {}

    override fun list(): List<Listed> {
        fault("list")
        return objects.map { (k, v) -> Listed(k, "\"x\"", v.size.toLong()) }
    }

    override fun get(name: String): ByteArray {
        fault("get")
        return objects.getValue(name)
    }
}

/** An Ed25519 signer, as the collector signs; here only to write receipts in the tests. */
class Ed25519TestSigner : Signer {
    private val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    override val publicKey: ByteArray = pair.public.encoded.copyOfRange(12, 44) // the raw key after the SPKI prefix

    override fun sign(statement: ByteArray): ByteArray = Signature.getInstance("Ed25519").run {
        initSign(pair.private)
        update(statement)
        sign()
    }
}

/**
 * A stand-in collector for the phone's tests: pairs, picks up `up/` as PROTOCOL.md §10 says (briefly), and writes
 * receipts. The real collector (Python) is tested on its own and against the phone end to end.
 */
class FakeCollector(private val up: FakeUp, private val ack: FakeAck, private val clock: () -> Long) {
    class Sender(val keyId: ByteArray, val sign: ByteArray, val open: ByteArray)

    val opening = Keys.x25519Generate()
    val openPublic: ByteArray = Keys.x25519PublicBytes(opening.public)
    var signer: Signer = Ed25519TestSigner()
    var instance: ByteArray = Encoding.randomBytes(16)
    val senders = LinkedHashMap<String, Sender>()
    val stored = HashMap<Pair<String, String>, Pair<String, Long>>()
    var seq = 0L
    var maxSealed = Sizes.DEFAULT_MAX_SEALED
    var warnings = listOf<String>()
    var vanished = 0L

    /** Per-delivery results to force: (app, delivery) → a reason. */
    val rejectDelivery = HashMap<Pair<String, String>, String>()

    private var pairing = Encoding.randomBytes(16)
    private var code = Encoding.randomBytes(16)

    fun offerText(endpoint: String = "https://storage.example.org"): String {
        pairing = Encoding.randomBytes(16)
        code = Encoding.randomBytes(16)
        val key = { mapOf("id" to "key" + Encoding.hex(Encoding.randomBytes(4)), "secret" to Encoding.hex(Encoding.randomBytes(16))) }
        return String(Json.write(linkedMapOf(
            "sealdrop" to 1L, "type" to "pair-offer", "pairing" to Encoding.b64url(pairing), "expires" to clock() + 600_000,
            "storage" to mapOf(
                "up" to mapOf("endpoint" to endpoint, "region" to "test-region-1", "bucket" to "test-bucket", "prefix" to "up/", "key" to key()),
                "ack" to mapOf("prefix" to "ack/", "key" to key()),
            ),
            "collector_open" to Encoding.b64url(openPublic), "collector_sign" to Encoding.b64url(signer.publicKey),
            "code" to Encoding.b64url(code),
        )))
    }

    /** The `pair` command: takes the waiting request, answers with the paired receipt. Gives the fingerprint. */
    fun pair(): String {
        val (name, data) = up.objects.entries.first { it.value.size == 262_376 }
        val opened = Reading.openPairRequest(BytesSource(data), listOf(opening.private))
        val r = opened.request
        val transcript = Pairing.macTranscript(pairing, openPublic, signer.publicKey, r.senderSign, r.senderOpen, r.replaces)
        check(Pairing.macOk(Pairing.pairMac(code, pairing, transcript), r.mac)) { "wrong MAC" }
        val keyId = Keys.keyId(r.senderSign)
        senders[Encoding.hex(keyId)] = Sender(keyId, r.senderSign, r.senderOpen)
        up.objects.remove(name)
        receipt(senders.getValue(Encoding.hex(keyId)), linkedMapOf(
            "v" to 1L, "type" to "paired", "for" to Encoding.hex(keyId), "pairing" to Encoding.b64url(pairing), "time" to clock(),
        ))
        return Pairing.fingerprint(pairing, openPublic, signer.publicKey, r.senderSign, r.senderOpen)
    }

    /** A regular run: every upload is handled and deleted, then each sender gets one receipt. */
    fun run(only: Sender? = null) {
        val storedEntries = HashMap<String, MutableList<Map<String, Any?>>>()
        val rejected = ArrayList<Map<String, Any?>>()
        val verifiers: Map<String, Verifier> = senders.mapValues { P256Verifier(it.value.sign) }
        for ((name, data) in up.objects.toList()) {
            up.objects.remove(name)
            val headerOpens = try {
                Sealed.checkListedSize(app.sealdrop.core.Where.UP, data.size.toLong(), maxSealed)
                SealedFile(BytesSource(data)).openHeader(listOf(opening.private), Sealed.INFO_TO_COLLECTOR, listOf(1, 2))
                true
            } catch (e: Rejected) {
                false
            }
            try {
                val sealed = Reading.openUpload(BytesSource(data), listOf(opening.private), verifiers, maxSealed)
                val writer = Encoding.hex(sealed.header!!.writerKeyId)
                val results = Reading.checkDeliveries(sealed).map { v ->
                    val key = v.delivery.app to v.delivery.delivery
                    val forced = rejectDelivery.remove(key)
                    val known = stored[key]
                    val entry = linkedMapOf<String, Any?>("app" to key.first, "delivery" to key.second, "digest" to v.delivery.digest)
                    when {
                        forced != null || !v.ok -> entry.apply { put("result", "rejected"); put("reason", forced ?: v.reason) }
                        known == null -> {
                            seq++
                            stored[key] = v.delivery.digest to seq
                            entry.apply { put("result", "stored"); put("seq", seq) }
                        }
                        known.first == v.delivery.digest -> entry.apply { put("result", "duplicate"); put("seq", known.second) }
                        else -> entry.apply { put("result", "conflict") }
                    }
                }
                storedEntries.getOrPut(writer) { ArrayList() } += linkedMapOf(
                    "message" to Encoding.hex(sealed.header!!.messageId), "sealed_sha256" to Encoding.hex(Encoding.sha256(data)),
                    "received" to clock(), "deliveries" to results,
                )
            } catch (e: Rejected) {
                rejected += linkedMapOf<String, Any?>("name" to name).apply {
                    if (headerOpens) put("sealed_sha256", Encoding.hex(Encoding.sha256(data)))
                    put("size", data.size.toLong())
                    put("reason", e.reason)
                    put("at", clock())
                }
            }
        }
        for (s in if (only != null) listOf(only) else senders.values) {
            report(s, storedEntries[Encoding.hex(s.keyId)] ?: emptyList(), rejected)
        }
    }

    /** A receipt for [s]; [statusSeq] can be lowered to play a collector restored from an old backup. */
    fun report(s: Sender, stored: List<Map<String, Any?>>, rejected: List<Map<String, Any?>> = emptyList(), statusSeq: Long = seq) {
        receipt(s, linkedMapOf(
            "v" to 1L, "type" to "receipt", "for" to Encoding.hex(s.keyId), "time" to clock(), "stored" to stored, "rejected" to rejected,
            "status" to linkedMapOf(
                "collector" to "1.0.0", "instance" to Encoding.hex(instance), "seq" to statusSeq, "last_pickup" to clock(),
                "last_backup" to null, "free_bytes" to (1L shl 40), "max_sealed" to maxSealed, "warnings" to warnings,
                "rejected_7d" to rejected.size.toLong(), "rejected_more" to 0L, "vanished_7d" to vanished,
            ),
        ))
    }

    fun receipt(s: Sender, manifest: Map<String, Any?>, by: Signer = signer) {
        val content = Manifests.contentPrefix(manifest)
        val out = ByteArrayOutputStream()
        Sealed.seal(out, Sizes.KIND_RECEIPT, ByteArrayInputStream(content), content.size.toLong(), Keys.x25519Public(s.open), by, clock())
        ack.objects[Encoding.base32(Encoding.randomBytes(20)).lowercase()] = out.toByteArray()
    }
}
