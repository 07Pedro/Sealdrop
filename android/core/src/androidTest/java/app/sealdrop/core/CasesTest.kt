package app.sealdrop.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream

/**
 * The committed test files (testvectors/, made by the Python side): every case opens or fails exactly as cases.json
 * says, with the same reason.
 */
@RunWith(AndroidJUnit4::class)
class CasesTest {
    private val senders = mapOf(Encoding.hex(Keys.keyId(TestFiles.public("sender_sign"))) to P256Verifier(TestFiles.public("sender_sign")))
    private val collectorKeys = listOf(TestFiles.x25519("collector_open"), TestFiles.x25519("collector_open_retired"))

    private class Opened(val header: Header, val verdicts: List<Verdict>? = null, val content: ByteArray? = null,
                         val manifest: Map<*, *>? = null, val request: PairRequest? = null)

    private fun read(case: Map<*, *>, data: ByteArray): Opened {
        if (case["reader"] == "sender") {
            val collector = TestFiles.public("collector_sign")
            val (header, manifest) = Reading.openReceipt(data, listOf(TestFiles.x25519("sender_open")),
                Ed25519Verifier(collector), Keys.keyId(collector))
            Receipts.parse(manifest, listOf(Keys.keyId(TestFiles.public("sender_sign")))) // the phone's own check of the form
            return Opened(header, manifest = manifest.obj())
        }
        if (case["file"].str().startsWith("pair-request")) {
            val opened = Reading.openPairRequest(BytesSource(data), collectorKeys)
            return Opened(opened.header, manifest = opened.manifest, request = opened.request)
        }
        val maxSealed = case["max_sealed"]?.long() ?: Sizes.DEFAULT_MAX_SEALED
        val sealed = Reading.openUpload(BytesSource(data), collectorKeys, senders, maxSealed)
        val content = ByteArrayOutputStream()
        Reading.openUpload(BytesSource(data), collectorKeys, senders).content().use { it.copyTo(content) }
        return Opened(sealed.header!!, verdicts = Reading.checkDeliveries(sealed), content = content.toByteArray())
    }

    @Test
    fun everyCase() {
        assertTrue(TestFiles.cases.size > 30)
        for (case in TestFiles.cases) {
            val id = case["id"].str()
            val data = TestFiles.mutate(TestFiles.bytes("files/${case["file"]}"), case["mutations"]?.list().orEmpty())
            if (case["expect"] == "reject") {
                try {
                    read(case, data)
                    fail("$id: opened, but should be rejected (${case["reason"]})")
                } catch (e: Rejected) {
                    assertEquals("$id: ${e.detail}", case["reason"], e.reason)
                }
                continue
            }
            val got = read(case, data)
            assertEquals(id, case["sealed_sha256"], TestFiles.sha256Hex(data))
            assertEquals(id, case["size"], data.size.toLong())
            val expected = case["header"].obj()
            val header = got.header
            assertEquals(id, listOf(expected["kind"], expected["created"], expected["n"], expected["message_id"], expected["writer_key_id"]),
                listOf(header.kind.toLong(), header.created, header.n, Encoding.hex(header.messageId), Encoding.hex(header.writerKeyId)))
            case["content_sha256"]?.let { assertEquals(id, it, TestFiles.sha256Hex(got.content!!)) }
            case["deliveries"]?.let { deliveries ->
                val want = deliveries.list().map { d ->
                    d as Map<*, *>
                    listOf("app", "delivery", "digest", "result", "reason").filter { it in d }.associateWith { d[it] }
                }
                val have = got.verdicts!!.map { v ->
                    mapOf("app" to v.delivery.app, "delivery" to v.delivery.delivery, "digest" to v.delivery.digest) +
                        if (v.ok) mapOf("result" to "stored") else mapOf("result" to "rejected", "reason" to v.reason)
                }
                assertEquals(id, want, have)
            }
            case["manifest"]?.let { assertEquals(id, it, got.manifest) }
            if ("pair_check" in case) checkPairing(id, case, got.request!!)
        }
    }

    private fun checkPairing(id: String, case: Map<*, *>, request: PairRequest) {
        assertEquals(id, case["pair_check"], Manifests.checkPairNames(request))
        val offer = TestFiles.vectors["pairing"].obj()["offer"].obj()
        val transcript = Pairing.macTranscript(request.pairing, TestFiles.public("collector_open"), TestFiles.public("collector_sign"),
            request.senderSign, request.senderOpen, request.replaces)
        val mac = Pairing.pairMac(Encoding.unb64url(offer["code"]), request.pairing, transcript)
        assertTrue(id, Pairing.macOk(mac, request.mac))
        assertEquals(id, case["fingerprint"], Pairing.fingerprint(request.pairing, TestFiles.public("collector_open"),
            TestFiles.public("collector_sign"), request.senderSign, request.senderOpen))
    }

    @Test
    fun theManifestsAreWrittenByteForByteAsInPython() {
        // The pairing request's content is the Python-written manifest: Kotlin writes the same bytes for it.
        val case = TestFiles.cases.first { it["id"] == "pair-request" }
        val opened = Reading.openPairRequest(BytesSource(TestFiles.bytes("files/${case["file"]}")), collectorKeys)
        val sealed = SealedFile(BytesSource(TestFiles.bytes("files/${case["file"]}")))
        sealed.openHeader(collectorKeys, Sealed.INFO_TO_COLLECTOR, listOf(Sizes.KIND_PAIR))
        val r = opened.request
        val manifest = Manifests.pairManifest(r.pairing, r.senderSign, r.senderOpen, r.label, r.replaces, r.mac)
        assertEquals(Encoding.hex(sealed.readContent()), Encoding.hex(Manifests.contentPrefix(manifest)))
    }
}
