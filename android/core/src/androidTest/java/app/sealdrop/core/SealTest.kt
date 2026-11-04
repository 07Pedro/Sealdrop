package app.sealdrop.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.SequenceInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/** Kotlin seals, Kotlin opens: piece boundaries, streaming from disk, receipts, pairing requests, the Keystore. */
@RunWith(AndroidJUnit4::class)
class SealTest {
    private val sender = TestFiles.p256Signer("sender_sign")
    private val collectorOpen = Keys.x25519Public(TestFiles.public("collector_open"))
    private val collectorKeys = listOf(TestFiles.x25519("collector_open"))
    private val senders = mapOf(Encoding.hex(sender.keyId) to P256Verifier(sender.publicKey))
    private val created = 1789285265000L

    private fun bytes(size: Int, seed: Int) = ByteArray(size) { (it * 31 + seed).toByte() }

    /** Content and the manifest's deliveries for files of the given sizes, one delivery each. */
    private fun bundle(vararg sizes: Int): Pair<ByteArray, List<Delivery>> {
        val blobs = sizes.mapIndexed { i, size -> bytes(size, i) }
        val deliveries = blobs.mapIndexed { i, blob ->
            Delivery("org.example.tracker", "d-$i", created, listOf(FileEntry("data/f$i.bin", blob.size.toLong(), TestFiles.sha256Hex(blob))))
        }
        return Manifests.contentPrefix(Manifests.bundleManifest(deliveries)) + blobs.fold(ByteArray(0)) { a, b -> a + b } to deliveries
    }

    private fun seal(kind: Int, content: ByteArray, signer: Signer = sender, reader: java.security.PublicKey = collectorOpen): Pair<ByteArray, SealResult> {
        val out = ByteArrayOutputStream()
        val result = Sealed.seal(out, kind, ByteArrayInputStream(content), content.size.toLong(), reader, signer, created)
        return out.toByteArray() to result
    }

    @Test
    fun pieceBoundaries() {
        // One piece; exactly 1 MiB of padded length; two pieces; exactly 4 MiB; above 4 MiB (pieces of padding only).
        for (size in listOf(10, Sizes.PIECE - 1000, Sizes.PIECE, 4 * Sizes.PIECE - 600, 4 * Sizes.PIECE + 5)) {
            val (content, deliveries) = bundle(size)
            val (data, result) = seal(Sizes.KIND_BUNDLE, content)
            assertEquals("$size", result.size, data.size.toLong())
            assertEquals("$size", Sizes.sealedSize(Sizes.paddedLength(1, content.size.toLong())), data.size.toLong())
            assertEquals(result.sha256, TestFiles.sha256Hex(data))
            val sealed = Reading.openUpload(BytesSource(data), collectorKeys, senders)
            val verdicts = Reading.checkDeliveries(sealed)
            assertEquals(deliveries.map { it.digest }, verdicts.map { it.delivery.digest })
            assertTrue(verdicts.all { it.ok })
            val opened = Reading.openUpload(BytesSource(data), collectorKeys, senders).content().readBytes()
            assertArrayEquals("$size", content, opened)
        }
    }

    @Test
    fun bundleStreamsFromDisk() {
        val dir = File(InstrumentationRegistry.getInstrumentation().context.cacheDir, "seal-test").apply { mkdirs() }
        try {
            val blobs = listOf(bytes(3 * Sizes.PIECE + 7, 1), bytes(1234, 2))
            val files = blobs.mapIndexed { i, b -> File(dir, "f$i").apply { writeBytes(b) } }
            val delivery = Delivery("org.example.tracker", "d-1", created,
                files.mapIndexed { i, f -> FileEntry("f$i", f.length(), TestFiles.sha256Hex(blobs[i])) })
            val prefix = Manifests.contentPrefix(Manifests.bundleManifest(listOf(delivery)))
            val n = prefix.size + files.sumOf { it.length() }
            val target = File(dir, "bundle.sealed")
            val streams = listOf(ByteArrayInputStream(prefix)) + files.map { it.inputStream() }
            target.outputStream().buffered().use { out ->
                SequenceInputStream(java.util.Collections.enumeration(streams)).use { Sealed.seal(out, 1, it, n, collectorOpen, sender, created) }
            }
            val written = ByteArrayOutputStream()
            FileSource(target).use { source ->
                val sealed = Reading.openUpload(source, collectorKeys, senders)
                val verdicts = Reading.checkDeliveries(sealed) { _, _ -> { b, off, len -> written.write(b, off, len) } }
                assertTrue(verdicts.single().ok)
            }
            assertArrayEquals(blobs[0] + blobs[1], written.toByteArray())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun rejectedDeliveryNeverReachesTheSink() {
        val blob = bytes(100, 3)
        val good = Delivery("org.example.tracker", "d-1", created, listOf(FileEntry("a", 100, TestFiles.sha256Hex(blob))))
        val bad = Delivery("../x", "d-2", created, listOf(FileEntry("a", 100, TestFiles.sha256Hex(blob))))
        val content = Manifests.contentPrefix(Manifests.bundleManifest(listOf(good, bad))) + blob + blob
        val sealed = Reading.openUpload(BytesSource(seal(1, content).first), collectorKeys, senders)
        val asked = mutableListOf<String>()
        val verdicts = Reading.checkDeliveries(sealed) { d, _ -> asked.add(d.delivery); null }
        assertEquals(listOf(true, false), verdicts.map { it.ok })
        assertEquals(Reasons.BAD_NAME, verdicts[1].reason)
        assertEquals(listOf("d-1"), asked)
    }

    @Test
    fun receiptRoundTrip() {
        val collector = TestFiles.collectorSigner()
        val manifest = linkedMapOf("v" to 1L, "type" to "paired", "for" to Encoding.hex(sender.keyId),
            "pairing" to Encoding.b64url(ByteArray(16)), "time" to created)
        val (data, _) = seal(Sizes.KIND_RECEIPT, Manifests.contentPrefix(manifest), collector, Keys.x25519Public(TestFiles.public("sender_open")))
        assertEquals(4328, data.size)
        val (header, opened) = Reading.openReceipt(data, listOf(TestFiles.x25519("sender_open")), Ed25519Verifier(collector.publicKey), collector.keyId)
        assertEquals(Sizes.KIND_RECEIPT, header.kind)
        assertTrue(Receipts.parse(opened, listOf(sender.keyId)) is Receipts.Paired)
    }

    @Test
    fun aSenderSignatureNeverPassesAsTheCollectors() {
        // A receipt signed by the phone's key fails even if its key ID claims to be the collector's.
        val impostor = object : Signer by sender {
            override val keyId = TestFiles.collectorSigner().keyId
        }
        val manifest = linkedMapOf("v" to 1L, "type" to "paired", "for" to Encoding.hex(sender.keyId),
            "pairing" to Encoding.b64url(ByteArray(16)), "time" to created)
        val (data, _) = seal(Sizes.KIND_RECEIPT, Manifests.contentPrefix(manifest), impostor, Keys.x25519Public(TestFiles.public("sender_open")))
        val collector = TestFiles.collectorSigner()
        val e = assertThrows(Rejected::class.java) {
            Reading.openReceipt(data, listOf(TestFiles.x25519("sender_open")), Ed25519Verifier(collector.publicKey), collector.keyId)
        }
        assertEquals(Reasons.BAD_SIGNATURE, e.reason)
    }

    @Test
    fun pairingRequestFromThePhone() {
        val offer = Pairing.checkOffer(TestFiles.vectors["pairing"].obj()["offer"], 0)
        val senderOpen = TestFiles.public("sender_open")
        val transcript = Pairing.macTranscript(offer.pairing, offer.collectorOpen, offer.collectorSign, sender.publicKey, senderOpen, null)
        val manifest = Manifests.pairManifest(offer.pairing, sender.publicKey, senderOpen, "Phone", null,
            Pairing.pairMac(offer.code, offer.pairing, transcript))
        val (data, _) = seal(Sizes.KIND_PAIR, Manifests.contentPrefix(manifest), reader = Keys.x25519Public(offer.collectorOpen))
        assertEquals(262376, data.size)
        val opened = Reading.openPairRequest(BytesSource(data), collectorKeys)
        assertTrue(Pairing.macOk(Pairing.pairMac(offer.code, offer.pairing, transcript), opened.request.mac))
        // A regular run turns it away.
        assertEquals(Reasons.UNKNOWN_SENDER, assertThrows(Rejected::class.java) { Reading.openUpload(BytesSource(data), collectorKeys, senders) }.reason)
    }

    @Test
    fun orderOfChecks() {
        val (content, _) = bundle(10)
        val (data, _) = seal(1, content)
        val reason = { d: ByteArray -> assertThrows(Rejected::class.java) { Reading.openUpload(BytesSource(d), collectorKeys, senders) }.reason }
        assertEquals(Reasons.DAMAGED, reason(data.copyOf(data.size - 1)))
        assertEquals(Reasons.TOO_BIG, assertThrows(Rejected::class.java) {
            Reading.openUpload(BytesSource(data), collectorKeys, senders, maxSealed = 100_000)
        }.reason)
        assertEquals(Reasons.UNKNOWN_SENDER, assertThrows(Rejected::class.java) { Reading.openUpload(BytesSource(data), collectorKeys, emptyMap()) }.reason)
        val flipped = data.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertEquals(Reasons.BAD_SIGNATURE, reason(flipped))
        assertEquals(Reasons.DAMAGED, assertThrows(Rejected::class.java) {
            Reading.openUpload(BytesSource(data), listOf(TestFiles.x25519("stranger_open")), senders)
        }.reason)
    }

    @Test
    fun contentMustMatchN() {
        val out = ByteArrayOutputStream()
        assertThrows(IllegalArgumentException::class.java) { Sealed.seal(out, 1, ByteArrayInputStream(ByteArray(9)), 10, collectorOpen, sender, created) }
        assertThrows(IllegalArgumentException::class.java) { Sealed.seal(out, 1, ByteArrayInputStream(ByteArray(11)), 10, collectorOpen, sender, created) }
        assertThrows(IllegalArgumentException::class.java) {
            Sealed.seal(out, Sizes.KIND_RECEIPT, ByteArrayInputStream(ByteArray(0)), Sizes.SMALL_MAX + 1L, collectorOpen, sender, created)
        }
    }

    /** Sealdrop's signing key lives in the Keystore (§9.4): its signatures come out as low-S r ‖ s and open. */
    @Test
    fun keystoreSigner() {
        val alias = "sealdrop-core-test"
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            val pair = generator.generateKeyPair()
            val signer = P256Signer(pair.private, Keys.p256Point(pair.public))
            val half = Keys.P256_N.shiftRight(1)
            repeat(20) {
                val raw = signer.sign("x$it".toByteArray())
                assertTrue(java.math.BigInteger(1, raw.copyOfRange(32, 64)) <= half)
            }
            val (content, _) = bundle(1000)
            val (data, _) = seal(1, content, signer)
            val sealed = Reading.openUpload(BytesSource(data), collectorKeys, mapOf(Encoding.hex(signer.keyId) to P256Verifier(signer.publicKey)))
            assertTrue(Reading.checkDeliveries(sealed).single().ok)
            assertFalse(pair.private.encoded != null && pair.private.encoded.isNotEmpty()) // it can't be exported
        } finally {
            keyStore.deleteEntry(alias)
        }
    }
}
