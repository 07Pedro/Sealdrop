package app.sealdrop.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

/**
 * The other direction of PROTOCOL.md §13: Sealdrop's code seals, the collector opens. Writes sealed files and what
 * they must open to into the test app's files folder (`cross/`), for `testvectors/check_android_files.py`:
 *
 *     adb pull /sdcard/Android/data/app.sealdrop.core.test/files/cross
 *     python testvectors/check_android_files.py cross
 */
@RunWith(AndroidJUnit4::class)
class CrossFilesTest {
    private val created = 1789285265000L
    private val sender = TestFiles.p256Signer("sender_sign")
    private val collectorOpen = Keys.x25519Public(TestFiles.public("collector_open"))
    private val offer = Pairing.checkOffer(TestFiles.vectors["pairing"].obj()["offer"], 0)
    private val expected = mutableListOf<Map<String, Any?>>()

    private fun write(dir: File, name: String, reader: String, kind: Int, content: ByteArray, signer: Signer,
                      to: java.security.PublicKey, extra: Map<String, Any?>) {
        val out = ByteArrayOutputStream()
        val result = Sealed.seal(out, kind, ByteArrayInputStream(content), content.size.toLong(), to, signer, created)
        File(dir, name).writeBytes(out.toByteArray())
        val h = result.header
        expected += linkedMapOf<String, Any?>(
            "file" to name, "reader" to reader, "size" to result.size, "sealed_sha256" to result.sha256,
            "header" to linkedMapOf("kind" to h.kind.toLong(), "created" to h.created, "n" to h.n,
                "message_id" to Encoding.hex(h.messageId), "writer_key_id" to Encoding.hex(h.writerKeyId)),
            "content_sha256" to TestFiles.sha256Hex(content),
        ) + extra
    }

    private fun bundle(dir: File, name: String, files: List<Triple<String, ByteArray, Boolean>>) {
        // One delivery per file; the flag says whether its checksum is given correctly.
        val deliveries = files.mapIndexed { i, (path, data, honest) ->
            Delivery("org.example.tracker", "android-${name.substringBefore('.')}-$i", created,
                listOf(FileEntry(path, data.size.toLong(), if (honest) TestFiles.sha256Hex(data) else "0".repeat(64))))
        }
        val content = Manifests.contentPrefix(Manifests.bundleManifest(deliveries)) + files.fold(ByteArray(0)) { a, f -> a + f.second }
        write(dir, name, "collector", Sizes.KIND_BUNDLE, content, sender, collectorOpen, mapOf(
            "deliveries" to deliveries.zip(files).map { (d, f) ->
                linkedMapOf("app" to d.app, "delivery" to d.delivery, "digest" to d.digest) +
                    if (f.third) mapOf("result" to "stored") else mapOf("result" to "rejected", "reason" to Reasons.BAD_FILE)
            },
        ))
    }

    private fun pairRequest(dir: File, name: String, signer: Signer, senderOpen: ByteArray, replaces: ByteArray?) {
        val transcript = Pairing.macTranscript(offer.pairing, offer.collectorOpen, offer.collectorSign, signer.publicKey, senderOpen, replaces)
        val manifest = Manifests.pairManifest(offer.pairing, signer.publicKey, senderOpen, "Phone – test", replaces,
            Pairing.pairMac(offer.code, offer.pairing, transcript))
        write(dir, name, "pair", Sizes.KIND_PAIR, Manifests.contentPrefix(manifest), signer, Keys.x25519Public(offer.collectorOpen), mapOf(
            "manifest" to manifest,
            "fingerprint" to Pairing.fingerprint(offer.pairing, offer.collectorOpen, offer.collectorSign, signer.publicKey, senderOpen),
        ))
    }

    @Test
    fun writeFilesForTheCollector() {
        val context = InstrumentationRegistry.getInstrumentation().context
        val dir = File(context.getExternalFilesDir(null), "cross").apply { deleteRecursively(); mkdirs() }
        fun data(size: Int, seed: Int) = ByteArray(size) { (it * 7 + seed * 13 + it / 997).toByte() }

        bundle(dir, "bundle-two-pieces.sealed", listOf(
            Triple("manifest.json", data(1500, 1), true),
            Triple("data/ride.json.gz", data(1_200_000, 2), true),
            Triple("photos/a.jpg", data(5000, 3), false),
        ))
        bundle(dir, "bundle-over-4-mib.sealed", listOf(Triple("data/large.bin", data(4 * Sizes.PIECE + 100, 4), true)))

        pairRequest(dir, "pair-request-test-keys.sealed", sender, TestFiles.public("sender_open"), null)
        val alias = "sealdrop-cross-test"
        try {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256).build())
            val pair = generator.generateKeyPair()
            val opening = Keys.x25519PublicBytes(Keys.x25519Generate().public)
            pairRequest(dir, "pair-request-keystore.sealed", P256Signer(pair.private, Keys.p256Point(pair.public)), opening,
                Keys.keyId(TestFiles.public("sender_sign")))
        } finally {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
        }

        val receipt = linkedMapOf("v" to 1L, "type" to "paired", "for" to Encoding.hex(sender.keyId),
            "pairing" to Encoding.b64url(offer.pairing), "time" to created)
        write(dir, "paired-receipt.sealed", "sender", Sizes.KIND_RECEIPT, Manifests.contentPrefix(receipt), TestFiles.collectorSigner(),
            Keys.x25519Public(TestFiles.public("sender_open")), mapOf("manifest" to receipt))

        File(dir, "expected.json").writeBytes(Json.write(linkedMapOf("note" to "Made by CrossFilesTest on Android.", "files" to expected)))
        assertTrue(File(dir, "expected.json").length() > 0)
    }
}
