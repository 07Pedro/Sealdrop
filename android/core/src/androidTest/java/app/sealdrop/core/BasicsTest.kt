package app.sealdrop.core

import android.crypto.hpke.AeadParameterSpec
import android.crypto.hpke.Hpke
import android.crypto.hpke.KdfParameterSpec
import android.crypto.hpke.KemParameterSpec
import android.crypto.hpke.Recipient
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.math.BigInteger
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** §3's text rules, HKDF, HPKE (RFC 9180), signatures and sizes, against testvectors/vectors.json. */
@RunWith(AndroidJUnit4::class)
class BasicsTest {
    private val v = TestFiles.vectors
    private fun unhex(text: Any?) = Encoding.unhex(text)

    @Test
    fun json() {
        for (case in v["json"].list()) {
            case as Map<*, *>
            val data = Encoding.unb64url(case["bytes"])
            if (case["valid"] == true) Json.parse(data)
            else assertThrows(case["id"].str(), FormatException::class.java) { Json.parse(data) }
        }
    }

    @Test
    fun deepNestingIsRefusedNotCrashing() {
        assertThrows(FormatException::class.java) { Json.parse(ByteArray(100_000) { '['.code.toByte() }) }
    }

    @Test
    fun jsonIsWrittenAsTheCollectorWritesIt() {
        // Python's json.dumps(ensure_ascii=False, separators=(",", ":")): the same bytes for the same value.
        val text = "{\"a\":[1,true,null,\"x\\\"\\\\\\n\\u0001é \"],\"b\":{}}"
        assertEquals(text, String(Json.write(Json.parse(text.toByteArray())), Charsets.UTF_8))
        assertEquals(v["pairing"].obj()["offer_text_bytes"], Json.write(v["pairing"].obj()["offer"]).size.toLong())
        assertThrows(IllegalArgumentException::class.java) { Json.write("\ud800") }
        assertThrows(IllegalArgumentException::class.java) { Json.write(-1L) }
    }

    @Test
    fun base64url() {
        for (case in v["base64url"].list()) {
            case as Map<*, *>
            if (case["valid"] == true) {
                assertEquals(case["hex"], Encoding.hex(Encoding.unb64url(case["text"])))
                assertEquals(case["text"], Encoding.b64url(unhex(case["hex"])))
            } else {
                assertThrows(case["text"].str(), FormatException::class.java) { Encoding.unb64url(case["text"]) }
            }
        }
    }

    @Test
    fun hex() {
        assertArrayEquals(byteArrayOf(0, -1), Encoding.unhex("00ff"))
        for (bad in listOf("00FF", "0", "zz", " 00")) {
            assertThrows(bad, FormatException::class.java) { Encoding.unhex(bad) }
        }
    }

    @Test
    fun hkdfRfc5869() {
        for ((i, case) in v["hkdf"].list().withIndex()) {
            case as Map<*, *>
            val okm = Hkdf.sha256(unhex(case["ikm"]), unhex(case["salt"]), unhex(case["info"]), case["length"].long().toInt())
            assertEquals("A.${i + 1}", case["okm"], Encoding.hex(okm))
        }
    }

    /** RFC 9180, appendix A.2.1, through Android's HPKE: the recipient side, the key schedule's AEAD, the exports. */
    @Test
    fun hpkeRfc9180A2() {
        val h = v["hpke"].obj()
        val hpke = Hpke.getInstance(
            Hpke.getSuiteName(KemParameterSpec.DHKEM_X25519_HKDF_SHA256, KdfParameterSpec.HKDF_SHA256, AeadParameterSpec.CHACHA20POLY1305),
        )
        val recipient = Recipient.Builder(hpke, unhex(h["enc"]), Keys.x25519Private(unhex(h["skRm"])))
            .setApplicationInfo(unhex(h["info"])).build()
        val pt = unhex(h["pt"])
        val encryptions = h["encryptions"].list().map { it.obj() }
        // Messages 0 and 1 in order, through the context.
        for (e in encryptions.filter { it["seq"].long() < 2 }) {
            assertArrayEquals("seq ${e["seq"]}", pt, recipient.open(unhex(e["ct"]), unhex(e["aad"])))
        }
        // Message 255 with the schedule's key and base nonce, as the context would after 255 messages.
        val key = unhex(h["key"])
        val baseNonce = unhex(h["base_nonce"])
        for (e in encryptions) {
            val nonce = baseNonce.copyOf()
            val seq = e["seq"].long()
            for (i in 0 until 8) nonce[11 - i] = (nonce[11 - i].toInt() xor ((seq shr (8 * i)).toInt() and 0xFF)).toByte()
            val cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            cipher.updateAAD(unhex(e["aad"]))
            assertEquals("seq $seq", e["ct"], Encoding.hex(cipher.doFinal(pt)))
        }
        for (x in h["exports"].list().map { it.obj() }) {
            assertEquals(x["value"], Encoding.hex(recipient.export(x["length"].long().toInt(), unhex(x["context"]))))
        }
        // The vector's key pair works with Sealdrop's own sealing too.
        val sealed = HpkeSuite.seal(Keys.x25519Public(unhex(h["pkRm"])), Sealed.INFO_TO_COLLECTOR, ByteArray(104) { it.toByte() })
        assertArrayEquals(ByteArray(104) { it.toByte() }, HpkeSuite.open(Keys.x25519Private(unhex(h["skRm"])), Sealed.INFO_TO_COLLECTOR, sealed))
        assertNull(HpkeSuite.open(Keys.x25519Private(unhex(h["skRm"])), Sealed.INFO_TO_SENDER, sealed))
    }

    @Test
    fun x25519KeysRoundTrip() {
        val raw = TestFiles.private("sender_open")
        assertArrayEquals(raw, Keys.x25519PrivateBytes(Keys.x25519Private(raw)))
        val pair = Keys.x25519Generate()
        val public = Keys.x25519PublicBytes(pair.public)
        assertEquals(32, public.size)
        val sealed = HpkeSuite.seal(Keys.x25519Public(public), Sealed.INFO_TO_SENDER, byteArrayOf(1, 2, 3))
        assertArrayEquals(byteArrayOf(1, 2, 3), HpkeSuite.open(pair.private, Sealed.INFO_TO_SENDER, sealed))
    }

    @Test
    fun p256Signatures() {
        val p = v["signatures"].obj()["p256"].obj()
        val verifier = P256Verifier(Encoding.unb64url(p["public"]))
        for (case in p["cases"].list().map { it.obj() }) {
            assertEquals(case["id"].str(), case["valid"], verifier.verify(unhex(case["signature"]), unhex(case["statement"])))
        }
        // High S comes out as low S; the DER conversion keeps short values.
        val cases = p["cases"].list().map { it.obj() }.associateBy { it["id"] }
        val low = unhex(cases["low-s"]!!["signature"])
        val high = unhex(cases["high-s"]!!["signature"])
        assertArrayEquals(low, Keys.derToRaw(Keys.rawToDer(high)!!))
        assertArrayEquals(high, Keys.derToRaw(Keys.rawToDer(high)!!, lowS = false))
        val short = unhex(cases["short-r"]!!["signature"])
        assertArrayEquals(short, Keys.derToRaw(Keys.rawToDer(short)!!))
        assertNull(Keys.rawToDer(unhex(cases["r-zero"]!!["signature"])))
        assertNull(Keys.rawToDer(unhex(cases["s-is-n"]!!["signature"])))
    }

    @Test
    fun ed25519Signatures() {
        val e = v["signatures"].obj()["ed25519"].obj()
        val verifier = Ed25519Verifier(Encoding.unb64url(e["public"]))
        for (case in e["cases"].list().map { it.obj() }) {
            assertEquals(case["id"].str(), case["valid"], verifier.verify(unhex(case["signature"]), unhex(case["statement"])))
        }
        assertFalse(verifier.verify(ByteArray(63), ByteArray(0)))
    }

    @Test
    fun pointsOffTheCurveAreRefused() {
        val point = TestFiles.public("sender_sign").copyOf()
        point[64] = (point[64].toInt() xor 1).toByte()
        assertThrows(IllegalArgumentException::class.java) { Keys.p256Public(point) }
        assertThrows(IllegalArgumentException::class.java) { Keys.p256Public(point.copyOf(64)) }
    }

    @Test
    fun keyIds() {
        for (name in listOf("collector_sign", "sender_sign", "stranger_sign")) {
            assertEquals(name, TestFiles.keys[name].obj()["key_id"], Encoding.hex(Keys.keyId(TestFiles.public(name))))
        }
        assertArrayEquals(TestFiles.public("sender_sign"), Keys.p256Point(Keys.p256Public(TestFiles.public("sender_sign"))))
    }

    @Test
    fun phoneWritesLowS() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val signer = P256Signer(pair.private, Keys.p256Point(pair.public))
        val half = Keys.P256_N.shiftRight(1)
        repeat(50) {
            val raw = signer.sign("x$it".toByteArray())
            assertTrue(BigInteger(1, raw.copyOfRange(32, 64)) <= half)
            assertTrue(P256Verifier(signer.publicKey).verify(raw, "x$it".toByteArray()))
        }
    }

    @Test
    fun sizeExamples() {
        for (e in v["sizes"].obj()["examples"].list().map { it.obj() }) {
            val length = Sizes.paddedLength(e["kind"].long().toInt(), e["n"].long())
            assertEquals(e.toString(), listOf(e["length"], e["pieces"], e["size"]), listOf(length, Sizes.pieces(length), Sizes.sealedSize(length)))
        }
        assertThrows(IllegalArgumentException::class.java) { Sizes.paddedLength(3, Sizes.SMALL_MAX + 1L) }
        assertEquals(256 * Sizes.KiB, Sizes.paddedLength(2, 0))
    }

    @Test
    fun sizeCountsAndLimits() {
        val s = v["sizes"].obj()
        assertEquals(s["up_sizes"], Sizes.possibleLengths(Where.UP).size.toLong())
        assertEquals(1038L, s["up_sizes"])
        assertEquals(s["ack_sizes"], Sizes.possibleLengths(Where.ACK).size.toLong())
        assertEquals(s["max_delivery_bytes"], Sizes.maxDeliveryBytes())
        assertEquals(4 * Sizes.GiB - 8 * Sizes.MiB, Sizes.maxDeliveryBytes())
        assertEquals(s["max_delivery_bytes_at_1_gib"], Sizes.maxDeliveryBytes(Sizes.GiB))
    }

    @Test
    fun everySizeMapsBack() {
        for (where in Where.entries) {
            for (length in Sizes.possibleLengths(where)) assertEquals(length, Sizes.lengthForSize(where, Sizes.sealedSize(length)))
        }
        for (size in v["sizes"].obj()["impossible_up_sizes"].list()) assertNull(size.toString(), Sizes.lengthForSize(Where.UP, size.long()))
        assertNull(Sizes.lengthForSize(Where.UP, Long.MAX_VALUE))
    }
}
