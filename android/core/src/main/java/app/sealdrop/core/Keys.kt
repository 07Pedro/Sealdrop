package app.sealdrop.core

import android.crypto.hpke.XdhKeySpec
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.X509EncodedKeySpec

/** Who signs a sealed file: the phone with P-256 (in the Keystore), the collector with Ed25519. */
interface Signer {
    /** The public key in its encoding (§2): the 65-byte SEC1 point, or Ed25519's raw 32 bytes. */
    val publicKey: ByteArray
    val keyId: ByteArray get() = Keys.keyId(publicKey)
    fun sign(statement: ByteArray): ByteArray
}

fun interface Verifier {
    fun verify(signature: ByteArray, statement: ByteArray): Boolean
}

/** Keys, their encodings and key IDs (PROTOCOL.md §2, §3). */
object Keys {
    /** The order of the P-256 group. */
    val P256_N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    private val P256_P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val P256_B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    private val ED25519_SPKI = Encoding.unhex("302a300506032b6570032100")

    val p256Params: ECParameterSpec by lazy {
        AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
    }

    /** SHA-256 of a public signing key in its encoding (raw 32 bytes, or the 65-byte SEC1 point). */
    fun keyId(publicEncoding: ByteArray): ByteArray = Encoding.sha256(publicEncoding)

    // --- X25519, through the provider that does HPKE (Conscrypt), so that HPKE takes the keys ---------------------

    private val xdh: KeyFactory get() = KeyFactory.getInstance("XDH", HpkeSuite.provider)

    fun x25519Public(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "X25519 keys are 32 bytes" }
        return xdh.generatePublic(XdhKeySpec(raw))
    }

    fun x25519Private(raw: ByteArray): PrivateKey {
        require(raw.size == 32) { "X25519 keys are 32 bytes" }
        return xdh.generatePrivate(XdhKeySpec(raw))
    }

    fun x25519PublicBytes(key: PublicKey): ByteArray = xdh.getKeySpec(key, XdhKeySpec::class.java).key

    fun x25519PrivateBytes(key: PrivateKey): ByteArray = xdh.getKeySpec(key, XdhKeySpec::class.java).key

    /** A new opening key (the phone's, made at pairing; §2). */
    fun x25519Generate(): KeyPair = KeyPairGenerator.getInstance("XDH", HpkeSuite.provider).generateKeyPair()

    // --- P-256: the 65-byte point, and signatures as r ‖ s ---------------------------------------------------------

    fun p256Point(key: PublicKey): ByteArray {
        val w = (key as ECPublicKey).w
        return byteArrayOf(4) + fixed32(w.affineX) + fixed32(w.affineY)
    }

    /** Loads a 65-byte uncompressed point; IllegalArgumentException if it isn't one on the curve. */
    fun p256Public(point: ByteArray): PublicKey {
        require(point.size == 65 && point[0] == 4.toByte()) { "P-256 key must be an uncompressed 65-byte point" }
        val x = BigInteger(1, point.copyOfRange(1, 33))
        val y = BigInteger(1, point.copyOfRange(33, 65))
        require(x < P256_P && y < P256_P) { "P-256 point out of range" }
        // y² = x³ − 3x + b (mod p)
        val right = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(P256_B).mod(P256_P)
        require(y.multiply(y).mod(P256_P) == right) { "not a point on P-256" }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), p256Params))
    }

    /** DER (as Android writes it) to r ‖ s, in the low-S form if [lowS] (§3). */
    fun derToRaw(der: ByteArray, lowS: Boolean = true): ByteArray {
        fun fail(): Nothing = throw IllegalArgumentException("not a DER ECDSA signature")
        var i = 0
        fun byte(): Int = der.getOrNull(i++)?.toInt()?.and(0xFF) ?: fail()
        fun integer(): BigInteger {
            if (byte() != 0x02) fail()
            val length = byte()
            if (length !in 1..33 || i + length > der.size) fail()
            val value = BigInteger(der.copyOfRange(i, i + length))
            i += length
            if (value.signum() <= 0) fail()
            return value
        }
        if (byte() != 0x30 || byte() != der.size - 2) fail()
        val r = integer()
        var s = integer()
        if (i != der.size || r >= P256_N || s >= P256_N) fail()
        if (lowS && s > P256_N.shiftRight(1)) s = P256_N.subtract(s)
        return fixed32(r) + fixed32(s)
    }

    /** DER for a 64-byte r ‖ s, or null if r or s is 0 or not below n. */
    fun rawToDer(raw: ByteArray): ByteArray? {
        if (raw.size != 64) return null
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        if (r.signum() == 0 || s.signum() == 0 || r >= P256_N || s >= P256_N) return null
        val rb = r.toByteArray()
        val sb = s.toByteArray()
        return byteArrayOf(0x30, (4 + rb.size + sb.size).toByte(), 0x02, rb.size.toByte()) + rb +
            byteArrayOf(0x02, sb.size.toByte()) + sb
    }

    private fun fixed32(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == 32 -> bytes
            bytes.size == 33 && bytes[0] == 0.toByte() -> bytes.copyOfRange(1, 33)
            bytes.size < 32 -> ByteArray(32 - bytes.size) + bytes
            else -> throw IllegalArgumentException("more than 32 bytes")
        }
    }

    internal fun ed25519Public(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "Ed25519 public key must be 32 bytes" }
        return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(ED25519_SPKI + raw))
    }
}

/**
 * The phone's signer: ECDSA P-256 with SHA-256, written as r ‖ s in the low-S form. [key] is a Keystore key in
 * Sealdrop; a software key in the tests.
 */
class P256Signer(private val key: PrivateKey, override val publicKey: ByteArray) : Signer {
    override fun sign(statement: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(key)
        update(statement)
        Keys.derToRaw(sign())
    }
}

class P256Verifier(point: ByteArray) : Verifier {
    private val key = Keys.p256Public(point)

    override fun verify(signature: ByteArray, statement: ByteArray): Boolean {
        val der = Keys.rawToDer(signature) ?: return false
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(statement)
                verify(der)
            }
        } catch (e: GeneralSecurityException) {
            false
        }
    }
}

/** The collector's signatures, as the phone checks them (Ed25519, RFC 8032, pure). */
class Ed25519Verifier(public: ByteArray) : Verifier {
    private val key = Keys.ed25519Public(public)

    override fun verify(signature: ByteArray, statement: ByteArray): Boolean {
        if (signature.size != 64) return false
        return try {
            Signature.getInstance("Ed25519").run {
                initVerify(key)
                update(statement)
                verify(signature)
            }
        } catch (e: GeneralSecurityException) {
            false
        }
    }
}
