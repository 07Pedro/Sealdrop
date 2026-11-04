package app.sealdrop.core

import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec

/** The shared test files in `testvectors/` (the test APK's assets): keys, sealed files, cases and vectors. */
object TestFiles {
    private val assets get() = InstrumentationRegistry.getInstrumentation().context.assets

    fun bytes(path: String): ByteArray = assets.open(path).use { it.readBytes() }

    fun json(path: String): Map<*, *> = Json.parse(bytes(path)) as Map<*, *>

    val keys: Map<*, *> by lazy { json("keys.json") }
    val vectors: Map<*, *> by lazy { json("vectors.json") }
    val cases: List<Map<*, *>> by lazy { (json("cases.json")["cases"] as List<*>).map { it as Map<*, *> } }

    fun public(name: String): ByteArray = Encoding.unb64url((keys[name] as Map<*, *>)["public"])

    fun private(name: String): ByteArray = Encoding.unb64url((keys[name] as Map<*, *>)["private"])

    fun x25519(name: String): PrivateKey = Keys.x25519Private(private(name))

    /** A test key as a software P-256 signer (in Sealdrop the key lives in the Keystore). */
    fun p256Signer(name: String): P256Signer {
        val spec = ECPrivateKeySpec(BigInteger(1, private(name)), Keys.p256Params)
        return P256Signer(KeyFactory.getInstance("EC").generatePrivate(spec), public(name))
    }

    /** The collector's signer, here only to make receipts in the tests: the phone never signs with Ed25519. */
    fun collectorSigner(): Signer = object : Signer {
        private val key = KeyFactory.getInstance("Ed25519")
            .generatePrivate(PKCS8EncodedKeySpec(Encoding.unhex("302e020100300506032b657004220420") + private("collector_sign")))
        override val publicKey = public("collector_sign")
        override fun sign(statement: ByteArray): ByteArray = Signature.getInstance("Ed25519").run {
            initSign(key)
            update(statement)
            sign()
        }
    }

    /** A case's mutations: the same operations the Python tests apply (testvectors/README.md). */
    fun mutate(data: ByteArray, ops: List<*>): ByteArray {
        var out = data.copyOf()
        for (op in ops) {
            op as Map<*, *>
            fun int(name: String) = (op[name] as Long).toInt()
            out = when (op["op"]) {
                "flip" -> out.also { it[int("offset")] = (it[int("offset")].toInt() xor (1 shl int("bit"))).toByte() }
                "cut" -> out.copyOf(int("length"))
                "append" -> out + Encoding.unhex(op["bytes"])
                "remove" -> out.copyOfRange(0, int("offset")) + out.copyOfRange(int("offset") + int("length"), out.size)
                "swap" -> {
                    val o = int("offset")
                    val a = int("first")
                    val b = int("second")
                    out.copyOfRange(0, o) + out.copyOfRange(o + a, o + a + b) + out.copyOfRange(o, o + a) +
                        out.copyOfRange(o + a + b, out.size)
                }
                else -> throw IllegalArgumentException("unknown op ${op["op"]}")
            }
        }
        return out
    }

    fun sha256Hex(data: ByteArray): String = Encoding.hex(Encoding.sha256(data))
}

fun Any?.obj(): Map<*, *> = this as Map<*, *>
fun Any?.list(): List<*> = this as List<*>
fun Any?.str(): String = this as String
fun Any?.long(): Long = this as Long
