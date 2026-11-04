package app.sealdrop.core

import android.crypto.hpke.AeadParameterSpec
import android.crypto.hpke.Hpke
import android.crypto.hpke.KdfParameterSpec
import android.crypto.hpke.KemParameterSpec
import android.crypto.hpke.Message
import java.security.GeneralSecurityException
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey

/**
 * HPKE (RFC 9180), mode base, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305: one message per context,
 * an empty `aad`, output `enc` (32 bytes) ‖ ciphertext (PROTOCOL.md §3). Android 17's `android.crypto.hpke`.
 */
internal object HpkeSuite {
    const val ENC = 32

    private val hpke: Hpke by lazy {
        Hpke.getInstance(
            Hpke.getSuiteName(KemParameterSpec.DHKEM_X25519_HKDF_SHA256, KdfParameterSpec.HKDF_SHA256,
                AeadParameterSpec.CHACHA20POLY1305),
        )
    }

    val provider: Provider get() = hpke.provider

    fun seal(reader: PublicKey, info: ByteArray, plaintext: ByteArray): ByteArray {
        val message = hpke.seal(reader, info, plaintext, null)
        check(message.encapsulated.size == ENC)
        return message.encapsulated + message.ciphertext
    }

    /** The plaintext, or null if it doesn't open with [key] (another reader's file, or damaged). */
    fun open(key: PrivateKey, info: ByteArray, sealed: ByteArray): ByteArray? {
        if (sealed.size < ENC) return null
        val message = Message(sealed.copyOfRange(0, ENC), sealed.copyOfRange(ENC, sealed.size))
        return try {
            hpke.open(key, info, message, null)
        } catch (e: GeneralSecurityException) {
            null
        } catch (e: IllegalStateException) {
            null // e.g. an `enc` that gives an all-zero shared secret
        } catch (e: IllegalArgumentException) {
            null
        }
    }
}
