package app.sealdrop.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import app.sealdrop.core.Encoding
import app.sealdrop.core.Json
import app.sealdrop.core.Keys
import app.sealdrop.core.P256Signer
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The phone's keys (PROTOCOL.md §2, §9.4). The signing keys never leave the Keystore. The storage keys from the QR
 * code and the private opening keys are kept in one file, encrypted with a Keystore AES-256-GCM key. Both Keystore
 * keys: StrongBox if the phone has it, otherwise the TEE; no user authentication and no validity end, so they work
 * while the phone is locked.
 */
class Vault(
    context: Context,
    private val file: File = File(context.filesDir, "secrets.bin"),
    /** Keystore aliases start with it; the tests use their own. */
    private val prefix: String = "sealdrop.",
) {
    /** A key is missing or can no longer be used: Sealdrop stops sending and asks to pair again (§9.4). */
    class Broken(message: String, cause: Throwable? = null) : Exception(message, cause)

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // --- signing keys -----------------------------------------------------------------------------------------------

    /** A new P-256 signing key; gives its alias. */
    fun newSigningKey(): String {
        val alias = prefix + "sign." + Encoding.hex(Encoding.randomBytes(8))
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        try {
            generator.initialize(spec(true))
            generator.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            generator.initialize(spec(false))
            generator.generateKeyPair()
        }
        return alias
    }

    /** The signer for [alias]; Broken if the key is gone or unusable. */
    fun signer(alias: String): P256Signer {
        val entry = try {
            keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        } catch (e: GeneralSecurityException) {
            throw Broken("signing key unusable", e)
        } ?: throw Broken("signing key missing")
        return P256Signer(entry.privateKey, Keys.p256Point(entry.certificate.publicKey))
    }

    fun deleteKey(alias: String) {
        try {
            keyStore.deleteEntry(alias)
        } catch (e: GeneralSecurityException) {
            // already gone
        }
    }

    // --- the secrets file -------------------------------------------------------------------------------------------

    private fun wrapKey(create: Boolean): SecretKey? {
        (keyStore.getKey(wrap, null) as? SecretKey)?.let { return it }
        if (!create) return null
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(wrap, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        return try {
            generator.init(spec(true))
            generator.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            generator.init(spec(false))
            generator.generateKey()
        }
    }

    /** The secrets, or an empty map if there are none yet. Broken if the file can't be opened. */
    @Synchronized
    fun read(): Map<String, Any?> {
        if (!file.exists()) return emptyMap()
        val data = file.readBytes()
        val key = wrapKey(create = false) ?: throw Broken("wrapping key missing")
        val plain = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data.copyOf(12)))
                doFinal(data, 12, data.size - 12)
            }
        } catch (e: GeneralSecurityException) {
            throw Broken("secrets can't be opened", e)
        }
        @Suppress("UNCHECKED_CAST")
        return Json.parse(plain) as Map<String, Any?>
    }

    @Synchronized
    fun write(secrets: Map<String, Any?>) {
        val key = wrapKey(create = true)!!
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) } // a random IV
        val sealed = cipher.iv + cipher.doFinal(Json.write(secrets))
        val temporary = File(file.parentFile, file.name + ".new")
        temporary.outputStream().use { out ->
            out.write(sealed)
            out.fd.sync()
        }
        if (!temporary.renameTo(file)) throw java.io.IOException("can't replace the secrets file")
    }

    fun update(change: (MutableMap<String, Any?>) -> Unit) {
        synchronized(this) {
            val secrets = LinkedHashMap(read())
            change(secrets)
            write(secrets)
        }
    }

    /** Unpairing: every key and secret goes. */
    fun wipe() {
        synchronized(this) {
            file.delete()
            for (alias in keyStore.aliases().toList()) if (alias.startsWith(prefix)) deleteKey(alias)
        }
    }

    private val wrap = prefix + "wrap"
}
