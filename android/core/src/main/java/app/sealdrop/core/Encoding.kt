package app.sealdrop.core

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Text rules (PROTOCOL.md §3) besides JSON: base64url, hex and base32; plus SHA-256 and random bytes. */
object Encoding {
    private val B64URL = Regex("[A-Za-z0-9_-]*")
    private val HEX = Regex("(?:[0-9a-f]{2})*")
    private const val BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private val random = SecureRandom()

    fun b64url(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    /** Strict base64url without padding; [length] checks the decoded size. */
    fun unb64url(text: Any?, length: Int? = null): ByteArray {
        if (text !is String || !B64URL.matches(text) || text.length % 4 == 1) throw FormatException("not base64url")
        val data = Base64.getUrlDecoder().decode(text)
        if (b64url(data) != text) throw FormatException("base64url with unused bits set")
        if (length != null && data.size != length) throw FormatException("expected $length bytes, got ${data.size}")
        return data
    }

    fun hex(data: ByteArray): String = buildString(data.size * 2) {
        for (b in data) append(DIGITS[(b.toInt() shr 4) and 15]).append(DIGITS[b.toInt() and 15])
    }

    private const val DIGITS = "0123456789abcdef"

    /** Lowercase hex only; [length] checks the decoded size. */
    fun unhex(text: Any?, length: Int? = null): ByteArray {
        if (text !is String || !HEX.matches(text)) throw FormatException("not lowercase hex")
        val data = ByteArray(text.length / 2) { text.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
        if (length != null && data.size != length) throw FormatException("expected $length bytes, got ${data.size}")
        return data
    }

    /** RFC 4648 §6, alphabet A–Z 2–7, no padding. */
    fun base32(data: ByteArray): String {
        val out = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                out.append(BASE32[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) out.append(BASE32[(buffer shl (5 - bits)) and 31])
        return out.toString()
    }

    fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
        parts.forEach { update(it) }
        digest()
    }

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    /** A JSON integer as [Json] reads it. */
    fun isInt(value: Any?): Boolean = value is Long

    fun isOne(value: Any?): Boolean = value is Long && value == 1L
}
