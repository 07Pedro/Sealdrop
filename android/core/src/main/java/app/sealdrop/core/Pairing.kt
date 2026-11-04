package app.sealdrop.core

import java.security.MessageDigest

/** Pairing (PROTOCOL.md §7): the QR code's offer, the request's MAC and the fingerprint. */
object Pairing {
    private const val LABEL = "[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    private val ENDPOINT = Regex("https://($LABEL(?:\\.$LABEL)*)(?::([0-9]{1,5}))?")
    private val REGION = Regex("[a-z0-9-]{1,32}")
    private val BUCKET = Regex("[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
    private val PREFIX = Regex("(?:[a-z0-9_-]+/)*")
    private val KEY_TEXT = Regex("[!-~]{1,128}")
    private val PAIR = "sealdrop/v1/pair".toByteArray(Charsets.US_ASCII)
    private val PAIR_MAC = "sealdrop/v1/pair-mac".toByteArray(Charsets.US_ASCII)
    private val FINGERPRINT = "sealdrop/v1/fingerprint".toByteArray(Charsets.US_ASCII)

    /** How late an offer may still be taken, for a phone whose clock is a little wrong. */
    const val ALLOWANCE_MS = 5 * 60 * 1000L

    /** One location from the QR code, complete. Its [toString] leaves the key out, so it never ends up in a log. */
    class Location(
        val endpoint: String, val region: String, val bucket: String, val prefix: String, val keyId: String, val secret: String,
    ) {
        override fun toString() = "Location($endpoint, $region, $bucket, $prefix)"
    }

    /** A checked pair offer. It holds the storage keys and the one-time code: [toString] shows neither. */
    class Offer(
        val pairing: ByteArray, val expires: Long, val up: Location, val ack: Location,
        val collectorOpen: ByteArray, val collectorSign: ByteArray, val code: ByteArray,
    ) {
        override fun toString() = "Offer(up=$up, ack=$ack)"
    }

    fun macTranscript(
        pairing: ByteArray, collectorOpen: ByteArray, collectorSign: ByteArray, senderSign: ByteArray, senderOpen: ByteArray,
        replaces: ByteArray?,
    ): ByteArray = PAIR + pairing + collectorOpen + collectorSign + senderSign + senderOpen + (replaces ?: ByteArray(32))

    fun pairMac(code: ByteArray, pairing: ByteArray, transcript: ByteArray): ByteArray =
        Hkdf.hmac(Hkdf.sha256(code, pairing, PAIR_MAC, 32), transcript)

    fun macOk(expected: ByteArray, given: ByteArray): Boolean = MessageDigest.isEqual(expected, given)

    fun fingerprint(
        pairing: ByteArray, collectorOpen: ByteArray, collectorSign: ByteArray, senderSign: ByteArray, senderOpen: ByteArray,
    ): String {
        val digest = Encoding.sha256(FINGERPRINT, pairing, collectorOpen, collectorSign, senderSign, senderOpen)
        return Encoding.base32(digest.copyOf(10)).chunked(4).joinToString(" ")
    }

    // --- the offer in the QR code ----------------------------------------------------------------------------------

    /** What the phone checks (§7, step 1); FormatException if anything is wrong or it has expired. */
    fun checkOffer(offer: Any?, nowMs: Long, allowanceMs: Long = ALLOWANCE_MS): Offer {
        if (offer !is Map<*, *> || !Encoding.isOne(offer["sealdrop"]) || offer["type"] != "pair-offer") {
            throw FormatException("sealdrop or type")
        }
        val pairing = Encoding.unb64url(offer["pairing"], 16)
        val collectorOpen = Encoding.unb64url(offer["collector_open"], 32)
        val collectorSign = Encoding.unb64url(offer["collector_sign"], 32)
        val code = Encoding.unb64url(offer["code"], 16)
        val expires = offer["expires"] as? Long ?: throw FormatException("expired")
        if (expires + allowanceMs < nowMs) throw FormatException("expired")
        val (up, ack) = resolveStorage(offer["storage"])
        return Offer(pairing, expires, up, ack, collectorOpen, collectorSign, code)
    }

    /** Both locations in full (`ack` takes what it leaves out from `up`); FormatException if they break §7's rules. */
    fun resolveStorage(storage: Any?): Pair<Location, Location> {
        if (storage !is Map<*, *>) throw FormatException("storage")
        val up = storage["up"] as? Map<*, *> ?: throw FormatException("location")
        val ack = storage["ack"] as? Map<*, *> ?: throw FormatException("location")
        checkLocation(up, full = true)
        checkLocation(ack, full = false)
        fun field(name: String) = (if (name in ack) ack[name] else up[name]) as String
        val upLocation = location(up, up["endpoint"] as String, up["region"] as String, up["bucket"] as String)
        val ackLocation = location(ack, field("endpoint"), field("region"), field("bucket"))
        if (upLocation.endpoint == ackLocation.endpoint && upLocation.bucket == ackLocation.bucket) {
            val a = upLocation.prefix
            val b = ackLocation.prefix
            if (a.isEmpty() || b.isEmpty() || a.startsWith(b) || b.startsWith(a)) {
                throw FormatException("up and ack overlap in one bucket")
            }
        }
        return upLocation to ackLocation
    }

    private fun location(loc: Map<*, *>, endpoint: String, region: String, bucket: String): Location {
        val key = loc["key"] as Map<*, *>
        return Location(endpoint, region, bucket, loc["prefix"] as String, key["id"] as String, key["secret"] as String)
    }

    private fun checkLocation(loc: Map<*, *>, full: Boolean) {
        for ((name, pattern) in listOf("endpoint" to ENDPOINT, "region" to REGION, "bucket" to BUCKET)) {
            if (name !in loc && !full) continue // left out: the same as in `up` (a null isn't leaving it out)
            val value = loc[name]
            if (value !is String || !pattern.matches(value)) throw FormatException(name)
        }
        (loc["endpoint"] as? String)?.let { endpoint ->
            val port = ENDPOINT.matchEntire(endpoint)!!.groupValues[2]
            if (port.isNotEmpty() && port.toInt() !in 1..65535) throw FormatException("endpoint port")
        }
        val prefix = loc["prefix"]
        if (prefix !is String || prefix.length > 64 || !PREFIX.matches(prefix)) throw FormatException("prefix")
        val key = loc["key"]
        if (key !is Map<*, *> || listOf("id", "secret").any { val v = key[it]; v !is String || !KEY_TEXT.matches(v) }) {
            throw FormatException("key")
        }
    }
}
