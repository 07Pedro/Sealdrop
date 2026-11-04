package app.sealdrop.core

/** Where a sealed file is listed: `up/` (bundles and pairing requests) or `ack/` (receipts). */
enum class Where { UP, ACK }

/** Padded lengths and the sizes a sealed file can have (PROTOCOL.md §4, §9.2). */
object Sizes {
    const val KiB = 1024L
    const val MiB = 1024 * KiB
    const val GiB = 1024 * MiB

    const val PIECE = 1024 * 1024
    const val PREFIX = 152 // HPKE enc (32) + sealed header (120)
    const val SIGNATURE = 64
    const val TAG = 16
    const val SMALL_MAX = 256 * 1024 // content limit of pairing requests and receipts
    const val DEFAULT_MAX_SEALED = 4 * GiB
    const val MANIFEST_ROOM = 4 * MiB

    const val KIND_BUNDLE = 1
    const val KIND_PAIR = 2
    const val KIND_RECEIPT = 3

    /** Far beyond any real file; keeps the arithmetic below from overflowing on a header's made-up length. */
    private const val MAX_CONTENT = 1L shl 50

    private fun roundUp(value: Long, step: Long): Long = (value + step - 1) / step * step

    /** `L` for content of [n] bytes; IllegalArgumentException if [n] is too big for the kind. */
    fun paddedLength(kind: Int, n: Long): Long {
        require(n >= 0) { "negative length" }
        return when (kind) {
            KIND_BUNDLE -> when {
                n <= 4 * MiB -> maxOf(256 * KiB, roundUp(n, 256 * KiB))
                n <= MAX_CONTENT -> roundUp(n, 4 * MiB)
                else -> throw IllegalArgumentException("bundle too big")
            }
            KIND_PAIR -> {
                require(n <= SMALL_MAX) { "pairing request over 256 KiB" }
                256 * KiB
            }
            KIND_RECEIPT -> {
                require(n <= SMALL_MAX) { "receipt over 256 KiB" }
                maxOf(4 * KiB, roundUp(n, 4 * KiB))
            }
            else -> throw IllegalArgumentException("unknown kind $kind")
        }
    }

    fun pieces(length: Long): Long = (length + PIECE - 1) / PIECE

    /** The exact file size for a padded length `L`: 152 + L + 16·N + 64. */
    fun sealedSize(length: Long): Long = PREFIX + length + TAG * pieces(length) + SIGNATURE

    /** Every `L` that can appear in `up/` (bundles; a pairing request has the smallest size) or `ack/`. */
    fun possibleLengths(where: Where, maxSealed: Long = DEFAULT_MAX_SEALED): List<Long> {
        if (where == Where.ACK) return (1..SMALL_MAX / 4096).map { it * 4 * KiB }
        val lengths = (1..16L).map { it * 256 * KiB }.toMutableList()
        var length = 8 * MiB
        while (sealedSize(length) <= maxSealed) {
            lengths.add(length)
            length += 4 * MiB
        }
        return lengths.filter { sealedSize(it) <= maxSealed }
    }

    /** The `L` behind a listed size, or null if no file there can have that size (the limit isn't applied). */
    fun lengthForSize(where: Where, size: Long): Long? {
        if (size < PREFIX + SIGNATURE + TAG || size > MAX_CONTENT) return null
        val candidates = when {
            where == Where.ACK -> (1..SMALL_MAX / 4096).map { it * 4 * KiB }
            size <= sealedSize(4 * MiB) -> (1..16L).map { it * 256 * KiB }
            else -> {
                // Above 4 MiB, L is a multiple of 4 MiB and N = L / 1 MiB, so size = 216 + L + 16·L/MiB.
                // floor((size − 216) · PIECE / (PIECE + TAG)), without overflowing:
                val x = size - PREFIX - SIGNATURE
                val q = x / (PIECE + TAG)
                val r = x % (PIECE + TAG)
                val length = roundUp(q * PIECE + r * PIECE / (PIECE + TAG), 4 * MiB)
                listOf(length - 4 * MiB, length)
            }
        }
        return candidates.firstOrNull { it > 0 && sealedSize(it) == size }
    }

    /** The most file bytes one delivery may hold (§9.2): the largest fitting `L` minus 4 MiB. */
    fun maxDeliveryBytes(maxSealed: Long = DEFAULT_MAX_SEALED): Long {
        val lengths = possibleLengths(Where.UP, maxSealed)
        if (lengths.isEmpty()) return 0
        return maxOf(0, lengths.last() - MANIFEST_ROOM)
    }
}
