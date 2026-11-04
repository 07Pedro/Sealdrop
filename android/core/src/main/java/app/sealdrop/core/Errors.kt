package app.sealdrop.core

/** Why a sealed file or a delivery is turned away (PROTOCOL.md §5, §6). */
object Reasons {
    // Whole-file reasons, in receipts' "rejected" list.
    const val DAMAGED = "damaged"
    const val TOO_BIG = "too-big"
    const val UNKNOWN_SENDER = "unknown-sender"
    const val BAD_SIGNATURE = "bad-signature"
    const val BAD_CONTENT = "bad-content"

    // Per-delivery reasons, in a delivery's "reason".
    const val BAD_NAME = "bad-name"
    const val BAD_FILE = "bad-file"
    const val NO_FILES = "no-files"
}

/** A sealed file fails a check. [reason] is one of the whole-file reasons in [Reasons]. */
class Rejected(val reason: String, val detail: String = "") : Exception(if (detail.isEmpty()) reason else "$reason: $detail")

/** Text that breaks §3's rules (JSON, base64url, hex), or a manifest or offer of the wrong form. */
class FormatException(message: String) : IllegalArgumentException(message)
