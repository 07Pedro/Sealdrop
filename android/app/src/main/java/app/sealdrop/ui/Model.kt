package app.sealdrop.ui

import androidx.compose.ui.graphics.ImageBitmap

/** An app as the screens show it. `icon` comes from the package manager; without one, its initial is shown. */
data class AppUi(val name: String, val packageName: String, val note: String = "", val icon: ImageBitmap? = null)

/** An app's hold: it asked Sealdrop not to send for now (docs/PROTOCOL.md §9.1). */
data class HoldUi(val app: String, val since: String, val packageName: String = "")

/** A delivery the server refused twice (state 6, §9.1): the owner sends it again or discards it. */
data class FailedUi(val app: String, val size: String, val since: String, val reason: String, val key: Pair<String, String>? = null)

/** The warnings of §9.3, each said in plain words (`warningText`). `detail` fills in the numbers. */
enum class WarningKind {
    STORAGE_LIMIT, KEY_REFUSED, WAITING, CLOCK, REJECTED, PAIR_AGAIN, TWO_COLLECTORS, HELD_LONG, FAILED,
    CANT_READ_RECEIPTS, SERVER_PROBLEM, LOST,
}

data class WarningUi(val kind: WarningKind, val detail: String = "")

data class StatusUi(
    val fingerprint: String,
    val label: String,
    val storageHost: String,
    val lastUpload: String?,
    val lastPickup: String?,
    val lastBackup: String?,
    val onPhone: String?,
    val network: String,
    val warnings: List<WarningUi> = emptyList(),
    val holds: List<HoldUi> = emptyList(),
    val failed: List<FailedUi> = emptyList(),
    val apps: List<AppUi> = emptyList(),
    val wifiOnly: Boolean = false,
)

/** Title and text of a warning. Written for the owner, who may not know the protocol. */
fun warningText(w: WarningUi): Pair<String, String> = when (w.kind) {
    WarningKind.STORAGE_LIMIT -> "Uploads are paused: storage limit reached" to
        "The storage account's limit is reached, so uploads are paused. Nothing is lost: everything waits on this " +
        "phone and is sent once the limit lifts. On a free plan, adding a payment method lifts it; daily limits " +
        "also reset each day."
    WarningKind.KEY_REFUSED -> "The storage refused this phone's key" to
        "The key may have been deleted or replaced. Nothing is lost. Pair again with new storage keys."
    WarningKind.WAITING -> "Waiting in the inbox for ${w.detail}" to
        "Your server hasn't picked these up. Is it running and online?"
    WarningKind.CLOCK -> "This phone's clock is wrong" to
        "The storage refuses requests with a wrong time. Turn on automatic date and time in Android's settings."
    WarningKind.REJECTED -> "Your server rejected files" to
        "It couldn't use ${w.detail}. Sealdrop sends them again on their own; if that fails too, they're listed " +
        "below."
    WarningKind.PAIR_AGAIN -> "Pair again" to
        "This phone's keys are missing or can no longer be used. Nothing is lost: pair again, and everything " +
        "waiting is sent."
    WarningKind.TWO_COLLECTORS -> "Two servers seem to read the inbox" to
        "If you replaced your server, this goes away within 7 days. If not, someone else may have your server's " +
        "storage keys."
    WarningKind.HELD_LONG -> "Sending has been held for over a day" to
        "An app asked Sealdrop to wait (below). If it isn't busy, end its hold."
    WarningKind.FAILED -> "Not delivered" to "Your server refused a delivery twice. Choose below what to do."
    WarningKind.CANT_READ_RECEIPTS -> "Can't read your server's receipts" to
        "Sealdrop can't confirm what arrived, so it keeps everything. Pair again if this stays."
    WarningKind.SERVER_PROBLEM -> "Your server reports a problem" to w.detail
    WarningKind.LOST -> "Your server lost deliveries" to
        "Probably after a restore. The apps hand them over again, nothing to do."
}

/** `K7Q2M3XD4HTBWPLA` → `K7Q2 M3XD 4HTB WPLA`. */
fun groups(text: String, size: Int = 4): String = text.chunked(size).joinToString(" ")
