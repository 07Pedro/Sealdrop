package app.sealdrop.api

/** The numbers of Sealdrop's interface (docs/PROTOCOL.md §9.1). Only ever added to; none changes its meaning. */
object Sealdrop {
    const val PACKAGE = "app.sealdrop"
    const val ACTION_DELIVER = "app.sealdrop.action.DELIVER"
    const val API_VERSION = 1

    const val NETWORK_MOBILE = 1
    const val NETWORK_WIFI_ONLY = 2

    const val OK = 0
    const val ALREADY_HAVE = 1
    const val NOT_APPROVED = 2
    const val NOT_PAIRED = 3
    const val BAD_REQUEST = 4
    const val CHECKSUM_WRONG = 5
    const val NO_SPACE = 6
    const val TOO_BIG = 7
    const val BUSY = 8
    const val CONFLICT = 9
    const val UNKNOWN_HANDLE = 10

    const val STATE_UNKNOWN = 0
    const val STATE_QUEUED = 1
    const val STATE_UPLOADING = 2
    const val STATE_IN_INBOX = 3
    const val STATE_PICKED_UP = 4
    const val STATE_CONFLICT = 5
    const val STATE_FAILED = 6

    const val WARNING_WAITING = 1 shl 0
    const val WARNING_KEY_REFUSED = 1 shl 1
    const val WARNING_CLOCK = 1 shl 2
    const val WARNING_REJECTED = 1 shl 3
    const val WARNING_NOT_PAIRED = 1 shl 4
    const val WARNING_TWO_COLLECTORS = 1 shl 5
    const val WARNING_HELD_LONG = 1 shl 6
    const val WARNING_FAILED = 1 shl 7
    const val WARNING_STORAGE_CAP = 1 shl 8
    const val WARNING_CANT_READ_RECEIPTS = 1 shl 9
    const val WARNING_COLLECTOR_PROBLEM = 1 shl 10
    const val WARNING_LOST = 1 shl 11

    /** The most an `add` call takes: 100 files and 1 GiB (one larger file alone). */
    const val MAX_FILES_PER_ADD = 100
    const val MAX_BYTES_PER_ADD = 1L shl 30
    const val MAX_STATUS_IDS = 500
}
