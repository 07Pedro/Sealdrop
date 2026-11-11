package app.sealdrop.send

/** When the background jobs try again after something went wrong ([Jobs]); plain rules, tested on the PC. */
object JobRules {
    const val MINUTE = 60_000L
    const val HOUR = 60 * MINUTE

    /** The watchdog's period: it puts back any job that went missing. */
    const val WATCHDOG_EVERY_MS = 6 * HOUR

    /** Before the first unlock after a restart, Sealdrop's storage is still locked: try again in 5 minutes. */
    const val UNTIL_UNLOCKED_MS = 5 * MINUTE

    /** After an error the run didn't expect: 15 minutes, doubling with each one in a row, at most 4 hours. */
    fun afterErrorMs(attempt: Int): Long = (15 * MINUTE shl attempt.coerceIn(0, 4)).coerceAtMost(4 * HOUR)
}
