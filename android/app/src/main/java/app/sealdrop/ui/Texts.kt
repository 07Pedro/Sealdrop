package app.sealdrop.ui

import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/** Times and sizes as the screens say them: "today 14:32", "5 minutes ago", "41 MB". */
object Texts {
    private const val MINUTE = 60_000L
    private const val HOUR = 60 * MINUTE
    private const val DAY = 24 * HOUR

    private fun dayNumber(ms: Long): Long {
        val c = Calendar.getInstance().apply { timeInMillis = ms }
        return c.get(Calendar.YEAR) * 1000L + c.get(Calendar.DAY_OF_YEAR)
    }

    fun clock(ms: Long): String = SimpleDateFormat("HH:mm", Locale.ROOT).format(Date(ms))

    /** "today 14:32", "yesterday 18:05", "on Monday", "3 Nov". */
    fun day(ms: Long, now: Long = System.currentTimeMillis()): String {
        val today = dayNumber(now)
        val then = dayNumber(ms)
        return when {
            then == today -> "today ${clock(ms)}"
            then == dayNumber(now - DAY) -> "yesterday ${clock(ms)}"
            now - ms < 6 * DAY && ms < now -> "on " + SimpleDateFormat("EEEE", Locale.ENGLISH).format(Date(ms))
            else -> SimpleDateFormat("d MMM", Locale.ENGLISH).format(Date(ms))
        }
    }

    /** "just now", "5 minutes ago", "3 hours ago", "3 days ago". */
    fun ago(ms: Long, now: Long = System.currentTimeMillis()): String {
        val d = maxOf(0, now - ms)
        return when {
            d < MINUTE -> "just now"
            d < HOUR -> plural(d / MINUTE, "minute") + " ago"
            d < DAY -> plural(d / HOUR, "hour") + " ago"
            else -> plural(d / DAY, "day") + " ago"
        }
    }

    /** "2 days", "5 hours". */
    fun duration(ms: Long): String = if (ms >= DAY) plural(ms / DAY, "day") else plural(maxOf(1, ms / HOUR), "hour")

    fun plural(n: Long, word: String) = if (n == 1L) "1 $word" else "$n ${word}s"

    /** Decimal megabytes, as phones show sizes: "0.2 MB", "2.1 MB", "41 MB". */
    fun size(bytes: Long): String {
        val mb = bytes / 1_000_000.0
        return when {
            mb < 0.1 && bytes > 0 -> "0.1 MB"
            mb < 10 -> String.format(Locale.ROOT, "%.1f MB", mb)
            else -> String.format(Locale.ROOT, "%.0f MB", mb)
        }
    }
}
