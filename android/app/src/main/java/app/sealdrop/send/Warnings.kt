package app.sealdrop.send

import app.sealdrop.Engine
import app.sealdrop.api.Sealdrop

/** The warning bits of PROTOCOL.md §9.1, each with its scope and the rule that clears it. */
object Warnings {
    const val DAY = 86_400_000L
    const val WEEK = 7 * DAY

    /** For one app ([app]), as `info()` gives them; for the screen with null (every app's). */
    fun bits(engine: Engine, app: String?): Int {
        val db = engine.db
        val now = engine.clock()
        val only = if (app == null) "" else " AND app = ?"
        fun count(sql: String, vararg args: Any?) = db.long(sql + only, *(if (app == null) args else arrayOf(*args, app)))
        fun recent(key: String) = db.getLong(key).let { it != 0L && now - it < WEEK }
        var bits = 0
        if (count("SELECT COUNT(*) FROM deliveries WHERE state = 3 AND inbox_at < ?", now - 2 * DAY) > 0) {
            bits = bits or Sealdrop.WARNING_WAITING
        }
        if (db.get(Health.KEY_REFUSED) != null) bits = bits or Sealdrop.WARNING_KEY_REFUSED
        if (db.get(Health.CLOCK) != null) bits = bits or Sealdrop.WARNING_CLOCK
        if (recent(Inbox.REJECTED_AT)) bits = bits or Sealdrop.WARNING_REJECTED
        if (engine.paired() == null || engine.broken()) bits = bits or Sealdrop.WARNING_NOT_PAIRED
        if (recent(Inbox.TWO_AT)) bits = bits or Sealdrop.WARNING_TWO_COLLECTORS
        if (Holds.heldLong(engine)) bits = bits or Sealdrop.WARNING_HELD_LONG
        if (count("SELECT COUNT(*) FROM deliveries WHERE state = 6 AND folder IS NOT NULL") > 0) {
            bits = bits or Sealdrop.WARNING_FAILED
        }
        if (db.get(Health.STORAGE_CAP) != null) bits = bits or Sealdrop.WARNING_STORAGE_CAP
        if (Inbox.cantRead(engine)) bits = bits or Sealdrop.WARNING_CANT_READ_RECEIPTS
        if (!db.get(Inbox.COLLECTOR_WARNINGS).isNullOrEmpty()) bits = bits or Sealdrop.WARNING_COLLECTOR_PROBLEM
        if (count("SELECT COUNT(*) FROM lost WHERE at > ?", now - WEEK) > 0) bits = bits or Sealdrop.WARNING_LOST
        return bits
    }
}
