package app.sealdrop.send

import app.sealdrop.Engine

/**
 * Holds (PROTOCOL.md §9.1): per app, 1 to 900 seconds, ended by `release()`, by running out, or by the owner. Sealdrop
 * sends and fetches nothing while any app holds.
 */
object Holds {
    /** When the current unbroken held time began (a gap of under a minute doesn't break it). */
    private const val SINCE = "hold.since"
    private const val LAST_END = "hold.last_end"
    private const val GAP_MS = 60_000L
    const val LONG_MS = 86_400_000L

    class Active(val app: String, val since: Long, val until: Long)

    fun active(engine: Engine): List<Active> =
        engine.db.query("SELECT app, since, until FROM holds WHERE until > ? ORDER BY since", engine.clock()) {
            Active(it.getString(0), it.getLong(1), it.getLong(2))
        }

    fun held(engine: Engine): Boolean = active(engine).isNotEmpty()

    /** When the last running hold ends, or 0. */
    fun endsAt(engine: Engine): Long = active(engine).maxOfOrNull { it.until } ?: 0

    fun hold(engine: Engine, app: String, seconds: Int) {
        val db = engine.db
        val now = engine.clock()
        db.tx {
            val active = active(engine)
            if (active.isEmpty()) {
                val lastEnd = maxOf(db.long("SELECT IFNULL(MAX(until), 0) FROM holds"), db.getLong(LAST_END))
                if (lastEnd < now - GAP_MS) db.putLong(SINCE, now)
            }
            val since = active.firstOrNull { it.app == app }?.since ?: now
            db.exec("INSERT OR REPLACE INTO holds (app, since, until) VALUES (?, ?, ?)", app, since, now + seconds * 1000L)
        }
        Engine.log("hold: $seconds s")
        engine.changed()
    }

    /** The app's own `release()`, or the owner ending its hold on the status screen (until its next `hold()`). */
    fun release(engine: Engine, app: String) {
        val db = engine.db
        val was = db.long("SELECT COUNT(*) FROM holds WHERE app = ? AND until > ?", app, engine.clock()) > 0
        db.exec("DELETE FROM holds WHERE app = ?", app)
        if (!was) return
        db.putLong(LAST_END, engine.clock())
        engine.changed()
        if (!held(engine)) engine.later.afterHold()
    }

    /** Warning bit 6: one or more apps holding, with no gap of a minute or more, for 24 hours. */
    fun heldLong(engine: Engine): Boolean = held(engine) && engine.clock() - engine.db.getLong(SINCE, engine.clock()) >= LONG_MS
}
