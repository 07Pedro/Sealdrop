package app.sealdrop.send

import app.sealdrop.Engine
import java.io.File

/** What the owner decides on Sealdrop's screen (PROTOCOL.md §9.1). */
object Owner {
    /** A failed delivery: its strikes start from 0, and it waits to be sent again (state 1). */
    fun sendAgain(engine: Engine, app: String, delivery: String) {
        engine.db.exec(
            "UPDATE deliveries SET state = 1, strikes = 0, whole_rejects = 0, alone = 0, time = 0, final_at = 0, reason = NULL, " +
                "queued_at = ? WHERE app = ? AND delivery = ? AND state = 6 AND folder IS NOT NULL",
            engine.clock(), app, delivery,
        )
        engine.changed()
        engine.later.sendSoon()
    }

    /** A failed delivery's copy is deleted; its state stays 6. */
    fun discard(engine: Engine, app: String, delivery: String) {
        val db = engine.db
        val folder = db.string("SELECT folder FROM deliveries WHERE app = ? AND delivery = ? AND state = 6", app, delivery) ?: return
        File(engine.copies(), folder).deleteRecursively()
        db.tx {
            db.exec("UPDATE deliveries SET folder = NULL WHERE app = ? AND delivery = ?", app, delivery)
            db.exec("DELETE FROM files WHERE app = ? AND delivery = ?", app, delivery)
        }
        engine.changed()
    }

    fun wifiOnly(engine: Engine, on: Boolean) {
        engine.db.put(Sync.WIFI_ONLY, if (on) "1" else null)
        engine.changed()
        if (!on) engine.later.sendNow()
    }
}
